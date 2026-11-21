//! The code review engine.
//!
//! A plain function over `github`, wrapped thinly by the MCP and A2A layers
//! and called directly by the webhook. The model runs on Workers AI, so there
//! is no third-party API key to hold and no egress: inference happens on the
//! same platform as the Worker and is billed to the Cloudflare account.
//!
//! Output goes to a COMMIT COMMENT, not a pull request review. That is a
//! stronger safety property than refusing `APPROVE`: a commit comment carries
//! no review event at all, so this agent cannot approve, cannot request
//! changes, cannot satisfy or block a branch protection rule, and leaves
//! nothing for a person to dismiss. It says its piece and changes nothing.

use crate::config::{non_empty, Config};
use crate::error::{Failure, GitHubError};
use crate::github::{
    compare_commits, create_commit_comment, get_pull_request_diff, list_commit_comments, GhResult,
};
use crate::platform::Platform;
use crate::tracing::{self, SpanHandle};
use regex::Regex;
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::{BTreeSet, HashMap};
use std::sync::OnceLock;

/// Workers AI models known to do function calling and structured output.
pub const REVIEW_MODELS: [(&str, &str); 3] = [
    ("glm-5.3", "@cf/zai-org/glm-5.3"),
    ("glm-5.3-flash", "@cf/zai-org/glm-5.3-flash"),
    ("kimi-k2.7-code", "@cf/moonshotai/kimi-k2.7-code"),
];

pub const DEFAULT_MODEL: &str = "@cf/zai-org/glm-5.3";

/// How much annotated diff to send. Not a context limit (every candidate model
/// holds at least 262K tokens): a quality and cost limit. A 400KB diff is a
/// rename sweep or a lockfile, and a review of it is noise at any price.
pub const DEFAULT_MAX_DIFF_BYTES: usize = 200_000;

/// Written into every posted review, and looked for before posting one.
///
/// GitHub retries a webhook delivery it thinks failed and a re-request is one
/// click in the UI, so "have I already reviewed this commit?" has to be
/// answerable. It is answered from the commit's own comments rather than from
/// KV: the record lives where the output lives and no namespace is needed.
pub const REVIEW_MARKER: &str = "<!-- nyuchi-review -->";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Blocking,
    Concern,
    Note,
}

impl Severity {
    fn label(self) -> &'static str {
        match self {
            Severity::Blocking => "Blocking",
            Severity::Concern => "Concern",
            Severity::Note => "Note",
        }
    }
    fn rank(self) -> u8 {
        match self {
            Severity::Blocking => 0,
            Severity::Concern => 1,
            Severity::Note => 2,
        }
    }
}

/// A single thing the model wants to say about a specific line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub path: String,
    pub line: u64,
    pub severity: Severity,
    pub title: String,
    pub body: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReviewResult {
    pub model: String,
    pub summary: String,
    /// Findings that landed on a real added line, ready for inline comments.
    pub findings: Vec<Finding>,
    /// Findings naming a line the diff does not add. Kept rather than dropped:
    /// a model pointing at a line it cannot see is a signal about the review.
    pub unanchored: Vec<Finding>,
    pub truncated: bool,
    pub posted: bool,
    /// The commit the review was posted on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha: Option<String>,
    /// Why nothing was posted, when posting was asked for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
}

// --- diff annotation ------------------------------------------------------

pub type AddedLines = HashMap<String, BTreeSet<u64>>;

fn hunk_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"@@ -[0-9]+(?:,[0-9]+)? \+([0-9]+)(?:,[0-9]+)? @@").expect("static regex")
    })
}

/// The whole reason inline comments land in the right place.
///
/// A unified diff does not carry per-line numbers; it carries hunk headers
/// (`@@ -a,b +c,d @@`) and leaves the arithmetic to the reader. Asking a
/// language model to do that arithmetic is asking for off-by-N comments on
/// unrelated lines, which is worse than no comment at all. So the number is
/// computed here and written into the text the model reads. Each line becomes
/// `<marker><new line number>|<content>`; removed lines get no number because
/// GitHub cannot anchor a comment to them.
pub fn annotate_diff(diff: &str) -> (String, AddedLines) {
    let mut out: Vec<String> = vec![];
    let mut added: AddedLines = HashMap::new();
    let mut path = String::new();
    let mut new_line: u64 = 0;

    for raw in diff.split('\n') {
        if raw.starts_with("diff --git") {
            // "diff --git a/x b/x": take the b-side, which is the new path.
            path = raw
                .find(" b/")
                .map(|i| raw[i + 3..].to_owned())
                .unwrap_or_default();
            new_line = 0;
            out.push(format!(
                "\n### {}",
                if path.is_empty() { raw } else { &path }
            ));
            continue;
        }
        // +++ carries the authoritative new path and survives a rename.
        if let Some(rest) = raw.strip_prefix("+++ ") {
            let p = rest.trim();
            if p != "/dev/null" {
                path = p.strip_prefix("b/").unwrap_or(p).to_owned();
            }
            continue;
        }
        if raw.starts_with("--- ") {
            continue;
        }
        if [
            "index ",
            "new file mode",
            "deleted file mode",
            "similarity index",
            "rename from",
            "rename to",
            "old mode",
            "new mode",
        ]
        .iter()
        .any(|p| raw.starts_with(p))
        {
            continue;
        }
        if raw.starts_with("Binary files") {
            out.push("(binary file, not shown)".into());
            continue;
        }
        if raw.starts_with("@@") {
            // @@ -oldStart,oldCount +newStart,newCount @@ optional context
            new_line = hunk_re()
                .captures(raw)
                .and_then(|c| c[1].parse().ok())
                .unwrap_or(0);
            out.push(raw.to_owned());
            continue;
        }
        if new_line == 0 {
            continue; // outside any hunk
        }
        if let Some(rest) = raw.strip_prefix('+') {
            out.push(format!("+{new_line:>5}|{rest}"));
            if !path.is_empty() {
                added.entry(path.clone()).or_default().insert(new_line);
            }
            new_line += 1;
        } else if let Some(rest) = raw.strip_prefix('-') {
            out.push(format!("-     |{rest}"));
        } else if raw.starts_with('\\') {
            out.push(raw.to_owned()); // "\ No newline at end of file"
        } else {
            // A context line. The leading space is the diff marker, not content.
            let rest = raw.get(1..).unwrap_or("");
            out.push(format!(" {new_line:>5}|{rest}"));
            new_line += 1;
        }
    }
    (out.join("\n").trim().to_owned(), added)
}

/// Cut the annotated diff to a byte budget on a line boundary.
pub fn truncate(text: &str, max_bytes: usize) -> (String, bool) {
    if text.len() <= max_bytes {
        return (text.to_owned(), false);
    }
    let mut end = max_bytes;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let cut = &text[..end];
    let kept = match cut.rfind('\n') {
        Some(i) if i > 0 => &cut[..i],
        _ => cut,
    };
    (format!("{kept}\n"), true)
}

// --- the prompt -----------------------------------------------------------

/// What separates a review worth reading from a review everybody mutes.
///
/// The failure mode of an automated reviewer is not being wrong, it is being
/// voluminous: a bot that posts nine style nits and one real bug has buried
/// the bug. So the instruction that matters most is the one telling it to
/// return nothing when there is nothing. Formatting is excluded because
/// prettier and markdownlint already gate every pull request in this org.
pub const SYSTEM_PROMPT: &str = r#"You review a single pull request diff for the Nyuchi engineering org. You are one reviewer among humans, not a gate.

REPORT, and only these:
- Correctness bugs: wrong logic, off-by-one, unhandled null/undefined, a promise not awaited, a race, a case the code claims to handle but does not.
- Security: injected input reaching a URL, query or command; a credential or token in a log, an error message or a response; authentication or authorization that fails open (a check written so that missing configuration means "allow").
- Resource and error handling: an unclosed handle, an unbounded loop or fetch, a swallowed error, a retry with no ceiling.
- API misuse: a call whose arguments cannot mean what the code assumes.
- Tests that assert nothing, or that would still pass if the behaviour they name were removed.

DO NOT REPORT:
- Formatting, whitespace, quote style, import order, line length. Prettier and markdownlint gate every pull request here; a comment about them is a comment about a check that already runs.
- Naming preferences, "consider extracting this", "consider adding a comment", or any suggestion whose benefit is taste.
- Anything you cannot see. You have a diff, not the repository. If a call looks wrong only because you cannot see the function it calls, say nothing.
- Praise, summaries of what the diff does, or restatements of the title.

RULES:
- Every finding must name a line the diff ADDS. Those lines are marked with a leading "+" and carry their new-file line number before the "|". Use exactly that number. Context lines (leading space) and removed lines (leading "-") are NOT valid targets; if your point concerns one, put it in the summary instead.
- Quote the specific expression you mean. A finding that could apply to any code is not a finding.
- Say what goes wrong and under what input or state. "This could be a problem" is not a finding; "if headers is empty this throws on .get" is.
- Severity: "blocking" means it is wrong and will misbehave in production. "concern" means it is likely wrong or is a real risk under a plausible input. "note" is a genuine defect that is minor. If you are reaching for a reason to report something, do not report it.
- Returning zero findings is a correct and expected outcome. Do not pad. Do not invent a "note" so the review looks thorough. A clean diff should get an empty findings array and a one-sentence summary saying so.
- The summary is at most three sentences and says what you checked and what you concluded. It is not a description of the change."#;

/// The shape the model is asked to return, and the shape validated against.
pub fn findings_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "summary": { "type": "string" },
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" },
                        "line": { "type": "number" },
                        "severity": { "type": "string", "enum": ["blocking", "concern", "note"] },
                        "title": { "type": "string" },
                        "body": { "type": "string" },
                    },
                    "required": ["path", "line", "severity", "title", "body"],
                },
            },
        },
        "required": ["summary", "findings"],
    })
}

// --- validation -----------------------------------------------------------

/// `Number(v)` for the value kinds a model might hand back as a line.
fn js_number(v: Option<&Value>) -> f64 {
    match v {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
        Some(Value::String(s)) => {
            let t = s.trim();
            if t.is_empty() {
                0.0
            } else {
                t.parse().unwrap_or(f64::NAN)
            }
        }
        Some(Value::Bool(b)) => f64::from(u8::from(*b)),
        Some(Value::Null) => 0.0,
        _ => f64::NAN,
    }
}

/// Cloudflare's own JSON-mode documentation says it "can't guarantee that the
/// model responds according to the requested JSON Schema". So the schema is a
/// request, and this is the enforcement.
pub fn parse_findings(response: &Value) -> Result<(String, Vec<Finding>), GitHubError> {
    // The binding returns an object for some models and a JSON string for
    // others. Both are normal; neither is trusted.
    let parsed;
    let value = if let Value::String(s) = response {
        parsed = serde_json::from_str::<Value>(s).map_err(|_| {
            GitHubError::new("the review model did not return JSON", 502)
                .with_detail(Value::String(s.chars().take(500).collect()))
        })?;
        &parsed
    } else {
        response
    };
    let Value::Object(obj) = value else {
        return Err(GitHubError::new("the review model returned no object", 502));
    };
    let summary = obj
        .get("summary")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let raw = obj
        .get("findings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut findings = vec![];
    for item in &raw {
        let Value::Object(f) = item else { continue };
        let line = js_number(f.get("line"));
        let (Some(path), Some(body)) = (
            f.get("path")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty()),
            f.get("body")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty()),
        ) else {
            continue;
        };
        if !line.is_finite() || line.fract() != 0.0 || line < 1.0 {
            continue;
        }
        let severity = match f.get("severity").and_then(Value::as_str) {
            Some("blocking") => Severity::Blocking,
            Some("concern") => Severity::Concern,
            _ => Severity::Note,
        };
        findings.push(Finding {
            path: path.to_owned(),
            line: line as u64,
            severity,
            title: f
                .get("title")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
            body: body.to_owned(),
        });
    }
    Ok((summary, findings))
}

/// Split findings by whether GitHub can actually anchor them. A comment on a
/// line the diff does not add is rejected with a 422 that fails the whole
/// review call, so one hallucinated line number would otherwise lose every
/// real finding alongside it.
pub fn anchor(findings: Vec<Finding>, added: &AddedLines) -> (Vec<Finding>, Vec<Finding>) {
    let mut anchored = vec![];
    let mut unanchored = vec![];
    for f in findings {
        if added.get(&f.path).is_some_and(|s| s.contains(&f.line)) {
            anchored.push(f);
        } else {
            unanchored.push(f);
        }
    }
    (anchored, unanchored)
}

/// Most serious first, so a capped review keeps the findings that matter.
pub fn rank(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings.sort_by_key(|f| f.severity.rank()); // stable
    findings
}

/// The whole review, as one comment. One comment rather than one per finding,
/// because commit comments do not thread and ten of them on one commit is the
/// noise that gets a reviewer muted. Each finding names its own `path:line`.
pub fn render_body(
    model: &str,
    summary: &str,
    findings: &[Finding],
    unanchored: &[Finding],
    truncated: bool,
) -> String {
    let mut lines: Vec<String> = vec![
        REVIEW_MARKER.into(),
        "### Automated review".into(),
        String::new(),
        if summary.trim().is_empty() {
            "No summary returned.".into()
        } else {
            summary.trim().to_owned()
        },
    ];
    if findings.is_empty() {
        lines.push(String::new());
        lines.push("No findings.".into());
    } else {
        lines.push(String::new());
        for f in findings {
            lines.push(format!(
                "**{} `{}:{}`** — {}",
                f.severity.label(),
                f.path,
                f.line,
                f.title
            ));
            lines.push(String::new());
            lines.push(f.body.trim().to_owned());
            lines.push(String::new());
        }
    }
    if !unanchored.is_empty() {
        lines.push(String::new());
        lines.push(format!(
            "<details><summary>Not anchored to a line this change adds ({})</summary>",
            unanchored.len()
        ));
        lines.push(String::new());
        for f in unanchored {
            let what = if f.title.is_empty() {
                &f.body
            } else {
                &f.title
            };
            lines.push(format!("- `{}:{}` — {}", f.path, f.line, what));
        }
        lines.push(String::new());
        lines.push("</details>".into());
    }
    if truncated {
        lines.push(String::new());
        lines.push(
            "> The diff was larger than this reviewer's budget and was truncated. Changes after the cut were not read."
                .into(),
        );
    }
    lines.push(String::new());
    lines.push("---".into());
    lines.push(String::new());
    lines.push(format!(
        "_`{model}` on Workers AI. A commit comment, not a review: this cannot approve, request changes, or affect merge state._"
    ));
    lines.join("\n")
}

// --- the engine -----------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct ReviewOptions {
    pub model: Option<String>,
    /// Post the review to GitHub. Default false: a dry run is the safe default.
    pub post: bool,
    pub max_findings: Option<usize>,
    pub max_diff_bytes: Option<usize>,
    /// Post even if this commit already carries a review.
    pub force: bool,
    /// What caused this review: "push", "pull_request", "mention:<login>".
    /// Attached to the AI Gateway log, so spend can be read by cause and by
    /// repository rather than estimated.
    pub trigger: Option<String>,
}

fn trigger_kind(opts: &ReviewOptions) -> &str {
    opts.trigger
        .as_deref()
        .unwrap_or("manual")
        .split(':')
        .next()
        .unwrap_or("manual")
}

fn model_for(cfg: &Config, opts: &ReviewOptions) -> String {
    opts.model
        .clone()
        .filter(|m| !m.is_empty())
        .or_else(|| non_empty(&cfg.review_model).map(str::to_owned))
        .unwrap_or_else(|| DEFAULT_MODEL.to_owned())
}

/// Route inference through an AI Gateway when one is configured. Unset means
/// calling Workers AI directly. Set it and every review is logged with the
/// repository and what triggered it attached, so "what did this repository
/// cost this month" is a query rather than an estimate.
///
/// `skipCache` is true because a cached review is a wrong review: the same
/// diff reviewed twice is a person asking for a second opinion.
pub fn gateway_options(cfg: &Config, repo: &str, opts: &ReviewOptions) -> Option<Value> {
    let id = non_empty(&cfg.ai_gateway_id)?;
    Some(json!({
        "gateway": {
            "id": id,
            "skipCache": true,
            // Attribution only, and at most five scalars (the gateway's
            // limit). The trigger is reduced to its KIND: "mention:<login>"
            // names a person, and a login has no business in a cost log.
            "metadata": {
                "worker": "shamwari-github-mcp",
                "job": "pr_review",
                "repo": repo,
                "trigger": trigger_kind(opts),
            },
        }
    }))
}

/// A gateway dynamic route (`dynamic/<route>`) speaks the OpenAI chat
/// completions shape only; a Workers AI model id speaks the native one.
pub fn is_dynamic_route(model: &str) -> bool {
    model.starts_with("dynamic/")
}

pub fn response_format(model: &str) -> Value {
    if is_dynamic_route(model) {
        json!({
            "type": "json_schema",
            "json_schema": { "name": "review_findings", "schema": findings_schema() },
        })
    } else {
        json!({ "type": "json_schema", "json_schema": findings_schema() })
    }
}

/// The model's answer, from either response shape.
pub fn model_output(out: &Value) -> Value {
    if let Some(r) = out.get("response") {
        return r.clone();
    }
    out.get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .cloned()
        .unwrap_or(Value::Null)
}

/// The guards that must pass before anything is fetched or spent.
fn assert_runnable<P: Platform>(p: &P, cfg: &Config) -> Result<(), GitHubError> {
    if cfg.review_enabled.as_deref() == Some("false") {
        return Err(GitHubError::new(
            "the review agent is disabled (REVIEW_ENABLED=false)",
            503,
        ));
    }
    if !p.has_ai() {
        return Err(GitHubError::new(
            "no Workers AI binding: add [ai] binding = \"AI\" to wrangler.toml and redeploy",
            500,
        ));
    }
    Ok(())
}

/// Review a diff. The part that does not care where the diff came from.
async fn review_diff<P: Platform>(
    p: &P,
    cfg: &Config,
    repo: &str,
    diff: &str,
    opts: &ReviewOptions,
    conversation: &str,
) -> GhResult<ReviewResult> {
    let model = model_for(cfg, opts);
    let max_diff_bytes = opts
        .max_diff_bytes
        .filter(|n| *n > 0)
        .or_else(|| {
            cfg.review_max_diff_bytes
                .as_deref()
                .and_then(|s| s.trim().parse::<usize>().ok())
                .filter(|n| *n > 0)
        })
        .unwrap_or(DEFAULT_MAX_DIFF_BYTES);
    let max_findings = opts.max_findings.unwrap_or(10);

    let (text, added) = annotate_diff(diff);
    let (sent, truncated) = truncate(&text, max_diff_bytes);

    if sent.trim().is_empty() {
        return Ok(ReviewResult {
            model,
            summary: "Nothing to review — this change has no readable diff.".into(),
            findings: vec![],
            unanchored: vec![],
            truncated,
            posted: false,
            sha: None,
            skipped: None,
        });
    }

    let input = json!({
        "messages": [
            { "role": "system", "content": SYSTEM_PROMPT },
            { "role": "user", "content": format!(
                "Repository: {repo}\n\nAnnotated diff. Lines this change ADDS start with \"+\" and carry their new-file line number before the \"|\"; only those are valid finding targets.\n\n{sent}"
            ) },
        ],
        "response_format": response_format(&model),
    });
    // The gateway is the THIRD argument, not a field of the input object:
    // putting it in the input silently does nothing and the call still
    // succeeds, so the mistake shows up as a gateway with no traffic rather
    // than as an error.
    let options = gateway_options(cfg, repo, opts);

    // The model call is the agent's one `chat` span: metadata only (model id,
    // diff size, whether it was cut, token counts), never the diff, the
    // prompt or the response.
    let mut attrs = tracing::identity("chat", conversation);
    attrs.insert("gen_ai.request.model".into(), json!(model));
    attrs.insert("review.diff_bytes".into(), json!(sent.len()));
    attrs.insert("review.truncated".into(), json!(truncated));
    let (model_ref, input_ref, options_ref) = (&model, &input, options.as_ref());
    let out = p
        .in_span("chat", attrs, |span| async move {
            let res = p
                .ai_run(model_ref, input_ref, options_ref)
                .await
                .map_err(|e| Failure::Internal(format!("Workers AI call failed: {e}")))?;
            if let Some(n) = res
                .pointer("/usage/prompt_tokens")
                .filter(|v| v.is_number())
            {
                span.set("gen_ai.usage.input_tokens", n.clone());
            }
            if let Some(n) = res
                .pointer("/usage/completion_tokens")
                .filter(|v| v.is_number())
            {
                span.set("gen_ai.usage.output_tokens", n.clone());
            }
            Ok::<Value, Failure>(res)
        })
        .await?;

    let (summary, findings) = parse_findings(&model_output(&out))?;
    let (anchored, unanchored) = anchor(findings, &added);

    Ok(ReviewResult {
        model,
        summary,
        findings: rank(anchored).into_iter().take(max_findings).collect(),
        unanchored,
        truncated,
        posted: false,
        sha: None,
        skipped: None,
    })
}

/// True when this commit already carries a review from us.
pub async fn already_reviewed<P: Platform>(
    p: &P,
    cfg: &Config,
    repo: &str,
    sha: &str,
) -> GhResult<bool> {
    let comments = list_commit_comments(p, cfg, repo, sha).await?;
    Ok(comments.iter().any(|c| {
        c.get("body")
            .and_then(Value::as_str)
            .is_some_and(|b| b.contains(REVIEW_MARKER))
    }))
}

async fn post<P: Platform>(
    p: &P,
    cfg: &Config,
    repo: &str,
    sha: &str,
    mut result: ReviewResult,
    opts: &ReviewOptions,
) -> GhResult<ReviewResult> {
    if !opts.post {
        return Ok(result);
    }
    if !opts.force && already_reviewed(p, cfg, repo, sha).await? {
        result.posted = false;
        result.skipped = Some("already reviewed".into());
        return Ok(result);
    }
    let body = render_body(
        &result.model,
        &result.summary,
        &result.findings,
        &result.unanchored,
        result.truncated,
    );
    create_commit_comment(p, cfg, repo, sha, &body).await?;
    result.posted = true;
    result.sha = Some(sha.to_owned());
    Ok(result)
}

/// Answer "already reviewed" BEFORE the model is called. `post` has always
/// refused to write a second review on a commit, but it asked only after the
/// diff had been fetched and the model paid to read it, so a redelivery or a
/// re-request bought a full review and then threw it away. Asking first costs
/// one GitHub read and saves the model call. `post` still checks again, which
/// covers two deliveries racing.
async fn skip_if_reviewed<P: Platform>(
    p: &P,
    cfg: &Config,
    repo: &str,
    sha: &str,
    opts: &ReviewOptions,
) -> GhResult<Option<ReviewResult>> {
    if !opts.post || opts.force {
        return Ok(None);
    }
    if !already_reviewed(p, cfg, repo, sha).await? {
        return Ok(None);
    }
    Ok(Some(ReviewResult {
        model: model_for(cfg, opts),
        summary: String::new(),
        findings: vec![],
        unanchored: vec![],
        truncated: false,
        posted: false,
        sha: Some(sha.to_owned()),
        skipped: Some("already reviewed".into()),
    }))
}

fn record_outcome(span: &SpanHandle, r: &ReviewResult) {
    span.set("review.posted", json!(r.posted));
    span.set("review.findings", json!(r.findings.len()));
    span.set("review.unanchored", json!(r.unanchored.len()));
    if let Some(sk) = &r.skipped {
        span.set("review.skipped", json!(sk));
    }
}

fn agent_attrs(conversation: &str, opts: &ReviewOptions) -> Map<String, Value> {
    let mut attrs = tracing::identity("invoke_agent", conversation);
    attrs.insert("review.trigger".into(), json!(trigger_kind(opts)));
    attrs
}

/// Review the commits a push introduced, and comment on the new head.
///
/// `before` and `after` come from the pull_request webhook's `synchronize`
/// payload, so the model reads what just arrived rather than the whole pull
/// request it has already seen.
pub async fn review_push<P: Platform>(
    p: &P,
    cfg: &Config,
    repo: &str,
    before: &str,
    after: &str,
    opts: &ReviewOptions,
) -> GhResult<ReviewResult> {
    assert_runnable(p, cfg)?;
    let conversation = format!("{repo}@{}", after.chars().take(12).collect::<String>());
    p.in_span(
        "invoke_agent",
        agent_attrs(&conversation, opts),
        |span| async move {
            if let Some(skipped) = skip_if_reviewed(p, cfg, repo, after, opts).await? {
                record_outcome(&span, &skipped);
                return Ok(skipped);
            }
            let diff = compare_commits(p, cfg, repo, before, after).await?;
            let result = review_diff(p, cfg, repo, &diff, opts, &conversation).await?;
            let posted = post(p, cfg, repo, after, result, opts).await?;
            record_outcome(&span, &posted);
            Ok(posted)
        },
    )
    .await
}

/// Review a whole pull request, and comment on its head commit.
///
/// This is the catch-up path as much as the on-demand one: because drafts are
/// skipped, everything pushed while a pull request was a draft has never been
/// read, so `ready_for_review` reviews the lot rather than only the last push.
///
/// Defaults to a DRY RUN: the first thing to do with a new reviewer is read
/// what it would have said, and a dry run lets two models run over the same
/// pull request without either writing to it.
pub async fn review_pull_request<P: Platform>(
    p: &P,
    cfg: &Config,
    repo: &str,
    number: u64,
    opts: &ReviewOptions,
    head_sha: Option<&str>,
) -> GhResult<ReviewResult> {
    assert_runnable(p, cfg)?;
    if opts.post && head_sha.is_none() {
        return Err(
            GitHubError::new("cannot post a review without the head commit sha", 400).into(),
        );
    }
    let conversation = format!("{repo}#{number}");
    p.in_span(
        "invoke_agent",
        agent_attrs(&conversation, opts),
        |span| async move {
            if let Some(sha) = head_sha {
                if let Some(skipped) = skip_if_reviewed(p, cfg, repo, sha, opts).await? {
                    record_outcome(&span, &skipped);
                    return Ok(skipped);
                }
            }
            let diff = get_pull_request_diff(p, cfg, repo, number).await?;
            let result = review_diff(p, cfg, repo, &diff, opts, &conversation).await?;
            if !opts.post {
                record_outcome(&span, &result);
                return Ok(result);
            }
            let posted = post(p, cfg, repo, head_sha.unwrap_or_default(), result, opts).await?;
            record_outcome(&span, &posted);
            Ok(posted)
        },
    )
    .await
}
