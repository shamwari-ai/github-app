//! GitHub webhook ingest: the autonomous half of the review agent.
//!
//! The rule this implements: a review runs after a commit, its output goes in
//! a comment on that commit, and nothing runs on a draft pull request.
//!
//! "Nothing runs on a draft" has a consequence that is easy to miss: everything
//! pushed while a pull request was a draft is never read, so leaving draft
//! reviews the whole pull request rather than only the last push.

use crate::config::{non_empty, Config};
use crate::github::get_pull_request_head;
use crate::platform::Platform;
use crate::review::{review_pull_request, review_push, ReviewOptions};
use crate::util::split_csv;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{json, Value};
use sha2::Sha256;

/// The handle that summons a review. Configurable because this agent is
/// heading for a brand of its own and the handle people type is the most
/// visible thing about it.
pub const DEFAULT_MENTION: &str = "@shamwari";

/// Who may summon a review by mention. A SPENDING gate as much as an access
/// one: on a public repository anyone can comment, and without it a stranger
/// typing the handle bills model calls to the repository owner.
pub const DEFAULT_TRIGGER_ASSOCIATIONS: [&str; 3] = ["OWNER", "MEMBER", "COLLABORATOR"];

/// What a delivery should cause. Pure, so the rules are testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Push {
        repo: String,
        number: u64,
        before: String,
        after: String,
    },
    Full {
        repo: String,
        number: u64,
        head: String,
    },
    Mention {
        repo: String,
        number: u64,
        by: String,
    },
    Skip {
        reason: String,
    },
}

fn skip(reason: impl Into<String>) -> Decision {
    Decision::Skip {
        reason: reason.into(),
    }
}

const REVIEWED_ACTIONS: [&str; 3] = ["synchronize", "opened", "ready_for_review"];

fn s<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

/// `String(x)` for the values a payload field might hold.
fn js_string(v: Option<&Value>) -> String {
    match v {
        None => "undefined".into(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

/// Decide what a delivery means.
///
/// `pull_request` rather than `push`: a raw push event does not know whether
/// its commits belong to a pull request, let alone whether that pull request
/// is a draft, and `synchronize` carries `before` and `after`, which is
/// exactly the range "after a commit" means.
pub fn decide(
    event: &str,
    payload: &Value,
    mention: &str,
    allowed_associations: &[String],
) -> Decision {
    if event == "ping" {
        return skip("ping");
    }
    if event == "issue_comment" {
        let d = decide_mention(payload, mention);
        // Checked after the mention matched, so an ordinary comment from an
        // outside contributor is "no mention" rather than "not permitted": the
        // gate should be invisible to everyone not trying to use the handle.
        if matches!(d, Decision::Mention { .. }) && !may_trigger(payload, allowed_associations) {
            return skip("commenter may not trigger a review");
        }
        return d;
    }
    if event != "pull_request" {
        return skip(format!("event not handled: {event}"));
    }

    let null = Value::Null;
    let p = if payload.is_object() { payload } else { &null };
    let action = s(p, "action").unwrap_or("");
    if !REVIEWED_ACTIONS.contains(&action) {
        return skip(format!(
            "action not handled: {}",
            if action.is_empty() { "(none)" } else { action }
        ));
    }

    let pr = p.get("pull_request").unwrap_or(&null);

    // THE DRAFT RULE. Checked before anything is fetched or spent, and on the
    // payload rather than on a later lookup, so a pull request marked ready
    // mid-delivery cannot slip a draft review through.
    if pr.get("draft") == Some(&Value::Bool(true)) {
        return skip("draft pull request");
    }

    // A closed or merged pull request can still emit synchronize on a race.
    if let Some(state) = pr
        .get("state")
        .filter(|v| !v.is_null() && v.as_str() != Some(""))
    {
        if state.as_str() != Some("open") {
            return skip(format!("pull request is {}", js_string(Some(state))));
        }
    }

    let repo = p
        .get("repository")
        .and_then(|r| s(r, "full_name"))
        .filter(|r| !r.is_empty());
    let number = pr
        .get("number")
        .and_then(Value::as_f64)
        .filter(|n| n.fract() == 0.0 && *n >= 0.0);
    let head = pr
        .get("head")
        .and_then(|h| s(h, "sha"))
        .filter(|h| !h.is_empty());

    let (Some(repo), Some(number), Some(head)) = (repo, number, head) else {
        return skip("payload missing repository, number or head");
    };
    let number = number as u64;

    let before = s(p, "before").unwrap_or("");
    let after = s(p, "after").unwrap_or("");

    // A push onto an open, non-draft pull request: read what just arrived.
    if action == "synchronize" && !before.is_empty() && !after.is_empty() && !is_zero(before) {
        return Decision::Push {
            repo: repo.to_owned(),
            number,
            before: before.to_owned(),
            after: after.to_owned(),
        };
    }

    // Opened, or leaving draft: read the whole thing. On ready_for_review this
    // is the catch-up for every commit the draft rule skipped.
    Decision::Full {
        repo: repo.to_owned(),
        number,
        head: head.to_owned(),
    }
}

fn is_zero(sha: &str) -> bool {
    (7..=40).contains(&sha.len()) && sha.bytes().all(|b| b == b'0')
}

/// Does this text summon the agent?
///
/// Word-boundary matched and case-insensitive, so "@shamwari" fires and
/// "@shamwari-docs" or "email@shamwari.com" do not. A bare substring search
/// would make every mention of the brand a review request.
///
/// Equivalent to `(^|[^\w@/-])@handle(?![\w-])` (ASCII `\w`), written by hand
/// because the `regex` crate has no lookahead.
pub fn mentions(body: Option<&str>, handle: &str) -> bool {
    let Some(body) = body.filter(|b| !b.is_empty()) else {
        return false;
    };
    let needle = format!("@{}", handle.trim_start_matches('@')).to_lowercase();
    let hay = body.to_lowercase();
    let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut from = 0;
    while let Some(i) = hay[from..].find(&needle) {
        let start = from + i;
        let end = start + needle.len();
        let before_ok = hay[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !(word(c) || c == '@' || c == '/' || c == '-'));
        let after_ok = hay[end..]
            .chars()
            .next()
            .is_none_or(|c| !(word(c) || c == '-'));
        if before_ok && after_ok {
            return true;
        }
        from = start + needle.chars().next().map_or(1, char::len_utf8);
    }
    false
}

/// A comment asking for a review.
///
/// THE LOOP. A commit comment raises no pull_request event, so the agent could
/// not trigger itself. `issue_comment` changes that: the moment this agent (or
/// any bot) writes its own handle in a comment, it summons itself. So every
/// comment from a Bot account is ignored, full stop.
///
/// THE DRAFT RULE DOES NOT APPLY. Automatic review skips drafts because nobody
/// asked for it. Here somebody did, by name; refusing them would obey the
/// letter of the rule against its entire purpose.
fn decide_mention(payload: &Value, mention: &str) -> Decision {
    let null = Value::Null;
    let p = if payload.is_object() { payload } else { &null };
    if s(p, "action") != Some("created") {
        // "edited" is excluded deliberately: editing a comment to add the
        // handle would let one comment be re-triggered indefinitely.
        return skip(format!(
            "comment action not handled: {}",
            js_string(p.get("action"))
        ));
    }

    let comment = p.get("comment").unwrap_or(&null);
    let user = comment.get("user").unwrap_or(&null);

    if s(user, "type") == Some("Bot") {
        return skip("comment is from a bot");
    }
    if !mentions(s(comment, "body"), mention) {
        return skip("no mention");
    }

    let issue = p.get("issue").unwrap_or(&null);
    if issue.get("pull_request").is_none_or(|v| v.is_null()) {
        return skip("comment is on an issue, not a pull request");
    }
    if let Some(state) = issue
        .get("state")
        .filter(|v| !v.is_null() && v.as_str() != Some(""))
    {
        if state.as_str() != Some("open") {
            return skip(format!("pull request is {}", js_string(Some(state))));
        }
    }

    let repo = p
        .get("repository")
        .and_then(|r| s(r, "full_name"))
        .filter(|r| !r.is_empty());
    let number = issue
        .get("number")
        .and_then(Value::as_f64)
        .filter(|n| n.fract() == 0.0 && *n >= 0.0);
    let (Some(repo), Some(number)) = (repo, number) else {
        return skip("payload missing repository or number");
    };

    Decision::Mention {
        repo: repo.to_owned(),
        number: number as u64,
        by: s(user, "login").unwrap_or("").to_owned(),
    }
}

/// Is this commenter allowed to spend a review?
pub fn may_trigger(payload: &Value, allowed: &[String]) -> bool {
    let assoc = payload
        .get("comment")
        .and_then(|c| s(c, "author_association"))
        .unwrap_or("");
    allowed.iter().any(|a| a == assoc)
}

/// Verify GitHub's HMAC-SHA256 signature over the raw body.
///
/// `Mac::verify_slice` is constant-time, so a signature cannot be recovered a
/// byte at a time by timing the response. The raw body must be the bytes
/// GitHub signed, which is why the caller reads the text once and parses it
/// afterwards rather than re-serialising.
pub fn verify_signature(secret: &str, raw_body: &str, header: Option<&str>) -> bool {
    let Some(header) = header else { return false };
    if secret.is_empty() {
        return false;
    }
    let mut it = header.split('=');
    let (scheme, hex) = (it.next().unwrap_or(""), it.next().unwrap_or(""));
    if scheme != "sha256" || hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    // A stated precondition, not the thing that makes this safe: a digest of
    // the wrong length would fail the comparison anyway.
    if hex.len() != 64 {
        return false;
    }
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        match u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16) {
            Ok(v) => *b = v,
            Err(_) => return false,
        }
    }
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(raw_body.as_bytes());
    mac.verify_slice(&bytes).is_ok()
}

/// What the HTTP layer should answer, and what to run after answering.
pub struct WebhookOutcome {
    pub status: u16,
    pub body: Value,
    /// Work to run after the response (`ctx.waitUntil`).
    pub job: Option<Decision>,
}

fn out(status: u16, body: Value) -> WebhookOutcome {
    WebhookOutcome {
        status,
        body,
        job: None,
    }
}

/// Handle one delivery's request: everything up to deciding what to run.
///
/// GitHub is answered immediately and the review runs in `waitUntil`: a review
/// is a model call over a diff and takes far longer than the ten seconds
/// GitHub allows. The honest limit: `waitUntil` has no retry and no
/// backpressure. If the Worker is evicted mid-review, that review is lost: the
/// commit simply never gets a comment, which is a visible absence rather than
/// a silent wrong answer, and re-requesting the delivery re-runs it.
pub fn handle_webhook(
    cfg: &Config,
    method: &str,
    raw_body: &str,
    signature: Option<&str>,
    event: Option<&str>,
) -> WebhookOutcome {
    if method != "POST" {
        return out(405, json!({ "error": "method not allowed" }));
    }
    let Some(secret) = non_empty(&cfg.github_webhook_secret) else {
        // Fail closed. An unset secret means every delivery is unauthenticated,
        // and an endpoint that reviews on unauthenticated input is an endpoint
        // anyone can bill to this account.
        return out(503, json!({ "error": "webhook not configured" }));
    };
    if !verify_signature(secret, raw_body, signature) {
        return out(401, json!({ "error": "bad signature" }));
    }
    let Ok(payload) = serde_json::from_str::<Value>(raw_body) else {
        return out(400, json!({ "error": "body is not JSON" }));
    };

    let configured = split_csv(cfg.review_trigger_associations.as_deref());
    let associations: Vec<String> = if configured.is_empty() {
        DEFAULT_TRIGGER_ASSOCIATIONS
            .iter()
            .map(|s| (*s).to_owned())
            .collect()
    } else {
        configured
    };
    let decision = decide(
        event.unwrap_or(""),
        &payload,
        non_empty(&cfg.review_mention).unwrap_or(DEFAULT_MENTION),
        &associations,
    );

    let (repo, number, kind) = match &decision {
        Decision::Skip { reason } => {
            return out(200, json!({ "ok": true, "skipped": reason }));
        }
        Decision::Push { repo, number, .. } => (repo.clone(), *number, "push"),
        Decision::Full { repo, number, .. } => (repo.clone(), *number, "full"),
        Decision::Mention { repo, number, .. } => (repo.clone(), *number, "mention"),
    };

    // The same allowlist every tool call passes. Checked here as well as in
    // github.rs so a repository outside it costs nothing rather than failing
    // after a token mint. (Exact, case-sensitive match, as before.)
    let allowed = split_csv(cfg.github_allowed_repos.as_deref());
    if !allowed.contains(&repo) {
        return out(
            200,
            json!({ "ok": true, "skipped": "repository not allowlisted" }),
        );
    }

    WebhookOutcome {
        status: 202,
        body: json!({ "ok": true, "queued": kind, "repo": repo, "pull_request": number }),
        job: Some(decision),
    }
}

/// Run the review a decision calls for. Never retries: a model call that
/// failed on a malformed diff will fail the same way and this path is not rate
/// limited. The absence of a comment is the signal.
pub async fn run_job<P: Platform>(p: &P, cfg: &Config, d: &Decision) {
    let (repo, number) = match d {
        Decision::Skip { .. } => return,
        Decision::Push { repo, number, .. }
        | Decision::Full { repo, number, .. }
        | Decision::Mention { repo, number, .. } => (repo.clone(), *number),
    };
    let result = match d {
        Decision::Push {
            repo,
            before,
            after,
            ..
        } => {
            review_push(
                p,
                cfg,
                repo,
                before,
                after,
                &ReviewOptions {
                    post: true,
                    trigger: Some("push".into()),
                    ..Default::default()
                },
            )
            .await
        }
        Decision::Mention { repo, number, by } => {
            // One lookup: the comment payload carries no head sha. The draft
            // flag it returns is deliberately NOT consulted: a person asking
            // by name overrides a rule that exists to prevent unasked-for
            // reviews.
            match get_pull_request_head(p, cfg, repo, *number).await {
                Ok(head) => {
                    review_pull_request(
                        p,
                        cfg,
                        repo,
                        *number,
                        &ReviewOptions {
                            post: true,
                            // asking again is the entire point of asking.
                            force: true,
                            trigger: Some(format!("mention:{by}")),
                            ..Default::default()
                        },
                        Some(&head.sha),
                    )
                    .await
                }
                Err(e) => Err(e),
            }
        }
        Decision::Full { repo, number, head } => {
            review_pull_request(
                p,
                cfg,
                repo,
                *number,
                &ReviewOptions {
                    post: true,
                    trigger: Some("pull_request".into()),
                    ..Default::default()
                },
                Some(head),
            )
            .await
        }
        Decision::Skip { .. } => return,
    };
    match result {
        Ok(r) => crate::log::info(&format!(
            "reviewed {repo}#{number} {}",
            json!({
                "posted": r.posted,
                "skipped": r.skipped,
                "findings": r.findings.len(),
                "unanchored": r.unanchored.len(),
                "model": r.model,
            })
        )),
        Err(e) => crate::log::error(&format!("review failed for {repo}#{number}: {e}")),
    }
}
