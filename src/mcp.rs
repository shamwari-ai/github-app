//! MCP (Model Context Protocol) surface for the GitHub worker.
//!
//! A hand-written, stateless Streamable HTTP binding of JSON-RPC 2.0 serving
//! both protocol eras from one tool table:
//!
//!   * the 2026-07-28 per-request revision (`server/discover`, per-request
//!     `_meta` envelope, mirrored `MCP-Protocol-Version` / `Mcp-Method` /
//!     `Mcp-Name` headers, meaningful HTTP statuses), and
//!   * the legacy `initialize` handshake, answered statelessly.
//!
//! The era classification and the error codes and statuses follow the
//! TypeScript MCP SDK (v2.4) this Worker used before the port; see
//! docs/rust-port.md for what is and is not reproduced.
//!
//! Read tools, PR tools and issue tools. There is no approve tool and no merge
//! tool: `github::create_review` refuses APPROVE, and merging needs
//! `contents: write`, which the scoped token does not ask for, so a merge tool
//! could not work here even if one existed.

use crate::config::Config;
use crate::error::{Failure, GitHubError};
use crate::github;
use crate::platform::Platform;
use crate::review::{review_pull_request, ReviewOptions};
use crate::router::{Req, Resp};
use crate::util::b64_decode;
use serde_json::{json, Map, Value};

pub const SERVER_NAME: &str = "shamwari-github-mcp";
pub const SERVER_TITLE: &str = "Shamwari for GitHub";
pub const SERVER_VERSION: &str = "0.1.0";

const INSTRUCTIONS: &str = "GitHub review, pull request and issue operations for the repositories the App is installed on. Call shamwari_whoami first: it reports, per installation, whether that installation grants the permissions the scoped token requests.";

/// The only revision of the 2026 era this server speaks.
pub const MODERN_VERSION: &str = "2026-07-28";
/// Legacy revisions answered on `initialize`, newest first.
pub const LEGACY_VERSIONS: [&str; 5] = [
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
    "2024-10-07",
];

const META_PROTOCOL: &str = "io.modelcontextprotocol/protocolVersion";
const META_CLIENT_CAPS: &str = "io.modelcontextprotocol/clientCapabilities";
const META_CLIENT_INFO: &str = "io.modelcontextprotocol/clientInfo";
const META_SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";

pub const HEADER_MISMATCH: i64 = -32020;
pub const UNSUPPORTED_VERSION: i64 = -32022;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;
pub const INTERNAL_ERROR: i64 = -32603;
pub const PARSE_ERROR: i64 = -32700;

// ---------------------------------------------------------------------------
// Tool table
// ---------------------------------------------------------------------------

/// Behaviour hints a client can surface before running a tool. They are hints,
/// not enforcement: the real guarantees are the scoped token (contents:read,
/// no workflows) and `create_review` refusing APPROVE. They let a client show
/// which tools write before it calls one.
#[derive(Clone, Copy)]
pub struct Annotations {
    pub read_only: bool,
    pub destructive: bool,
    pub idempotent: bool,
}

/// Reads nothing but the API; safe to repeat.
const READ: Annotations = Annotations {
    read_only: true,
    destructive: false,
    idempotent: true,
};
/// Adds something new each call: a second call makes a second thing.
const CREATE: Annotations = Annotations {
    read_only: false,
    destructive: false,
    idempotent: false,
};
/// Overwrites existing fields: repeating is safe but the old value is gone.
const UPDATE: Annotations = Annotations {
    read_only: false,
    destructive: true,
    idempotent: true,
};

#[derive(Clone, Copy)]
enum Kind {
    Str { min1: bool },
    Int { min: i64, max: Option<i64> },
    Bool,
    Enum(&'static [&'static str]),
    StrArray,
    Comments,
}

#[derive(Clone)]
struct Field {
    name: &'static str,
    kind: Kind,
    required: bool,
    default: Option<Value>,
    desc: Option<&'static str>,
}

struct ToolDef {
    name: &'static str,
    description: &'static str,
    ann: Annotations,
    fields: Vec<Field>,
}

fn f(name: &'static str, kind: Kind) -> Field {
    Field {
        name,
        kind,
        required: true,
        default: None,
        desc: None,
    }
}

impl Field {
    fn opt(mut self) -> Self {
        self.required = false;
        self
    }
    fn default(mut self, v: Value) -> Self {
        self.required = false;
        self.default = Some(v);
        self
    }
    fn desc(mut self, d: &'static str) -> Self {
        self.desc = Some(d);
        self
    }
}

const STATE3: &[&str] = &["open", "closed", "all"];
const STATE2: &[&str] = &["open", "closed"];

fn repo() -> Field {
    f("repo", Kind::Str { min1: true })
        .desc("Repository as owner/repo, as granted by the installation.")
}
fn number() -> Field {
    f("number", Kind::Int { min: 1, max: None })
}
fn state3() -> Field {
    f("state", Kind::Enum(STATE3)).default(json!("open"))
}
fn limit() -> Field {
    f(
        "limit",
        Kind::Int {
            min: 1,
            max: Some(100),
        },
    )
    .default(json!(20))
}
fn page() -> Field {
    f("page", Kind::Int { min: 1, max: None })
        .opt()
        .desc("Page, from 1.")
}
fn s_opt(name: &'static str) -> Field {
    f(name, Kind::Str { min1: false }).opt()
}

fn tools() -> Vec<ToolDef> {
    vec![
        ToolDef {
            name: "shamwari_whoami",
            ann: READ,
            description: "Verify the GitHub App credentials and report, for EVERY installation, whether it grants the permissions the scoped token asks for. Use this first when anything returns 422 or 404: a token mint requests the whole permission set in one call, so a single gap fails every tool on that installation, and a permission the App declares is not held until the installation owner accepts it.",
            fields: vec![],
        },
        ToolDef {
            name: "shamwari_list_pull_requests",
            ann: READ,
            description: "List pull requests, most recently updated first. Returns {items, count, page, has_more, next_page} with each entry trimmed to number, title, state, draft, author, base, head, labels, timestamps and url — call shamwari_get_pull_request for the rest.",
            fields: vec![repo(), state3(), limit(), page()],
        },
        ToolDef {
            name: "shamwari_get_pull_request",
            ann: READ,
            description: "One pull request in review-ready form: metadata, mergeability, the changed-file list, and a check-run rollup naming what is failing and what is still pending.",
            fields: vec![repo(), number()],
        },
        ToolDef {
            name: "shamwari_get_pull_request_diff",
            ann: READ,
            description: "The unified diff for a pull request. This is the text to actually review; fetch it before writing a review rather than reasoning from the file list alone.",
            fields: vec![repo(), number()],
        },
        ToolDef {
            name: "shamwari_create_review",
            ann: CREATE,
            description: "Submit a pull request review with an optional set of inline comments. Events are COMMENT or REQUEST_CHANGES only — this server refuses to approve pull requests, so a review from here never satisfies a branch protection review requirement.",
            fields: vec![
                repo(),
                number(),
                f("event", Kind::Enum(&["COMMENT", "REQUEST_CHANGES"])),
                f("body", Kind::Str { min1: true }).desc("The review summary."),
                f("comments", Kind::Comments)
                    .opt()
                    .desc("Inline comments. `line` is a line in the diff of `path`."),
            ],
        },
        ToolDef {
            name: "shamwari_create_pull_request",
            ann: CREATE,
            description: "Open a pull request. Draft unless draft is explicitly false, so an agent-opened PR does not demand review attention before a human has looked at it.",
            fields: vec![
                repo(),
                f("title", Kind::Str { min1: true }),
                f("head", Kind::Str { min1: true }).desc("The branch with the changes."),
                f("base", Kind::Str { min1: true }).desc("The branch to merge into."),
                s_opt("body"),
                f("draft", Kind::Bool).default(json!(true)),
            ],
        },
        ToolDef {
            name: "shamwari_update_pull_request",
            ann: UPDATE,
            description: "Change a pull request's title, body, base branch, or state (open/closed). Cannot merge: the scoped token holds contents:read only.",
            fields: vec![
                repo(),
                number(),
                s_opt("title"),
                s_opt("body"),
                s_opt("base"),
                f("state", Kind::Enum(STATE2)).opt(),
            ],
        },
        ToolDef {
            name: "shamwari_list_issues",
            ann: READ,
            description: "List issues, most recently updated first. Returns {items, count, page, has_more, next_page}; each entry carries is_pull_request because GitHub returns pull requests from this endpoint too.",
            fields: vec![repo(), state3(), limit(), page()],
        },
        ToolDef {
            name: "shamwari_get_issue",
            ann: READ,
            description: "One issue in full.",
            fields: vec![repo(), number()],
        },
        ToolDef {
            name: "shamwari_create_issue",
            ann: CREATE,
            description: "File an issue.",
            fields: vec![
                repo(),
                f("title", Kind::Str { min1: true }),
                s_opt("body"),
                f("labels", Kind::StrArray).opt(),
                f("assignees", Kind::StrArray).opt(),
            ],
        },
        ToolDef {
            name: "shamwari_update_issue",
            ann: UPDATE,
            description: "Retitle, re-body, relabel, reassign, or open/close an issue.",
            fields: vec![
                repo(),
                number(),
                s_opt("title"),
                s_opt("body"),
                f("state", Kind::Enum(STATE2)).opt(),
                f("labels", Kind::StrArray).opt(),
                f("assignees", Kind::StrArray).opt(),
            ],
        },
        ToolDef {
            name: "shamwari_comment",
            ann: CREATE,
            description: "Post a comment on an issue or a pull request (they share a numbering space and an endpoint).",
            fields: vec![repo(), number(), f("body", Kind::Str { min1: true })],
        },
        ToolDef {
            // CREATE rather than READ because this tool CAN post. It defaults
            // to a dry run, but an annotation describes what a tool may do,
            // not what it usually does: a client deciding whether to confirm
            // needs the ceiling.
            name: "shamwari_review_pull_request",
            ann: CREATE,
            description: "Review a pull request with a model running on Workers AI and return the findings, each naming a line the diff adds. DRY RUN by default: nothing is posted unless post is true, so the same call can compare two models on one pull request without either writing to it. When it does post, it posts ONE comment on the head commit — never a pull request review — so it cannot approve, cannot request changes, and cannot affect merge state. Findings come back most serious first and capped; anything the model aimed at a line the diff does not add is returned separately under unanchored rather than dropped.",
            fields: vec![
                repo(),
                number(),
                s_opt("model").desc("Workers AI model id, e.g. \"@cf/zai-org/glm-5.3\", \"@cf/zai-org/glm-5.3-flash\" or \"@cf/moonshotai/kimi-k2.7-code\". Defaults to REVIEW_MODEL. Pass it explicitly to compare models on the same pull request."),
                f("post", Kind::Bool).opt().desc("Post the review to GitHub. Default false — read the findings first."),
                s_opt("head_sha").desc("The commit to comment on. Required only when post is true — the review is posted as a comment on that commit, never as a pull request review."),
                f("max_findings", Kind::Int { min: 1, max: None }).opt().desc("Cap on reported findings. Default 10."),
                f("force", Kind::Bool).opt().desc("Post even if this commit already carries a review. Default false."),
            ],
        },
    ]
}

fn field_schema(fd: &Field) -> Value {
    let mut m = Map::new();
    match fd.kind {
        Kind::Str { min1 } => {
            m.insert("type".into(), json!("string"));
            if min1 {
                m.insert("minLength".into(), json!(1));
            }
        }
        Kind::Int { min, max } => {
            m.insert("type".into(), json!("integer"));
            m.insert("minimum".into(), json!(min));
            if let Some(max) = max {
                m.insert("maximum".into(), json!(max));
            }
        }
        Kind::Bool => {
            m.insert("type".into(), json!("boolean"));
        }
        Kind::Enum(vals) => {
            m.insert("type".into(), json!("string"));
            m.insert("enum".into(), json!(vals));
        }
        Kind::StrArray => {
            m.insert("type".into(), json!("array"));
            m.insert("items".into(), json!({ "type": "string" }));
        }
        Kind::Comments => {
            m.insert("type".into(), json!("array"));
            m.insert(
                "items".into(),
                json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "minLength": 1 },
                        "line": { "type": "integer", "minimum": 1 },
                        "body": { "type": "string", "minLength": 1 },
                    },
                    "required": ["path", "line", "body"],
                }),
            );
        }
    }
    if let Some(d) = &fd.default {
        m.insert("default".into(), d.clone());
    }
    if let Some(d) = fd.desc {
        m.insert("description".into(), json!(d));
    }
    Value::Object(m)
}

fn input_schema(t: &ToolDef) -> Value {
    let mut props = Map::new();
    let mut required = vec![];
    for fd in &t.fields {
        props.insert(fd.name.into(), field_schema(fd));
        if fd.required {
            required.push(fd.name);
        }
    }
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": props,
        "required": required,
        "additionalProperties": false,
    })
}

fn tool_json(t: &ToolDef) -> Value {
    json!({
        "name": t.name,
        "description": t.description,
        "inputSchema": input_schema(t),
        "annotations": {
            "readOnlyHint": t.ann.read_only,
            "destructiveHint": t.ann.destructive,
            "idempotentHint": t.ann.idempotent,
            "openWorldHint": true,
        },
    })
}

/// The `tools/list` payload.
pub fn tools_list() -> Vec<Value> {
    tools().iter().map(tool_json).collect()
}

// ---------------------------------------------------------------------------
// Argument validation (what the Zod schemas did)
// ---------------------------------------------------------------------------

fn js_type(v: Option<&Value>) -> &'static str {
    match v {
        None => "undefined",
        Some(Value::Null) => "null",
        Some(Value::Bool(_)) => "boolean",
        Some(Value::Number(_)) => "number",
        Some(Value::String(_)) => "string",
        Some(Value::Array(_)) => "array",
        Some(Value::Object(_)) => "object",
    }
}

fn is_int(v: &Value) -> Option<i64> {
    let n = v.as_f64()?;
    (n.fract() == 0.0 && n.abs() <= 9_007_199_254_740_991.0).then_some(n as i64)
}

fn check(fd: &Field, v: &Value) -> Result<Value, String> {
    let bad = |expected: &str| {
        format!(
            "{}: Invalid input: expected {expected}, received {}",
            fd.name,
            js_type(Some(v))
        )
    };
    match fd.kind {
        Kind::Str { min1 } => {
            let s = v.as_str().ok_or_else(|| bad("string"))?;
            if min1 && s.is_empty() {
                return Err(format!(
                    "{}: Too small: expected string to have >=1 characters",
                    fd.name
                ));
            }
            Ok(v.clone())
        }
        Kind::Int { min, max } => {
            if !v.is_number() {
                return Err(bad("number"));
            }
            let Some(n) = is_int(v) else {
                return Err(format!(
                    "{}: Invalid input: expected int, received number",
                    fd.name
                ));
            };
            if n < min {
                return Err(format!(
                    "{}: Too small: expected number to be >={min}",
                    fd.name
                ));
            }
            if let Some(max) = max {
                if n > max {
                    return Err(format!(
                        "{}: Too big: expected number to be <={max}",
                        fd.name
                    ));
                }
            }
            Ok(json!(n))
        }
        Kind::Bool => v
            .is_boolean()
            .then(|| v.clone())
            .ok_or_else(|| bad("boolean")),
        Kind::Enum(vals) => match v.as_str() {
            Some(s) if vals.contains(&s) => Ok(v.clone()),
            _ => Err(format!(
                "{}: Invalid option: expected one of {}",
                fd.name,
                vals.iter()
                    .map(|x| format!("\"{x}\""))
                    .collect::<Vec<_>>()
                    .join("|")
            )),
        },
        Kind::StrArray => {
            let a = v.as_array().ok_or_else(|| bad("array"))?;
            if a.iter().all(Value::is_string) {
                Ok(v.clone())
            } else {
                Err(format!(
                    "{}: Invalid input: expected string array items",
                    fd.name
                ))
            }
        }
        Kind::Comments => {
            let a = v.as_array().ok_or_else(|| bad("array"))?;
            let mut out = vec![];
            for (i, c) in a.iter().enumerate() {
                let path = c
                    .get("path")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty());
                let body = c
                    .get("body")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty());
                let line = c.get("line").and_then(is_int).filter(|n| *n >= 1);
                match (path, line, body) {
                    (Some(p), Some(l), Some(b)) => {
                        out.push(json!({ "path": p, "line": l, "body": b }))
                    }
                    _ => {
                        return Err(format!(
                            "{}.{i}: Invalid input: expected {{ path, line, body }} with a non-empty path and body and a positive integer line",
                            fd.name
                        ))
                    }
                }
            }
            Ok(Value::Array(out))
        }
    }
}

/// Validate and default tool arguments. Unknown keys are dropped (Zod's
/// default object behaviour).
fn validate(t: &ToolDef, args: &Value) -> Result<Map<String, Value>, Failure> {
    let empty = Map::new();
    let given = match args {
        Value::Object(m) => m,
        Value::Null => &empty,
        _ => {
            return Err(Failure::Argument(format!(
                "Invalid arguments for tool {}: expected an object, received {}",
                t.name,
                js_type(Some(args))
            )))
        }
    };
    let mut out = Map::new();
    let mut issues = vec![];
    for fd in &t.fields {
        match given.get(fd.name).filter(|v| !v.is_null() || fd.required) {
            Some(v) => match check(fd, v) {
                Ok(v) => {
                    out.insert(fd.name.into(), v);
                }
                Err(e) => issues.push(e),
            },
            None => {
                if let Some(d) = &fd.default {
                    out.insert(fd.name.into(), d.clone());
                } else if fd.required {
                    let expected = match fd.kind {
                        Kind::Int { .. } => "number",
                        Kind::Bool => "boolean",
                        Kind::StrArray | Kind::Comments => "array",
                        _ => "string",
                    };
                    issues.push(format!(
                        "{}: Invalid input: expected {expected}, received undefined",
                        fd.name
                    ));
                }
            }
        }
    }
    if issues.is_empty() {
        Ok(out)
    } else {
        Err(Failure::Argument(format!(
            "Invalid arguments for tool {}: {}",
            t.name,
            issues.join("; ")
        )))
    }
}

// ---------------------------------------------------------------------------
// Running a tool
// ---------------------------------------------------------------------------

/// Everything a PATCH-style tool needs: at least one field must change.
fn only_defined(a: &Map<String, Value>, keys: &[&str]) -> Result<Map<String, Value>, Failure> {
    let mut patch = Map::new();
    for k in keys {
        if let Some(v) = a.get(*k) {
            patch.insert((*k).to_owned(), v.clone());
        }
    }
    if patch.is_empty() {
        return Err(Failure::Argument(
            "nothing to update: pass at least one field to change".into(),
        ));
    }
    Ok(patch)
}

fn pick(a: &Map<String, Value>, keys: &[&str]) -> Map<String, Value> {
    keys.iter()
        .filter_map(|k| a.get(*k).map(|v| ((*k).to_owned(), v.clone())))
        .collect()
}

fn str_arg<'a>(a: &'a Map<String, Value>, k: &str) -> &'a str {
    a.get(k).and_then(Value::as_str).unwrap_or("")
}
fn num_arg(a: &Map<String, Value>, k: &str) -> u64 {
    a.get(k).and_then(Value::as_u64).unwrap_or(0)
}

/// What a tool returns: a string as plain text, anything else as pretty JSON.
enum Output {
    Json(Value),
    Text(String),
}

async fn run_tool<P: Platform>(
    p: &P,
    cfg: &Config,
    name: &str,
    a: &Map<String, Value>,
) -> Result<Output, Failure> {
    let r = str_arg(a, "repo");
    let n = num_arg(a, "number");
    Ok(match name {
        "shamwari_whoami" => Output::Json(github::whoami(p, cfg).await?),
        "shamwari_list_pull_requests" => Output::Json(
            github::list_pull_requests(
                p,
                cfg,
                r,
                str_arg(a, "state"),
                num_arg(a, "limit") as usize,
                a.get("page").and_then(Value::as_u64).unwrap_or(1),
            )
            .await?,
        ),
        "shamwari_get_pull_request" => Output::Json(github::get_pull_request(p, cfg, r, n).await?),
        "shamwari_get_pull_request_diff" => {
            Output::Text(github::get_pull_request_diff(p, cfg, r, n).await?)
        }
        "shamwari_create_review" => Output::Json(
            github::create_review(
                p,
                cfg,
                r,
                n,
                str_arg(a, "event"),
                str_arg(a, "body"),
                a.get("comments")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default(),
            )
            .await?,
        ),
        "shamwari_create_pull_request" => Output::Json(
            github::create_pull_request(
                p,
                cfg,
                r,
                pick(a, &["title", "head", "base", "body", "draft"]),
            )
            .await?,
        ),
        "shamwari_update_pull_request" => Output::Json(
            github::update_pull_request(
                p,
                cfg,
                r,
                n,
                only_defined(a, &["title", "body", "base", "state"])?,
            )
            .await?,
        ),
        "shamwari_list_issues" => Output::Json(
            github::list_issues(
                p,
                cfg,
                r,
                str_arg(a, "state"),
                num_arg(a, "limit") as usize,
                a.get("page").and_then(Value::as_u64).unwrap_or(1),
            )
            .await?,
        ),
        "shamwari_get_issue" => Output::Json(github::get_issue(p, cfg, r, n).await?),
        "shamwari_create_issue" => Output::Json(
            github::create_issue(
                p,
                cfg,
                r,
                pick(a, &["title", "body", "labels", "assignees"]),
            )
            .await?,
        ),
        "shamwari_update_issue" => Output::Json(
            github::update_issue(
                p,
                cfg,
                r,
                n,
                only_defined(a, &["title", "body", "state", "labels", "assignees"])?,
            )
            .await?,
        ),
        "shamwari_comment" => {
            Output::Json(github::create_comment(p, cfg, r, n, str_arg(a, "body")).await?)
        }
        "shamwari_review_pull_request" => {
            let opts = ReviewOptions {
                model: a.get("model").and_then(Value::as_str).map(str::to_owned),
                post: a.get("post") == Some(&Value::Bool(true)),
                force: a.get("force") == Some(&Value::Bool(true)),
                max_findings: a
                    .get("max_findings")
                    .and_then(Value::as_u64)
                    .map(|n| n as usize),
                ..Default::default()
            };
            let head = a.get("head_sha").and_then(Value::as_str);
            let res = review_pull_request(p, cfg, r, n, &opts, head).await?;
            Output::Json(serde_json::to_value(res).unwrap_or(Value::Null))
        }
        other => {
            return Err(Failure::Argument(format!("Tool {other} not found")));
        }
    })
}

/// What a tool call returns on the wire.
pub struct ToolResult {
    pub text: String,
    pub is_error: bool,
}

/// What a failed tools/call returns.
///
/// An argument error names the field the caller got wrong, and a GitHub error
/// names the repository, permission or status: both are written to be read by
/// the caller and acted on, so both pass through. Anything else is an
/// unexpected failure whose message is internal detail (a stack fragment, a
/// property name, an internal URL): log it, return a generic string. This is
/// the same rule the transport path applies; the two error paths must not
/// disagree about what a caller may see.
pub fn tool_error(name: &str, e: &Failure) -> ToolResult {
    match e {
        Failure::Argument(m) => ToolResult {
            text: format!("Error: {m}"),
            is_error: true,
        },
        Failure::GitHub(g) => ToolResult {
            text: format!("Error: {}", g.message),
            is_error: true,
        },
        Failure::Internal(m) => {
            crate::log::error(&format!("tools/call {name} failed: {m}"));
            ToolResult {
                text: "Error: internal error. The cause is in the worker log, not in the arguments — the same call will fail the same way.".into(),
                is_error: true,
            }
        }
    }
}

/// Call a tool by name with raw arguments, as `tools/call` does. Returns
/// `None` for an unknown tool (a protocol error, not a tool error).
pub async fn call_tool<P: Platform>(
    p: &P,
    cfg: &Config,
    name: &str,
    args: &Value,
) -> Option<ToolResult> {
    let defs = tools();
    let def = defs.iter().find(|t| t.name == name)?;
    let outcome = async {
        let a = validate(def, args)?;
        run_tool(p, cfg, name, &a).await
    }
    .await;
    Some(match outcome {
        Ok(Output::Text(t)) => ToolResult {
            text: t,
            is_error: false,
        },
        Ok(Output::Json(v)) => ToolResult {
            text: serde_json::to_string_pretty(&v).unwrap_or_default(),
            is_error: false,
        },
        Err(e) => tool_error(name, &e),
    })
}

fn tool_result_json(r: &ToolResult) -> Value {
    let mut m = Map::new();
    m.insert(
        "content".into(),
        json!([{ "type": "text", "text": r.text }]),
    );
    if r.is_error {
        m.insert("isError".into(), json!(true));
    }
    Value::Object(m)
}

// ---------------------------------------------------------------------------
// JSON-RPC and era handling
// ---------------------------------------------------------------------------

/// A JSON-RPC error response with the HTTP status the transport requires.
pub fn rpc_error(id: &Value, code: i64, message: &str, status: u16, data: Option<Value>) -> Resp {
    let mut error = Map::new();
    error.insert("code".into(), json!(code));
    error.insert("message".into(), json!(message));
    if let Some(d) = data {
        error.insert("data".into(), d);
    }
    Resp::json(
        status,
        &json!({ "jsonrpc": "2.0", "id": id, "error": Value::Object(error) }),
    )
}

fn server_info() -> Value {
    json!({ "name": SERVER_NAME, "title": SERVER_TITLE, "version": SERVER_VERSION })
}

fn is_json_content_type(ct: Option<&str>) -> bool {
    ct.map(|c| {
        c.split(';')
            .next()
            .unwrap_or("")
            .trim()
            .eq_ignore_ascii_case("application/json")
    })
    .unwrap_or(false)
}

fn obj(v: &Value) -> Option<&Map<String, Value>> {
    v.as_object()
}

fn is_rpc_request(v: &Value) -> bool {
    obj(v).is_some_and(|m| {
        m.get("jsonrpc") == Some(&json!("2.0"))
            && m.get("method").is_some_and(Value::is_string)
            && m.get("id").is_some_and(|i| i.is_string() || i.is_number())
    })
}

fn is_rpc_notification(v: &Value) -> bool {
    obj(v).is_some_and(|m| {
        m.get("jsonrpc") == Some(&json!("2.0"))
            && m.get("method").is_some_and(Value::is_string)
            && !m.contains_key("id")
    })
}

fn is_rpc_response(v: &Value) -> bool {
    obj(v).is_some_and(|m| {
        m.get("jsonrpc") == Some(&json!("2.0"))
            && m.get("id").is_some()
            && (m.contains_key("result") || m.contains_key("error"))
            && !m.contains_key("method")
    })
}

fn meta_of(params: Option<&Value>) -> Option<&Map<String, Value>> {
    params?.get("_meta")?.as_object()
}

fn has_claim(params: Option<&Value>) -> bool {
    meta_of(params).is_some_and(|m| m.contains_key(META_PROTOCOL))
}

fn claim_version(params: Option<&Value>) -> Option<&str> {
    meta_of(params)?.get(META_PROTOCOL)?.as_str()
}

/// `(key, problem)` for the first thing wrong with a per-request envelope.
fn envelope_issue(meta: &Map<String, Value>) -> Option<(&'static str, String)> {
    for key in [META_PROTOCOL, META_CLIENT_CAPS] {
        if !meta.contains_key(key) {
            return Some((key, "missing".into()));
        }
    }
    if !meta[META_PROTOCOL].is_string() {
        return Some((META_PROTOCOL, "expected string".into()));
    }
    if !meta[META_CLIENT_CAPS].is_object() {
        return Some((META_CLIENT_CAPS, "expected object".into()));
    }
    if let Some(info) = meta.get(META_CLIENT_INFO) {
        let ok = info.get("name").is_some_and(Value::is_string)
            && info.get("version").is_some_and(Value::is_string);
        if !ok {
            return Some((META_CLIENT_INFO, "expected { name, version }".into()));
        }
    }
    None
}

fn is_modern_version(v: &str) -> bool {
    v >= MODERN_VERSION
}

enum Route {
    Legacy {
        requested_version: Option<String>,
    },
    Modern {
        revision: Option<String>,
        is_request: bool,
    },
    Reject(Resp),
}

fn reject(id: &Value, code: i64, message: &str, data: Option<Value>) -> Route {
    Route::Reject(rpc_error(id, code, message, 400, data))
}

fn mismatch(id: &Value, header: &str, body: &str) -> Route {
    reject(
        id,
        HEADER_MISMATCH,
        &format!("Bad Request: the request headers and body disagree: {body}"),
        Some(json!({ "mismatch": { "header": header, "body": body } })),
    )
}

fn echo_id(v: &Value) -> Value {
    v.get("id")
        .filter(|i| i.is_string() || i.is_number())
        .cloned()
        .unwrap_or(Value::Null)
}

/// Classify one inbound POST for dual-era serving. Body-primary: a proxy
/// stripping a header must not change the era.
fn classify(req: &Req, body: &Value) -> Route {
    let trim = |s: Option<&str>| s.map(|x| x.trim().to_owned());
    let header_version = trim(req.header("mcp-protocol-version"));
    let header_method = trim(req.header("mcp-method"));
    let header_names_modern = header_version.as_deref().is_some_and(is_modern_version);

    if let Value::Array(items) = body {
        if items.is_empty() {
            return reject(
                &Value::Null,
                INVALID_REQUEST,
                "Bad Request: empty JSON-RPC batch",
                None,
            );
        }
        for el in items {
            if has_claim(el.get("params")) {
                return reject(
                    &Value::Null,
                    INVALID_REQUEST,
                    "Bad Request: JSON-RPC batches may not contain requests for protocol revision 2026-07-28 or later",
                    None,
                );
            }
            if !(is_rpc_request(el) || is_rpc_notification(el) || is_rpc_response(el)) {
                return reject(
                    &Value::Null,
                    INVALID_REQUEST,
                    "Bad Request: JSON-RPC batch contains an invalid message",
                    None,
                );
            }
        }
        return Route::Legacy {
            requested_version: None,
        };
    }
    if is_rpc_response(body) {
        return Route::Legacy {
            requested_version: None,
        };
    }

    let is_request = is_rpc_request(body);
    if !is_request && !is_rpc_notification(body) {
        return reject(
            &Value::Null,
            INVALID_REQUEST,
            "Bad Request: the request body is not a valid JSON-RPC message",
            None,
        );
    }
    let id = echo_id(body);
    let params = body.get("params");
    let method = body.get("method").and_then(Value::as_str).unwrap_or("");

    if !is_request {
        // Notifications.
        if has_claim(params) {
            let Some(claimed) = claim_version(params) else {
                return reject(
                    &id,
                    INVALID_PARAMS,
                    &format!("Invalid _meta envelope for protocol revision {MODERN_VERSION}: {META_PROTOCOL}: expected a protocol version string"),
                    None,
                );
            };
            if let Some(h) = header_version.as_deref() {
                if h != claimed {
                    return mismatch(
                        &id,
                        h,
                        &format!("the notification envelope names protocol version {claimed} but the MCP-Protocol-Version header names {h}"),
                    );
                }
            }
            if is_modern_version(claimed) {
                if let Some(hm) = header_method.as_deref() {
                    if hm != method {
                        return mismatch(
                            &id,
                            hm,
                            &format!("the notification body names method {method} but the Mcp-Method header names {hm}"),
                        );
                    }
                }
            }
            return Route::Modern {
                revision: Some(claimed.to_owned()),
                is_request: false,
            };
        }
        if header_names_modern {
            if let Some(hm) = header_method.as_deref() {
                if hm != method {
                    return mismatch(
                        &id,
                        hm,
                        &format!("the notification body names method {method} but the Mcp-Method header names {hm}"),
                    );
                }
            }
            return Route::Modern {
                revision: header_version,
                is_request: false,
            };
        }
        return Route::Legacy {
            requested_version: header_version,
        };
    }

    // Requests.
    let valid_modern_claim = has_claim(params)
        && claim_version(params).is_some_and(is_modern_version)
        && meta_of(params).is_some_and(|m| envelope_issue(m).is_none());
    if method == "initialize" && !valid_modern_claim {
        if header_names_modern {
            return mismatch(
                &id,
                header_version.as_deref().unwrap_or(""),
                "an initialize request (legacy handshake) was sent with a modern MCP-Protocol-Version header",
            );
        }
        let requested = params
            .and_then(|p| p.get("protocolVersion"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        return Route::Legacy {
            requested_version: requested,
        };
    }

    if has_claim(params) {
        if let Some((key, problem)) = meta_of(params).and_then(envelope_issue) {
            return reject(
                &id,
                INVALID_PARAMS,
                &format!("Invalid _meta envelope for protocol revision {MODERN_VERSION}: {key}: {problem}"),
                Some(json!({ "envelope": { "key": key, "problem": problem } })),
            );
        }
        let claimed = claim_version(params).map(str::to_owned);
        if let (Some(h), Some(c)) = (header_version.as_deref(), claimed.as_deref()) {
            if h != c {
                return mismatch(
                    &id,
                    h,
                    &format!("the body envelope names protocol version {c} but the MCP-Protocol-Version header names {h}"),
                );
            }
        }
        if let Some(hm) = header_method.as_deref() {
            if hm != method {
                return mismatch(
                    &id,
                    hm,
                    &format!("the body names method {method} but the Mcp-Method header names {hm}"),
                );
            }
        }
        return Route::Modern {
            revision: claimed,
            is_request: true,
        };
    }

    if header_names_modern {
        let missing = meta_of(params)
            .map(|m| {
                let mut v: Vec<&str> = [META_PROTOCOL, META_CLIENT_CAPS]
                    .into_iter()
                    .filter(|k| !m.contains_key(*k))
                    .collect();
                if v.is_empty() {
                    v.push(META_PROTOCOL);
                }
                v
            })
            .unwrap_or_else(|| vec!["_meta"]);
        return reject(
            &id,
            INVALID_PARAMS,
            &format!(
                "Invalid params: the MCP-Protocol-Version header names protocol revision {}, but the request is missing the required per-request envelope key(s): {}",
                header_version.as_deref().unwrap_or(""),
                missing.join(", ")
            ),
            Some(json!({ "envelope": { "missing": missing } })),
        );
    }

    Route::Legacy {
        requested_version: header_version,
    }
}

/// Which body field the `Mcp-Name` header must mirror, per method.
fn name_source(method: &str) -> Option<&'static str> {
    match method {
        "tools/call" | "prompts/get" => Some("name"),
        "resources/read" => Some("uri"),
        "tasks/get" | "tasks/update" | "tasks/cancel" => Some("taskId"),
        _ => None,
    }
}

/// `Mcp-Name` values may be sent as a Base64 sentinel `=?base64?<b64>?=`.
fn decode_mcp_param(v: &str) -> Option<String> {
    if let Some(inner) = v
        .strip_prefix("=?base64?")
        .and_then(|r| r.strip_suffix("?="))
    {
        let bytes = b64_decode(inner).ok()?;
        return String::from_utf8(bytes).ok();
    }
    Some(v.to_owned())
}

/// A 400 header-mismatch response.
fn mismatch_resp(id: &Value, header: &str, body: &str) -> Resp {
    match mismatch(id, header, body) {
        Route::Reject(r) => r,
        _ => unreachable!("mismatch always rejects"),
    }
}

/// The presence half of the standard-header rung: the headers a modern
/// request MUST carry and their agreement with the body.
fn validate_standard_headers(req: &Req, body: &Value) -> Option<Resp> {
    let id = echo_id(body);
    let method = body.get("method").and_then(Value::as_str).unwrap_or("");
    if req.header("mcp-protocol-version").is_none() {
        let claimed = claim_version(body.get("params")).unwrap_or("");
        return Some(mismatch_resp(
            &id,
            "(missing)",
            &format!("the body envelope names protocol version {claimed} but the required MCP-Protocol-Version header is absent"),
        ));
    }
    if req.header("mcp-method").is_none() {
        return Some(mismatch_resp(
            &id,
            "(missing)",
            &format!("the body names method {method} but the required Mcp-Method header is absent"),
        ));
    }
    let field = name_source(method)?;
    let body_value = body
        .get("params")
        .and_then(|p| p.get(field))
        .and_then(Value::as_str);
    let Some(header) = req.header("mcp-name").map(str::trim) else {
        return body_value.map(|bv| {
            mismatch_resp(
                &id,
                "(missing)",
                &format!("the body carries params.{field}=\"{bv}\" but the required Mcp-Name header is absent"),
            )
        });
    };
    let Some(decoded) = decode_mcp_param(header) else {
        return Some(mismatch_resp(
            &id,
            header,
            "the Mcp-Name header carries an invalid Base64 sentinel value",
        ));
    };
    match body_value {
        Some(bv) if bv != decoded => Some(mismatch_resp(
            &id,
            header,
            &format!("the body carries params.{field}=\"{bv}\" but the Mcp-Name header names \"{decoded}\""),
        )),
        _ => None,
    }
}

fn complete(mut result: Map<String, Value>, modern: bool) -> Value {
    if modern {
        result.insert("resultType".into(), json!("complete"));
        let meta = result
            .entry("_meta")
            .or_insert_with(|| json!({}))
            .as_object_mut();
        if let Some(m) = meta {
            m.insert(META_SERVER_INFO.into(), server_info());
        }
    }
    Value::Object(result)
}

/// Answer one request in either era. `Err((code, message))` is an in-band
/// JSON-RPC error; the caller decides the HTTP status.
async fn dispatch<P: Platform>(
    p: &P,
    cfg: &Config,
    method: &str,
    params: Option<&Value>,
    modern: bool,
    requested_version: Option<&str>,
) -> Result<Value, (i64, String)> {
    match (method, modern) {
        ("initialize", false) => {
            let version = requested_version
                .filter(|v| LEGACY_VERSIONS.contains(v))
                .unwrap_or(LEGACY_VERSIONS[0]);
            Ok(json!({
                "protocolVersion": version,
                "capabilities": { "tools": { "listChanged": true } },
                "serverInfo": server_info(),
                "instructions": INSTRUCTIONS,
            }))
        }
        ("server/discover", true) => {
            let mut m = Map::new();
            m.insert("ttlMs".into(), json!(0));
            m.insert("cacheScope".into(), json!("private"));
            m.insert("supportedVersions".into(), json!([MODERN_VERSION]));
            m.insert("capabilities".into(), json!({ "tools": {} }));
            m.insert("instructions".into(), json!(INSTRUCTIONS));
            Ok(complete(m, true))
        }
        ("ping", _) => Ok(complete(Map::new(), modern)),
        ("tools/list", _) => {
            let mut m = Map::new();
            if modern {
                m.insert("ttlMs".into(), json!(0));
                m.insert("cacheScope".into(), json!("private"));
            }
            m.insert("tools".into(), Value::Array(tools_list()));
            Ok(complete(m, modern))
        }
        ("tools/call", _) => {
            let name = params
                .and_then(|p| p.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let args = params
                .and_then(|p| p.get("arguments"))
                .cloned()
                .unwrap_or(Value::Null);
            match call_tool(p, cfg, name, &args).await {
                Some(r) => {
                    let Value::Object(m) = tool_result_json(&r) else {
                        unreachable!()
                    };
                    Ok(complete(m, modern))
                }
                None => Err((INVALID_PARAMS, format!("Tool {name} not found"))),
            }
        }
        _ => Err((METHOD_NOT_FOUND, "Method not found".into())),
    }
}

fn ok_resp(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn err_body(id: &Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

async fn serve_legacy_message<P: Platform>(
    p: &P,
    cfg: &Config,
    msg: &Value,
    requested_version: Option<&str>,
) -> Option<Value> {
    if !is_rpc_request(msg) {
        return None; // notifications and posted responses: accepted, no reply
    }
    let id = echo_id(msg);
    let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
    Some(
        match dispatch(p, cfg, method, msg.get("params"), false, requested_version).await {
            Ok(r) => ok_resp(&id, r),
            // Legacy clients read the JSON-RPC error, not the HTTP status;
            // answering 404 would look like the endpoint had vanished.
            Err((code, m)) => err_body(&id, code, &m),
        },
    )
}

/// Handle one POST to the MCP endpoint. Authentication, the Origin check and
/// the OAuth metadata have already been decided by the router.
pub async fn handle_mcp<P: Platform>(p: &P, cfg: &Config, req: &Req) -> Resp {
    if !is_json_content_type(req.header("content-type")) {
        return rpc_error(
            &Value::Null,
            -32000,
            "Unsupported Media Type: Content-Type must be application/json",
            415,
            None,
        );
    }
    let body: Value = match serde_json::from_str(&req.body) {
        Ok(v) => v,
        Err(_) => {
            return rpc_error(
                &Value::Null,
                PARSE_ERROR,
                "Parse error: Invalid JSON",
                400,
                None,
            );
        }
    };

    match classify(req, &body) {
        Route::Reject(r) => r,
        Route::Legacy { requested_version } => {
            if let Value::Array(items) = &body {
                let mut replies = vec![];
                for m in items {
                    if let Some(r) =
                        serve_legacy_message(p, cfg, m, requested_version.as_deref()).await
                    {
                        replies.push(r);
                    }
                }
                if replies.is_empty() {
                    return Resp::empty(202);
                }
                return Resp::json(200, &Value::Array(replies));
            }
            match serve_legacy_message(p, cfg, &body, requested_version.as_deref()).await {
                Some(r) => Resp::json(200, &r),
                None => Resp::empty(202),
            }
        }
        Route::Modern {
            revision,
            is_request,
        } => {
            let id = echo_id(&body);
            let supported = revision.as_deref().is_some_and(|r| r == MODERN_VERSION);
            if !supported {
                let requested = revision.as_deref().unwrap_or("unknown");
                return rpc_error(
                    &id,
                    UNSUPPORTED_VERSION,
                    &format!(
                        "Unsupported protocol version: {requested} (supported: {MODERN_VERSION})"
                    ),
                    400,
                    Some(json!({ "supported": [MODERN_VERSION], "requested": requested })),
                );
            }
            if !is_request {
                return Resp::empty(202); // accepted, nothing to dispatch
            }
            if let Some(rejection) = validate_standard_headers(req, &body) {
                return rejection;
            }
            let method = body.get("method").and_then(Value::as_str).unwrap_or("");
            match dispatch(p, cfg, method, body.get("params"), true, None).await {
                Ok(r) => Resp::json(200, &ok_resp(&id, r)),
                // The ladder maps an unknown method to 404; handler-level
                // errors (an unknown tool, bad params) stay in-band on 200.
                Err((METHOD_NOT_FOUND, m)) => rpc_error(&id, METHOD_NOT_FOUND, &m, 404, None),
                Err((code, m)) => Resp::json(200, &err_body(&id, code, &m)),
            }
        }
    }
}

/// The error answer for an unexpected failure outside a tool call: only
/// [`GitHubError`] messages are written for the caller; anything else is
/// logged in full and answered generically (CodeQL: "information exposure
/// through a stack trace").
pub fn internal_error(id: &Value, e: &Failure) -> Resp {
    match e {
        Failure::GitHub(GitHubError { message, .. }) => {
            rpc_error(id, INTERNAL_ERROR, message, 502, None)
        }
        other => {
            crate::log::error(&format!("unhandled error: {other}"));
            rpc_error(id, INTERNAL_ERROR, "internal error", 500, None)
        }
    }
}
