//! A2A (Agent2Agent) surface: how other agents reach this reviewer.
//!
//! MCP is tool-oriented; A2A is task-oriented. A code review is genuinely a
//! task, and this wraps the same review engine rather than reimplementing it.
//!
//! SYNCHRONOUS, DELIBERATELY. A review that finishes inside the request is
//! returned COMPLETED with its result inline, so there is no storage binding.
//! Streaming and push are advertised as false because they are not
//! implemented: an agent card that overstates is worse than a small one.
//!
//! WIRE FORMAT IS v1.0. A2A 1.0 removed the `kind` discriminator everywhere: a
//! text part is `{ text }`, not `{ kind: 'text', text }`, and the JSON member
//! name is the discriminator.

use crate::auth::authorization_server;
use crate::config::{non_empty, Config};
use crate::error::Failure;
use crate::platform::Platform;
use crate::review::{review_pull_request, ReviewOptions, DEFAULT_MODEL};
use crate::util::uuid_v4;
use regex::Regex;
use serde_json::{json, Map, Value};
use std::sync::OnceLock;
use url::Url;

pub const A2A_PROTOCOL_VERSION: &str = "1.0";

pub const TASK_COMPLETED: &str = "TASK_STATE_COMPLETED";
pub const TASK_FAILED: &str = "TASK_STATE_FAILED";
pub const TASK_REJECTED: &str = "TASK_STATE_REJECTED";

pub const INVALID_PARAMS: i64 = -32602;
pub const METHOD_NOT_FOUND: i64 = -32601;

/// The Agent Card: how an agent discovers what this is and how to talk to it.
///
/// Served unauthenticated, like the OAuth resource metadata beside it: a
/// client cannot authenticate until it has read which scheme to use. `None`
/// when WORKOS_AUTHORIZATION_SERVER is unset: the security scheme names the
/// authorization server, which comes only from configuration.
pub fn agent_card(cfg: &Config, base_url: &str) -> Option<Value> {
    let auth_server = authorization_server(cfg)?;
    let oidc = Url::parse(&auth_server)
        .ok()?
        .join("/.well-known/openid-configuration")
        .ok()?
        .to_string();
    Some(json!({
        "name": "Shamwari for GitHub",
        "description": "Reviews a pull request and reports what is wrong with it. Cannot approve, request changes, or affect merge state: findings are posted as a comment on the commit, which carries no review event.",
        "version": "0.1.0",
        "provider": { "organization": "Nyuchi Africa", "url": "https://nyuchi.com" },
        "protocolVersion": A2A_PROTOCOL_VERSION,
        "url": format!("{base_url}/a2a"),
        // Advertised honestly: neither is implemented, and a client that
        // believes otherwise will wait for events that never arrive.
        "capabilities": {
            "streaming": false,
            "pushNotifications": false,
            "extendedAgentCard": false,
        },
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain", "application/json"],
        // v1.0: the member name is the discriminator, not a `type` field.
        "securitySchemes": {
            "workos": { "openIdConnectSecurityScheme": { "openIdConnectUrl": oidc } }
        },
        "security": [{ "workos": [] }],
        "skills": [{
            "id": "review_pull_request",
            "name": "Review a pull request",
            "description": "Read a pull request's diff and report correctness, security and resource-handling defects, each naming a line the diff adds. Returns no findings when there are none, which is a correct outcome rather than a failure.",
            "tags": ["code-review", "github", "static-analysis"],
            "examples": [
                "Review nyuchi/web-services#18",
                "Check PR 42 in nyuchi/api-gateway for security problems",
            ],
            "inputModes": ["text/plain"],
            "outputModes": ["application/json"],
        }],
    }))
}

fn text_part(text: &str) -> Value {
    json!({ "text": text })
}

fn data_part(data: Value) -> Value {
    json!({ "data": data, "mediaType": "application/json" })
}

fn message(role: &str, parts: Vec<Value>) -> Value {
    json!({ "messageId": uuid_v4(), "role": role, "parts": parts })
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Target {
    pub repo: Option<String>,
    pub number: Option<u64>,
    pub error: Option<String>,
}

fn target_err(msg: &str) -> Target {
    Target {
        error: Some(msg.to_owned()),
        ..Default::default()
    }
}

// Every quantifier is BOUNDED, and the bounds are GitHub's own: an owner is at
// most 39 characters and a repository at most 100. The text arrives in an A2A
// message, so it is input from whoever holds a token, not from us. (The
// `regex` crate is linear-time regardless, so the bounds are belt and braces
// and keep the behaviour identical to the TypeScript version.)
fn hash_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"([A-Za-z0-9._-]{1,39}/[A-Za-z0-9._-]{1,100})#([0-9]{1,10})")
            .expect("static regex")
    })
}

fn loose_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"([A-Za-z0-9._-]{1,39}/[A-Za-z0-9._-]{1,100})[^0-9]{1,32}([0-9]{1,10})")
            .expect("static regex")
    })
}

/// Pull `owner/repo` and a pull request number out of a message.
///
/// Accepts a structured data part first, because an agent that can be precise
/// should not be made to phrase a sentence. Free text is the fallback and is
/// matched strictly: a bare number with no repository is ambiguous and is
/// refused rather than guessed at.
pub fn extract_target(params: &Value) -> Target {
    let parts: Vec<Value> = params
        .get("message")
        .and_then(|m| m.get("parts"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    for part in &parts {
        let Some(data) = part.get("data").filter(|d| d.is_object()) else {
            continue;
        };
        if let Some(repo) = data.get("repo").and_then(Value::as_str) {
            let n = data.get("number").and_then(Value::as_f64);
            return match n {
                Some(n) if n.fract() == 0.0 && n >= 0.0 => Target {
                    repo: Some(repo.to_owned()),
                    number: Some(n as u64),
                    error: None,
                },
                _ => target_err("data part has `repo` but no integer `number`"),
            };
        }
    }

    let joined: String = parts
        .iter()
        .filter_map(|p| p.get("text").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join(" ");
    // Bounded before any matching: a reference needing more than 2KB of
    // preamble is not one, and nothing should scan a multi-megabyte part.
    let text: String = joined.chars().take(2048).collect();
    if text.trim().is_empty() {
        return target_err("message has no text or data part naming a pull request");
    }

    for re in [hash_re(), loose_re()] {
        if let Some(c) = re.captures(&text) {
            if let Ok(n) = c[2].parse::<u64>() {
                return Target {
                    repo: Some(c[1].to_owned()),
                    number: Some(n),
                    error: None,
                };
            }
        }
    }
    target_err(
        "could not find a pull request. Give `owner/repo#number`, or a data part with { repo, number }.",
    )
}

fn now_iso<P: Platform>(p: &P) -> String {
    let ms = p.now_ms();
    let secs = (ms / 1000) as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // civil from days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60,
        ms % 1000
    )
}

fn task<P: Platform>(
    p: &P,
    id: &str,
    context_id: &str,
    state: &str,
    parts: Vec<Value>,
    artifacts: Option<Vec<Value>>,
) -> Value {
    // No `kind` field: A2A 1.0 removed the discriminator from Task.
    let mut t = Map::new();
    t.insert("id".into(), json!(id));
    t.insert("contextId".into(), json!(context_id));
    t.insert(
        "status".into(),
        json!({
            "state": state,
            "message": message("ROLE_AGENT", parts),
            "timestamp": now_iso(p),
        }),
    );
    if let Some(a) = artifacts {
        t.insert("artifacts".into(), Value::Array(a));
    }
    Value::Object(t)
}

fn ok(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn err(id: &Value, code: i64, msg: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": msg } })
}

/// Handle one A2A JSON-RPC message.
///
/// GetTask is deliberately absent rather than stubbed. Every task this server
/// produces is already terminal when SendMessage returns, so there is nothing
/// to poll for, and answering GetTask with a fabricated "not found" would tell
/// a client its task was lost when in fact it was handed back.
pub async fn handle_a2a<P: Platform>(p: &P, cfg: &Config, req: &Value) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(Value::as_str);
    match method {
        Some("SendMessage") => {
            let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
            let context_id = params
                .get("contextId")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(uuid_v4);
            let task_id = uuid_v4();

            let target = extract_target(&params);
            let (Some(repo), Some(number)) = (target.repo, target.number) else {
                // REJECTED, not FAILED: the agent understood the request and
                // declined it, which is different from trying and breaking.
                let msg = target
                    .error
                    .unwrap_or_else(|| "no pull request named".to_owned());
                return ok(
                    &id,
                    task(
                        p,
                        &task_id,
                        &context_id,
                        TASK_REJECTED,
                        vec![text_part(&msg)],
                        None,
                    ),
                );
            };

            let model = params
                .get("model")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .or_else(|| non_empty(&cfg.review_model).map(str::to_owned))
                .unwrap_or_else(|| DEFAULT_MODEL.to_owned());

            let result = review_pull_request(
                p,
                cfg,
                &repo,
                number,
                // A2A callers get a dry run. Posting is the webhook path's
                // job, and an agent asking to see a review is not the same as
                // asking for one to be published under this App's name.
                &ReviewOptions {
                    model: Some(model),
                    post: false,
                    trigger: Some("a2a".into()),
                    ..Default::default()
                },
                None,
            )
            .await;
            match result {
                Ok(r) => {
                    let summary = if r.summary.is_empty() {
                        "Review complete.".to_owned()
                    } else {
                        r.summary.clone()
                    };
                    let artifact = json!({
                        "artifactId": uuid_v4(),
                        "name": format!("review-{}-{number}", repo.replacen('/', "-", 1)),
                        "parts": [data_part(serde_json::to_value(&r).unwrap_or(Value::Null))],
                    });
                    ok(
                        &id,
                        task(
                            p,
                            &task_id,
                            &context_id,
                            TASK_COMPLETED,
                            vec![text_part(&summary)],
                            Some(vec![artifact]),
                        ),
                    )
                }
                Err(e) => {
                    let detail = match &e {
                        Failure::GitHub(g) => g.message.clone(),
                        other => {
                            crate::log::error(&format!("a2a review failed: {other}"));
                            "the review failed; the cause is in the worker log".to_owned()
                        }
                    };
                    ok(
                        &id,
                        task(
                            p,
                            &task_id,
                            &context_id,
                            TASK_FAILED,
                            vec![text_part(&detail)],
                            None,
                        ),
                    )
                }
            }
        }
        other => err(
            &id,
            METHOD_NOT_FOUND,
            &format!(
                "method not supported: {}. This agent implements SendMessage; every task it returns is already terminal, so there is nothing to poll.",
                other.unwrap_or("undefined")
            ),
        ),
    }
}
