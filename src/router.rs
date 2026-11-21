//! HTTP routing, in front of the MCP, A2A and webhook handlers.
//!
//!   POST /mcp                                    MCP Streamable HTTP (JSON-RPC 2.0)
//!   POST /a2a                                    A2A (JSON-RPC 2.0)
//!   POST /webhook                                GitHub webhook (HMAC-signed)
//!   GET  /.well-known/oauth-protected-resource   OAuth resource metadata
//!   GET  /.well-known/agent-card.json            A2A agent card
//!   GET  /health                                 liveness probe (no auth)
//!   GET  /github-app/{new,created,installed}     App setup pages
//!
//! Pure over [`Req`] / [`Resp`] and the [`Platform`] trait, so the whole
//! request path runs under `cargo test`. The Workers glue only converts
//! between the runtime's request and these types.

use crate::a2a::{agent_card, handle_a2a};
use crate::auth::{
    caller_identity, protected_resource_metadata, resource_url_for, verify_workos_token,
    AUTHORIZATION_SERVER_MISSING,
};
use crate::config::Config;
use crate::mcp::{handle_mcp, PARSE_ERROR};
use crate::origin::origin_allowed;
use crate::platform::Platform;
use crate::setup::{app_created, app_installed, app_new, HtmlResponse};
use crate::webhook::{handle_webhook, Decision};
use serde_json::{json, Value};
use url::Url;

#[derive(Debug, Clone, Default)]
pub struct Req {
    pub method: String,
    pub url: String,
    /// Header names are stored lower-cased.
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Req {
    pub fn header(&self, name: &str) -> Option<&str> {
        let n = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| *k == n)
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Debug, Clone, Default)]
pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Resp {
    pub fn json(status: u16, body: &Value) -> Resp {
        Resp {
            status,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: body.to_string(),
        }
    }

    pub fn empty(status: u16) -> Resp {
        Resp {
            status,
            headers: vec![],
            body: String::new(),
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn set(mut self, name: &str, value: &str) -> Resp {
        self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }
}

const CORS: [(&str, &str); 4] = [
    ("Access-Control-Allow-Origin", "*"),
    ("Access-Control-Allow-Methods", "POST, GET, OPTIONS"),
    // Mcp-Method and Mcp-Name are the 2026-07-28 mirrored headers; without
    // them listed here a browser client's preflight fails before the request
    // this server is meant to validate ever arrives.
    (
        "Access-Control-Allow-Headers",
        "Authorization, Content-Type, Mcp-Session-Id, Mcp-Protocol-Version, MCP-Protocol-Version, Mcp-Method, Mcp-Name",
    ),
    ("Access-Control-Expose-Headers", "WWW-Authenticate"),
];

fn cors(mut r: Resp) -> Resp {
    for (k, v) in CORS {
        r = r.set(k, v);
    }
    r
}

fn json_cors(status: u16, body: &Value) -> Resp {
    cors(Resp::json(status, body))
}

fn html(r: HtmlResponse) -> Resp {
    Resp {
        status: r.status,
        headers: r
            .headers
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect(),
        body: r.body,
    }
}

/// 401 pointing MCP clients at the OAuth resource metadata (WorkOS).
fn unauthorized(resource: &str, message: &str, invalid_token: bool) -> Resp {
    let meta_url = Url::parse(resource)
        .and_then(|u| u.join("/.well-known/oauth-protected-resource"))
        .map(|u| u.to_string())
        .unwrap_or_default();
    // RFC 6750: a presented-but-rejected token is `invalid_token`, and the
    // description names the gate that refused it (never the token or its
    // claims) so a client-side "authorization failed" can be diagnosed.
    let challenge = if invalid_token {
        let desc: String = message
            .chars()
            .filter(|c| *c != '"' && *c != '\\')
            .collect();
        format!(
            "Bearer resource_metadata=\"{meta_url}\", error=\"invalid_token\", error_description=\"{desc}\""
        )
    } else {
        format!("Bearer resource_metadata=\"{meta_url}\"")
    };
    cors(
        Resp::json(
            401,
            &json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32001, "message": message } }),
        )
        .set("WWW-Authenticate", &challenge),
    )
}

/// What the router decided, and any work to run after answering.
pub struct Outcome {
    pub resp: Resp,
    /// A webhook review to run after the response (`ctx.waitUntil`).
    pub job: Option<Decision>,
}

fn done(resp: Resp) -> Outcome {
    Outcome { resp, job: None }
}

pub async fn handle<P: Platform>(p: &P, cfg: &Config, req: Req) -> Outcome {
    let url = match Url::parse(&req.url) {
        Ok(u) => u,
        Err(_) => return done(json_cors(400, &json!({ "error": "bad request url" }))),
    };
    let path = url.path();

    if req.method == "OPTIONS" {
        return done(cors(Resp::empty(204)));
    }

    if path == "/health" {
        return done(json_cors(
            200,
            &json!({ "status": "ok", "server": "shamwari-github-mcp" }),
        ));
    }

    // GitHub webhook ingest. NOT behind the WorkOS bearer check: GitHub does
    // not carry one. It authenticates with its own HMAC signature over the raw
    // body, verified before anything else is read from the request.
    if path == "/webhook" {
        let o = handle_webhook(
            cfg,
            &req.method,
            &req.body,
            req.header("x-hub-signature-256"),
            req.header("x-github-event"),
        );
        return Outcome {
            resp: Resp::json(o.status, &o.body),
            job: o.job,
        };
    }

    // A2A Agent Card: public, for the same reason the OAuth metadata is: a
    // client cannot authenticate until it has read which scheme to use. Both
    // names are served (`agent-card.json` is 1.0, `agent.json` the one before).
    if path == "/.well-known/agent-card.json" || path == "/.well-known/agent.json" {
        let origin = url.origin().ascii_serialization();
        // Fail closed: the authorization server comes only from configuration.
        return done(match agent_card(cfg, &origin) {
            Some(card) => json_cors(200, &card),
            None => json_cors(503, &json!({ "error": AUTHORIZATION_SERVER_MISSING })),
        });
    }

    // OAuth 2.0 Protected Resource Metadata: public, so clients can discover
    // WorkOS as the authorization server. Served at the root form and at the
    // path-suffixed form RFC 9728 derives from the resource URL.
    let resource = resource_url_for(&req.url, cfg);
    if path == "/.well-known/oauth-protected-resource"
        || path == "/.well-known/oauth-protected-resource/mcp"
    {
        return done(match protected_resource_metadata(cfg, &resource) {
            Some(meta) => json_cors(200, &meta),
            None => json_cors(503, &json!({ "error": AUTHORIZATION_SERVER_MISSING })),
        });
    }

    // GitHub App setup pages. Public: GitHub sends a browser here, and none
    // holds or exchanges anything.
    if req.method == "GET" {
        match path {
            "/github-app/created" => {
                let code = url
                    .query_pairs()
                    .find(|(k, _)| k == "code")
                    .map(|(_, v)| v.into_owned());
                return done(html(app_created(code.as_deref())));
            }
            "/github-app/new" => return done(html(app_new())),
            "/github-app/installed" => return done(html(app_installed())),
            _ => {}
        }
    }

    let is_a2a = path == "/a2a";
    if path != "/mcp" && !is_a2a {
        return done(json_cors(404, &json!({ "error": "not found" })));
    }

    // Protocol-level sessions and the standalone GET stream were removed in
    // 2026-07-28: a server that only speaks this revision answers GET and
    // DELETE on the MCP endpoint with 405.
    if req.method == "GET" || req.method == "DELETE" {
        return done(json_cors(405, &json!({ "error": "method not allowed" })));
    }

    // Servers MUST validate Origin to prevent DNS rebinding. Absent Origin is
    // allowed: non-browser MCP clients do not send one.
    if !origin_allowed(req.header("origin"), &resource) {
        return done(json_cors(403, &json!({ "error": "forbidden origin" })));
    }

    // WorkOS Connect: verify the caller's access token on every request.
    let token = req
        .header("authorization")
        .and_then(|h| h.strip_prefix("Bearer "))
        .unwrap_or("");
    if token.is_empty() {
        // Logged because Cloudflare redacts the Authorization header, so the
        // request log alone cannot distinguish "client sent no token" from
        // "token was rejected": those have completely different causes.
        crate::log::warn("auth rejected: no bearer token presented");
        return done(unauthorized(&resource, "missing bearer token", false));
    }
    match verify_workos_token(p, token, cfg, Some(&resource)).await {
        Ok(claims) => {
            // Logged on every accepted call, because "an agent did this" and
            // "an agent did this FOR someone" are different answers to the
            // question asked after something goes wrong.
            let who = caller_identity(&claims);
            crate::log::info(&format!(
                "authorized {} {}",
                who.kind,
                json!({
                    "subject": who.subject,
                    "on_behalf_of": who.on_behalf_of,
                    "org": who.org,
                })
            ));
        }
        Err(e) => {
            // The response stays generic; the log names the gate and what the
            // token carried. Never log the token itself.
            crate::log::warn(&format!(
                "auth rejected: {}{}",
                e.message,
                e.detail
                    .as_ref()
                    .map(|d| format!(" — {d}"))
                    .unwrap_or_default()
            ));
            return done(unauthorized(&resource, &e.message, true));
        }
    }

    if req.method != "POST" {
        return done(json_cors(405, &json!({ "error": "method not allowed" })));
    }

    // A2A shares this endpoint's authentication and nothing else. It is not
    // MCP: no protocol-version headers, no era detection, no batch.
    if is_a2a {
        let payload: Value = match serde_json::from_str(&req.body) {
            Ok(v) => v,
            Err(_) => {
                return done(json_cors(
                    400,
                    &json!({ "jsonrpc": "2.0", "id": null, "error": { "code": PARSE_ERROR, "message": "parse error" } }),
                ));
            }
        };
        let response = handle_a2a(p, cfg, &payload).await;
        return done(json_cors(200, &response));
    }

    done(cors(handle_mcp(p, cfg, &req).await))
}
