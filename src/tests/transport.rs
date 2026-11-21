//! Port of test/transport.test.ts: the Streamable HTTP binding, exercised
//! through the router with real RS256 tokens.
//!
//! The status codes are the point. 2026-07-28 assigns meaning to them (404 for
//! an unknown method, 400 for a header mismatch or unsupported version, 405 for
//! GET/DELETE) and a client uses them to decide whether the server is modern
//! at all. Getting one wrong sends a client down the legacy fallback path,
//! which is exactly the class of failure that cost this worker its first
//! connection attempt.

use super::*;
use crate::error::{Failure, GitHubError};
use crate::mcp::{handle_mcp, internal_error};
use crate::router::{handle, Req, Resp};

const MODERN: &str = "2026-07-28";
const LEGACY: &str = "2025-06-18";
const META: &str = "io.modelcontextprotocol/protocolVersion";

fn cfg() -> Config {
    Config {
        mcp_resource_url: Some(AUDIENCE.into()),
        github_allowed_repos: Some("nyuchi/web-services".into()),
        ..auth_config()
    }
}

fn token() -> String {
    mint_token(json!({ "iss": ISSUER, "aud": AUDIENCE, "org_id": ORG, "role": "platform-team" }))
}

struct R {
    status: u16,
    body: Value,
}

fn req(method: &str, body: Option<&Value>, headers: &[(&str, &str)], with_token: bool) -> Req {
    let mut hs: Vec<(String, String)> = vec![
        ("content-type".into(), "application/json".into()),
        (
            "accept".into(),
            "application/json, text/event-stream".into(),
        ),
    ];
    if with_token {
        hs.push(("authorization".into(), format!("Bearer {}", token())));
    }
    for (k, v) in headers {
        hs.push((k.to_ascii_lowercase(), (*v).to_owned()));
    }
    Req {
        method: method.into(),
        url: "https://github.shamwari.ai/mcp".into(),
        headers: hs,
        body: body.map(Value::to_string).unwrap_or_default(),
    }
}

fn call(body: Value, headers: &[(&str, &str)]) -> R {
    call_with(&Mock::default().with_jwks(), body, headers)
}

fn call_with(p: &Mock, body: Value, headers: &[(&str, &str)]) -> R {
    let out = run(handle(p, &cfg(), req("POST", Some(&body), headers, true)));
    R {
        status: out.resp.status,
        body: parse(&out.resp),
    }
}

fn parse(r: &Resp) -> Value {
    if r.body.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&r.body).unwrap()
    }
}

fn modern(method: &str, params: Value) -> Value {
    let mut p = params;
    p["_meta"] = json!({
        META: MODERN,
        "io.modelcontextprotocol/clientInfo": { "name": "test", "version": "1" },
        "io.modelcontextprotocol/clientCapabilities": {},
    });
    json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": p })
}

fn modern_headers(method: &str) -> Vec<(&'static str, String)> {
    vec![
        ("MCP-Protocol-Version", MODERN.to_owned()),
        ("Mcp-Method", method.to_owned()),
    ]
}

fn mh<'a>(h: &'a [(&'static str, String)]) -> Vec<(&'a str, &'a str)> {
    h.iter().map(|(k, v)| (*k, v.as_str())).collect()
}

fn modern_call(method: &str, params: Value) -> R {
    let h = modern_headers(method);
    call(modern(method, params), &mh(&h))
}

// --- transport-level -----------------------------------------------------------

#[test]
fn get_and_delete_on_the_mcp_endpoint_are_405() {
    // Protocol-level sessions and the standalone GET stream were removed in
    // 2026-07-28.
    for m in ["GET", "DELETE"] {
        let out = run(handle(
            &Mock::default().with_jwks(),
            &cfg(),
            req(m, None, &[], true),
        ));
        assert_eq!(out.resp.status, 405, "{m}");
    }
}

#[test]
fn a_foreign_origin_is_refused_with_403() {
    let h = modern_headers("server/discover");
    let mut hs = mh(&h);
    hs.push(("Origin", "https://evil.example.com"));
    assert_eq!(call(modern("server/discover", json!({})), &hs).status, 403);
}

#[test]
fn the_resources_own_origin_is_allowed() {
    let h = modern_headers("server/discover");
    let mut hs = mh(&h);
    hs.push(("Origin", "https://github.shamwari.ai"));
    assert_eq!(call(modern("server/discover", json!({})), &hs).status, 200);
}

// --- modern era ---------------------------------------------------------------------

#[test]
fn server_discover_returns_supported_versions_capabilities_and_identity() {
    let r = modern_call("server/discover", json!({}));
    assert_eq!(r.status, 200);
    assert_eq!(r.body["result"]["supportedVersions"], json!([MODERN]));
    assert_eq!(r.body["result"]["resultType"], "complete");
    assert!(r.body["result"]["capabilities"]["tools"].is_object());
    let info = &r.body["result"]["_meta"]["io.modelcontextprotocol/serverInfo"];
    assert!(info["name"].is_string());
    assert_eq!(info["title"], "Shamwari for GitHub");
}

#[test]
fn an_unknown_method_is_404_not_200() {
    // The JSON-RPC body is what distinguishes this from a 404 served by a URL
    // that is not an MCP endpoint at all.
    let r = modern_call("nope/nope", json!({}));
    assert_eq!(r.status, 404);
    assert_eq!(r.body["error"]["code"], -32601);
}

#[test]
fn a_missing_mcp_method_header_is_400_with_header_mismatch() {
    let r = call(
        modern("tools/list", json!({})),
        &[("MCP-Protocol-Version", MODERN)],
    );
    assert_eq!(r.status, 400);
    assert_eq!(r.body["error"]["code"], -32020);
}

#[test]
fn a_missing_protocol_version_header_is_400_with_header_mismatch() {
    let r = call(
        modern("tools/list", json!({})),
        &[("Mcp-Method", "tools/list")],
    );
    assert_eq!(r.status, 400);
    assert_eq!(r.body["error"]["code"], -32020);
}

#[test]
fn a_header_that_disagrees_with_the_body_is_400_with_header_mismatch() {
    let r = call(
        modern("tools/list", json!({})),
        &[
            ("MCP-Protocol-Version", MODERN),
            ("Mcp-Method", "tools/call"),
        ],
    );
    assert_eq!(r.status, 400);
    assert_eq!(r.body["error"]["code"], -32020);
}

#[test]
fn tools_call_requires_the_mcp_name_header_to_match_the_tool() {
    let params = json!({ "name": "shamwari_whoami", "arguments": {} });
    let mut h = modern_headers("tools/call");
    let missing = call(modern("tools/call", params.clone()), &mh(&h));
    assert_eq!(missing.status, 400);
    assert_eq!(missing.body["error"]["code"], -32020);

    h.push(("Mcp-Name", "shamwari_get_issue".into()));
    let wrong = call(modern("tools/call", params.clone()), &mh(&h));
    assert_eq!(wrong.status, 400);

    h.pop();
    h.push(("Mcp-Name", "shamwari_whoami".into()));
    let p = Mock::default().with_jwks();
    // whoami needs a configured App; here the point is only that the headers
    // pass and the call is dispatched (it answers in-band with a tool error).
    let r = call_with(&p, modern("tools/call", params), &mh(&h));
    assert_eq!(r.status, 200);
    assert_eq!(r.body["result"]["resultType"], "complete");
    assert_eq!(r.body["result"]["isError"], true);
}

#[test]
fn an_unsupported_version_is_400_with_the_supported_list() {
    let body = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list",
        "params": { "_meta": { META: "1900-01-01", "io.modelcontextprotocol/clientCapabilities": {} } },
    });
    let r = call(
        body,
        &[
            ("MCP-Protocol-Version", "1900-01-01"),
            ("Mcp-Method", "tools/list"),
        ],
    );
    assert_eq!(r.status, 400);
    assert_eq!(r.body["error"]["code"], -32022);
    assert_eq!(r.body["error"]["data"]["supported"], json!([MODERN]));
}

#[test]
fn a_modern_header_without_the_envelope_is_400_invalid_params() {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" });
    let r = call(
        body,
        &[
            ("MCP-Protocol-Version", MODERN),
            ("Mcp-Method", "tools/list"),
        ],
    );
    assert_eq!(r.status, 400);
    assert_eq!(r.body["error"]["code"], -32602);
}

#[test]
fn an_envelope_missing_client_capabilities_is_400_invalid_params() {
    let body = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list",
        "params": { "_meta": { META: MODERN } },
    });
    let r = call(
        body,
        &[
            ("MCP-Protocol-Version", MODERN),
            ("Mcp-Method", "tools/list"),
        ],
    );
    assert_eq!(r.status, 400);
    assert_eq!(r.body["error"]["code"], -32602);
}

#[test]
fn tools_list_works_on_the_modern_path() {
    let r = modern_call("tools/list", json!({}));
    assert_eq!(r.status, 200);
    assert_eq!(r.body["result"]["tools"].as_array().unwrap().len(), 13);
    assert_eq!(r.body["result"]["resultType"], "complete");
}

// --- legacy era ------------------------------------------------------------------------

#[test]
fn initialize_still_answers_with_the_legacy_revision() {
    // The regression that matters: a client that connected before this change
    // must keep connecting after it.
    let r = call(
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": LEGACY, "capabilities": {}, "clientInfo": { "name": "legacy-client", "version": "1" } } }),
        &[],
    );
    assert_eq!(r.status, 200);
    assert_eq!(r.body["result"]["protocolVersion"], LEGACY);
    assert_eq!(
        r.body["result"]["serverInfo"]["name"],
        "shamwari-github-mcp"
    );
    assert!(r.body["result"]["capabilities"]["tools"].is_object());
    assert!(r.body["result"]["instructions"]
        .as_str()
        .unwrap()
        .contains("shamwari_whoami"));
}

#[test]
fn an_unknown_legacy_protocol_version_is_answered_with_the_latest_supported() {
    let r = call(
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "1999-01-01" } }),
        &[],
    );
    assert_eq!(r.body["result"]["protocolVersion"], "2025-11-25");
}

#[test]
fn a_legacy_request_carries_no_headers_and_is_not_version_validated() {
    let r = call(
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
        &[],
    );
    assert_eq!(r.status, 200);
    assert_eq!(r.body["result"]["tools"].as_array().unwrap().len(), 13);
    assert!(r.body["result"].get("resultType").is_none());
}

#[test]
fn an_unknown_method_stays_200_for_a_legacy_client() {
    // Legacy clients read the JSON-RPC error, not the HTTP status; returning
    // 404 to them would look like the endpoint had vanished.
    let r = call(
        json!({ "jsonrpc": "2.0", "id": 3, "method": "nope/nope" }),
        &[],
    );
    assert_eq!(r.status, 200);
    assert_eq!(r.body["error"]["code"], -32601);
}

#[test]
fn a_legacy_notification_is_accepted_with_202_and_no_body() {
    let out = run(handle(
        &Mock::default().with_jwks(),
        &cfg(),
        req(
            "POST",
            Some(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })),
            &[],
            true,
        ),
    ));
    assert_eq!(out.resp.status, 202);
    assert!(out.resp.body.is_empty());
}

#[test]
fn a_legacy_batch_is_answered_as_a_batch() {
    let r = call(
        json!([{ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }, { "jsonrpc": "2.0", "method": "notifications/initialized" }]),
        &[],
    );
    assert_eq!(r.status, 200);
    assert_eq!(r.body.as_array().unwrap().len(), 1);
}

#[test]
fn a_batch_may_not_carry_a_modern_envelope() {
    let r = call(json!([modern("tools/list", json!({}))]), &[]);
    assert_eq!(r.status, 400);
    assert_eq!(r.body["error"]["code"], -32600);
}

#[test]
fn a_non_json_content_type_is_415_and_invalid_json_is_400() {
    let mut rq = req("POST", Some(&json!({})), &[], true);
    rq.headers.retain(|(k, _)| k != "content-type");
    rq.headers
        .push(("content-type".into(), "text/plain".into()));
    let out = run(handle(&Mock::default().with_jwks(), &cfg(), rq));
    assert_eq!(out.resp.status, 415);

    let mut rq = req("POST", None, &[], true);
    rq.body = "{not json".into();
    let out = run(handle(&Mock::default().with_jwks(), &cfg(), rq));
    assert_eq!(out.resp.status, 400);
    assert_eq!(parse(&out.resp)["error"]["code"], -32700);
}

#[test]
fn a_body_that_is_not_json_rpc_is_400_invalid_request() {
    let r = call(json!({ "hello": "world" }), &[]);
    assert_eq!(r.status, 400);
    assert_eq!(r.body["error"]["code"], -32600);
}

// --- auth still gates everything ---------------------------------------------------------

#[test]
fn no_bearer_token_is_still_401_whatever_the_era() {
    let h = modern_headers("tools/list");
    let hs = mh(&h);
    let out = run(handle(
        &Mock::default().with_jwks(),
        &cfg(),
        req("POST", Some(&modern("tools/list", json!({}))), &hs, false),
    ));
    assert_eq!(out.resp.status, 401);
    assert!(out
        .resp
        .header("WWW-Authenticate")
        .unwrap()
        .starts_with("Bearer resource_metadata="));
    assert!(!out
        .resp
        .header("WWW-Authenticate")
        .unwrap()
        .contains("invalid_token"));
    let legacy = run(handle(
        &Mock::default().with_jwks(),
        &cfg(),
        req(
            "POST",
            Some(&json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" })),
            &[],
            false,
        ),
    ));
    assert_eq!(legacy.resp.status, 401);
}

#[test]
fn a_rejected_token_is_401_invalid_token_naming_the_gate_but_not_the_token() {
    let bad = mint_token(
        json!({ "iss": ISSUER, "aud": AUDIENCE, "org_id": "org_someone_else", "role": "platform-team" }),
    );
    let mut rq = req(
        "POST",
        Some(&json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" })),
        &[],
        false,
    );
    rq.headers
        .push(("authorization".into(), format!("Bearer {bad}")));
    let out = run(handle(&Mock::default().with_jwks(), &cfg(), rq));
    assert_eq!(out.resp.status, 401);
    let challenge = out.resp.header("WWW-Authenticate").unwrap();
    assert!(challenge.contains(r#"error="invalid_token""#));
    assert!(challenge.contains("organization not permitted"));
    assert!(!challenge.contains(&bad));
    assert!(!out.resp.body.contains("org_someone_else"));
}

#[test]
fn the_a2a_endpoint_is_behind_the_same_gate() {
    let mut rq = req("POST", Some(&json!({})), &[], false);
    rq.url = "https://github.shamwari.ai/a2a".into();
    assert_eq!(
        run(handle(&Mock::default().with_jwks(), &cfg(), rq))
            .resp
            .status,
        401
    );
}

#[test]
fn health_the_agent_card_and_unknown_paths() {
    let get = |path: &str| {
        run(handle(
            &Mock::default(),
            &Config {
                workos_authorization_server: Some("https://identity.example.test".into()),
                ..cfg()
            },
            Req {
                method: "GET".into(),
                url: format!("https://github.shamwari.ai{path}"),
                ..Default::default()
            },
        ))
        .resp
    };
    assert_eq!(get("/health").status, 200);
    assert_eq!(get("/.well-known/agent-card.json").status, 200);
    assert_eq!(get("/.well-known/agent.json").status, 200);
    assert_eq!(get("/nope").status, 404);
    let preflight = run(handle(
        &Mock::default(),
        &cfg(),
        Req {
            method: "OPTIONS".into(),
            url: "https://github.shamwari.ai/mcp".into(),
            ..Default::default()
        },
    ))
    .resp;
    assert_eq!(preflight.status, 204);
    assert!(preflight
        .header("Access-Control-Allow-Headers")
        .unwrap()
        .contains("Mcp-Method"));
}

// --- error responses do not leak internals ------------------------------------------------

#[test]
fn an_unexpected_error_is_logged_not_returned() {
    // CodeQL: "information exposure through a stack trace". An arbitrary
    // failure's message can carry internal paths or upstream detail; only
    // GitHub errors are written here deliberately for the caller.
    let res = internal_error(
        &json!(1),
        &Failure::Internal("ENOENT: /srv/secret/config.json line 42".into()),
    );
    assert_eq!(res.status, 500);
    let body = parse(&res);
    assert_eq!(body["error"]["message"], "internal error");
    for leak in ["ENOENT", "secret", "config.json"] {
        assert!(!res.body.contains(leak));
    }
}

#[test]
fn a_github_error_message_is_returned_because_it_is_written_for_the_caller() {
    let res = internal_error(
        &json!(1),
        &Failure::GitHub(GitHubError::new("repo not allowlisted", 403)),
    );
    assert_eq!(res.status, 502);
    assert_eq!(parse(&res)["error"]["message"], "repo not allowlisted");
}

// --- the tools, through tools/call (the TypeScript `mcp-helper` rpc) -----------------------

fn legacy_rpc(body: Value, cfg: &Config, p: &Mock) -> Value {
    let rq = Req {
        method: "POST".into(),
        url: "https://github.shamwari.ai/mcp".into(),
        headers: vec![("content-type".into(), "application/json".into())],
        body: json!({ "jsonrpc": "2.0", "id": 1 })
            .as_object()
            .unwrap()
            .iter()
            .chain(body.as_object().unwrap())
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<serde_json::Map<_, _>>()
            .into_iter()
            .fold(json!({}), |mut a, (k, v)| {
                a[k] = v;
                a
            })
            .to_string(),
    };
    parse(&run(handle_mcp(p, cfg, &rq)))
}

#[test]
fn a_bad_argument_reaches_the_caller_through_tools_call_not_a_stub() {
    let res = legacy_rpc(
        json!({ "method": "tools/call", "params": { "name": "shamwari_get_pull_request", "arguments": { "repo": "nyuchi/web-services", "number": "twelve" } } }),
        &cfg(),
        &Mock::default(),
    );
    assert_eq!(res["result"]["isError"], true);
    assert!(res["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("number"));
}

#[test]
fn a_missing_required_argument_names_the_field() {
    let res = legacy_rpc(
        json!({ "method": "tools/call", "params": { "name": "shamwari_comment", "arguments": { "repo": "nyuchi/web-services", "number": 1 } } }),
        &cfg(),
        &Mock::default(),
    );
    assert_eq!(res["result"]["isError"], true);
    assert!(res["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("body"));
}

#[test]
fn an_unknown_tool_is_an_invalid_params_error() {
    let res = legacy_rpc(
        json!({ "method": "tools/call", "params": { "name": "shamwari_merge", "arguments": {} } }),
        &cfg(),
        &Mock::default(),
    );
    assert_eq!(res["error"]["code"], -32602);
}

#[test]
fn a_repo_outside_the_allowlist_is_refused_through_tools_call_before_any_request() {
    let p = Mock::default();
    let res = legacy_rpc(
        json!({ "method": "tools/call", "params": { "name": "shamwari_get_issue", "arguments": { "repo": "evil/repo", "number": 1 } } }),
        &cfg(),
        &p,
    );
    assert_eq!(res["result"]["isError"], true);
    assert!(res["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("not allowlisted"));
    assert!(
        p.requests.borrow().is_empty(),
        "a repo outside the allowlist must never reach GitHub"
    );
}

#[test]
fn defaults_are_applied_and_the_list_query_is_what_github_expects() {
    crate::github::clear_caches();
    let p = Mock::default().route(|r| {
        let u = r.url.as_str();
        let ok = |b: Value| {
            Some(HttpResponse {
                status: 200,
                body: b.to_string(),
            })
        };
        if u.ends_with("/installation") {
            return ok(json!({ "id": 1 }));
        }
        if u.ends_with("/access_tokens") {
            return ok(json!({ "token": "t", "expires_at": "2027-01-01T00:00:00Z" }));
        }
        if u.contains("/pulls?") {
            return ok(
                json!([{ "number": 1, "title": "a", "user": { "login": "x" } }, { "number": 2 }]),
            );
        }
        None
    });
    let c = Config {
        github_app_id: Some("1".into()),
        github_app_private_key: Some(pem("PRIVATE KEY", &pkcs8_der(test_key()))),
        ..cfg()
    };
    let res = legacy_rpc(
        json!({ "method": "tools/call", "params": { "name": "shamwari_list_pull_requests", "arguments": { "repo": "nyuchi/web-services", "limit": 1 } } }),
        &c,
        &p,
    );
    let text = res["result"]["content"][0]["text"].as_str().unwrap();
    let out: Value = serde_json::from_str(text).unwrap();
    assert_eq!(out["count"], 1);
    assert_eq!(out["has_more"], true);
    assert_eq!(out["next_page"], 2);
    assert_eq!(out["items"][0]["author"], "x");
    let list = p
        .requests
        .borrow()
        .iter()
        .find(|q| q.url.contains("/pulls?"))
        .cloned()
        .unwrap();
    assert!(
        list.url
            .ends_with("/pulls?state=open&per_page=2&page=1&sort=updated&direction=desc"),
        "{}",
        list.url
    );
}

#[test]
fn an_update_with_nothing_to_change_is_an_argument_error() {
    let res = legacy_rpc(
        json!({ "method": "tools/call", "params": { "name": "shamwari_update_issue", "arguments": { "repo": "nyuchi/web-services", "number": 3 } } }),
        &cfg(),
        &Mock::default(),
    );
    assert_eq!(res["result"]["isError"], true);
    assert!(res["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("nothing to update"));
}

#[test]
fn a_create_review_with_approve_is_rejected_by_the_schema_before_it_reaches_github() {
    let p = Mock::default();
    let res = legacy_rpc(
        json!({ "method": "tools/call", "params": { "name": "shamwari_create_review", "arguments": { "repo": "nyuchi/web-services", "number": 1, "event": "APPROVE", "body": "lgtm" } } }),
        &cfg(),
        &p,
    );
    assert_eq!(res["result"]["isError"], true);
    assert!(p.requests.borrow().is_empty());
}

#[test]
fn the_input_schemas_follow_the_zod_ones_required_fields_and_defaults() {
    let tools = crate::mcp::tools_list();
    let t = |n: &str| tools.iter().find(|t| t["name"] == n).unwrap().clone();
    let list = t("shamwari_list_pull_requests");
    assert_eq!(list["inputSchema"]["required"], json!(["repo"]));
    assert_eq!(
        list["inputSchema"]["properties"]["state"]["default"],
        "open"
    );
    assert_eq!(list["inputSchema"]["properties"]["limit"]["default"], 20);
    assert_eq!(list["inputSchema"]["properties"]["limit"]["maximum"], 100);
    assert_eq!(
        t("shamwari_create_pull_request")["inputSchema"]["properties"]["draft"]["default"],
        true
    );
    assert_eq!(t("shamwari_whoami")["inputSchema"]["required"], json!([]));
    assert_eq!(
        t("shamwari_create_review")["inputSchema"]["properties"]["event"]["enum"],
        json!(["COMMENT", "REQUEST_CHANGES"])
    );
}
