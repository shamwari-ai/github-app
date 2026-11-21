//! Port of test/a2a.test.ts: the A2A surface.
//!
//! Weighted towards the wire format, because A2A 1.0 removed the `kind`
//! discriminator everywhere and the old shape still looks plausible. A part
//! written as `{ kind: 'text', text }` serialises fine, reads fine, and no
//! current client parses it: a defect invisible until an actual agent tries to
//! talk to us.

use super::*;
use crate::a2a::*;
use std::time::Instant;

fn cfg() -> Config {
    // Test fixture: the issuer is configuration, never a default in code.
    Config {
        workos_authorization_server: Some("https://identity.example.test".into()),
        ..Default::default()
    }
}

fn send(parts: Value, over: Value) -> Value {
    let mut params =
        json!({ "message": { "messageId": "m1", "role": "ROLE_USER", "parts": parts } });
    for (k, v) in over.as_object().unwrap() {
        params[k] = v.clone();
    }
    json!({ "jsonrpc": "2.0", "id": 1, "method": "SendMessage", "params": params })
}

fn to(parts: Value) -> Value {
    json!({ "message": { "parts": parts } })
}

// --- the card ----------------------------------------------------------------

#[test]
fn the_card_declares_the_1_0_protocol_version() {
    let c = agent_card(&cfg(), "https://github.shamwari.ai").unwrap();
    assert_eq!(c["protocolVersion"], A2A_PROTOCOL_VERSION);
    assert_eq!(c["url"], "https://github.shamwari.ai/a2a");
}

#[test]
fn the_card_advertises_only_what_is_implemented() {
    // An agent card that overstates is worse than a small one: a client
    // believes it and waits for events that never come.
    let c = agent_card(&cfg(), "https://github.shamwari.ai").unwrap();
    assert_eq!(c["capabilities"]["streaming"], false);
    assert_eq!(c["capabilities"]["pushNotifications"], false);
    assert_eq!(c["capabilities"]["extendedAgentCard"], false);
}

#[test]
fn the_security_scheme_uses_the_v1_0_member_name_discriminator() {
    // Not { type: 'openIdConnect' }: 1.0 identifies the scheme by which member
    // is present, exactly as it does for parts.
    let c = agent_card(&cfg(), "https://x.test").unwrap();
    let scheme = &c["securitySchemes"]["workos"]["openIdConnectSecurityScheme"];
    assert!(scheme.is_object());
    assert!(scheme["openIdConnectUrl"]
        .as_str()
        .unwrap()
        .ends_with("identity.example.test/.well-known/openid-configuration"));
}

#[test]
fn the_card_fails_closed_when_workos_authorization_server_is_unset() {
    assert!(agent_card(&Config::default(), "https://x.test").is_none());
}

#[test]
fn the_card_fails_closed_when_the_authorization_server_is_not_an_https_origin() {
    for bad in [
        "http://identity.example.test",
        "https://user:pass@identity.example.test",
    ] {
        let c = Config {
            workos_authorization_server: Some(bad.into()),
            ..Default::default()
        };
        assert!(agent_card(&c, "https://x.test").is_none(), "{bad}");
    }
}

#[test]
fn the_card_builds_its_openid_connect_url_on_the_parsed_origin() {
    let c = Config {
        workos_authorization_server: Some("HTTPS://Identity.Example.Test/some/path".into()),
        ..Default::default()
    };
    let card = agent_card(&c, "https://x.test").unwrap();
    assert_eq!(
        card["securitySchemes"]["workos"]["openIdConnectSecurityScheme"]["openIdConnectUrl"],
        "https://identity.example.test/.well-known/openid-configuration"
    );
}

#[test]
fn the_card_says_plainly_that_it_cannot_approve() {
    let c = agent_card(&cfg(), "https://x.test").unwrap();
    assert!(c["description"]
        .as_str()
        .unwrap()
        .to_lowercase()
        .contains("cannot approve"));
}

// --- finding the pull request --------------------------------------------------

#[test]
fn a_data_part_is_read_in_preference_to_prose() {
    let t = extract_target(&to(
        json!([{ "data": { "repo": "nyuchi/web-services", "number": 18 } }]),
    ));
    assert_eq!(
        (t.repo.as_deref(), t.number),
        (Some("nyuchi/web-services"), Some(18))
    );
}

#[test]
fn owner_repo_hash_number_is_understood() {
    let t = extract_target(&to(
        json!([{ "text": "please review nyuchi/web-services#18" }]),
    ));
    assert_eq!(
        (t.repo.as_deref(), t.number),
        (Some("nyuchi/web-services"), Some(18))
    );
}

#[test]
fn a_looser_sentence_still_resolves() {
    let t = extract_target(&to(
        json!([{ "text": "take a look at nyuchi/api-gateway PR 95" }]),
    ));
    assert_eq!(
        (t.repo.as_deref(), t.number),
        (Some("nyuchi/api-gateway"), Some(95))
    );
}

#[test]
fn a_bare_number_is_refused_rather_than_guessed_at() {
    // Guessing the repository would review the wrong thing confidently, which
    // is the failure mode this whole agent is built to avoid.
    let t = extract_target(&to(json!([{ "text": "review PR 18" }])));
    assert!(t.error.is_some());
    assert!(t.repo.is_none());
}

#[test]
fn a_data_part_naming_a_repo_but_no_number_is_an_error_not_a_guess() {
    let t = extract_target(&to(json!([{ "data": { "repo": "nyuchi/web-services" } }])));
    assert!(t.error.unwrap().contains("integer `number`"));
}

#[test]
fn an_empty_message_is_refused() {
    assert!(extract_target(&to(json!([]))).error.is_some());
    assert!(extract_target(&json!({})).error.is_some());
}

// --- task shape ----------------------------------------------------------------

#[test]
fn an_unusable_request_is_rejected_not_failed() {
    // Different facts: rejected means understood and declined; failed means
    // tried and broke. A client retries one and not the other.
    let res = run(handle_a2a(
        &Mock::default(),
        &cfg(),
        &send(json!([{ "text": "review something" }]), json!({})),
    ));
    assert_eq!(res["result"]["status"]["state"], TASK_REJECTED);
    assert!(res["result"]["id"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(res["result"]["contextId"]
        .as_str()
        .is_some_and(|s| !s.is_empty()));
}

#[test]
fn a_task_carries_no_kind_field_because_1_0_removed_the_discriminator() {
    let res = run(handle_a2a(
        &Mock::default(),
        &cfg(),
        &send(json!([{ "text": "nope" }]), json!({})),
    ));
    assert!(res["result"].get("kind").is_none());
}

#[test]
fn a_text_part_is_text_not_kind_and_text() {
    let res = run(handle_a2a(
        &Mock::default(),
        &cfg(),
        &send(json!([{ "text": "nope" }]), json!({})),
    ));
    let part = &res["result"]["status"]["message"]["parts"][0];
    assert!(part.get("text").is_some());
    assert!(part.get("kind").is_none());
}

#[test]
fn a_caller_supplied_context_id_is_preserved_across_the_exchange() {
    let res = run(handle_a2a(
        &Mock::default(),
        &cfg(),
        &send(
            json!([{ "text": "nope" }]),
            json!({ "contextId": "ctx-123" }),
        ),
    ));
    assert_eq!(res["result"]["contextId"], "ctx-123");
}

#[test]
fn a_review_that_fails_becomes_a_failed_task_not_a_transport_error() {
    // No AI binding, so the review fails. A2A expresses that as task state; a
    // JSON-RPC error would tell the client the protocol broke.
    let c = Config {
        review_enabled: Some("true".into()),
        ..Default::default()
    };
    let res = run(handle_a2a(
        &Mock::default(),
        &c,
        &send(
            json!([{ "text": "review nyuchi/web-services#18" }]),
            json!({}),
        ),
    ));
    assert_eq!(res["result"]["status"]["state"], TASK_FAILED);
}

#[test]
fn a_completed_review_carries_its_result_inline_as_a_data_part() {
    crate::github::clear_caches();
    let p = Mock::default()
        .route(|r| {
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
            if u.ends_with("/pulls/18") {
                return Some(HttpResponse {
                    status: 200,
                    body: "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1,1 +1,2 @@\n a\n+b\n".into(),
                });
            }
            None
        })
        .with_ai(|_, _, _| Ok(json!({ "response": { "summary": "clean", "findings": [] } })));
    let c = Config {
        github_app_id: Some("1".into()),
        github_app_private_key: Some(pem("PRIVATE KEY", &pkcs8_der(test_key()))),
        github_allowed_repos: Some("nyuchi/web-services".into()),
        review_enabled: Some("true".into()),
        ..Default::default()
    };
    let res = run(handle_a2a(
        &p,
        &c,
        &send(
            json!([{ "text": "review nyuchi/web-services#18" }]),
            json!({}),
        ),
    ));
    assert_eq!(res["result"]["status"]["state"], TASK_COMPLETED);
    let part = &res["result"]["artifacts"][0]["parts"][0];
    assert_eq!(part["mediaType"], "application/json");
    assert_eq!(part["data"]["summary"], "clean");
    assert_eq!(part["data"]["posted"], false, "A2A callers get a dry run");
    assert_eq!(p.count("/comments"), 0);
}

#[test]
fn an_unknown_method_is_a_json_rpc_error_that_says_what_is_served() {
    let res = run(handle_a2a(
        &Mock::default(),
        &cfg(),
        &json!({ "jsonrpc": "2.0", "id": 1, "method": "GetTask", "params": {} }),
    ));
    assert_eq!(res["error"]["code"], -32601);
    // GetTask is absent on purpose, and the message has to say why rather than
    // let a client conclude its task was lost.
    let m = res["error"]["message"].as_str().unwrap();
    assert!(m.contains("terminal") || m.contains("SendMessage"));
}

// --- the extractor runs on input from whoever holds a token ----------------------
//
// CodeQL flagged both of these in the TypeScript as polynomial backtracking.
// The `regex` crate is linear-time by construction, but the bounds and the
// 2KB cap are kept so the behaviour is identical, and these pin it.

#[test]
fn a_pathological_input_does_not_hang_the_extractor() {
    // 100k dashes with no slash: the shape that makes an unbounded pattern
    // backtrack. Bounded, this returns immediately.
    let evil = "-".repeat(100_000);
    let started = Instant::now();
    let t = extract_target(&to(json!([{ "text": evil }])));
    assert!(t.error.is_some(), "should find no pull request");
    assert!(
        started.elapsed().as_millis() < 1000,
        "the bound is not holding"
    );
}

#[test]
fn the_near_miss_shape_is_fast_too() {
    // Many dashes, then a slash, then many more: worse for a naive pattern
    // because the prefix can match in many ways before failing.
    let evil = format!("{}/{}", "-".repeat(50_000), "-".repeat(50_000));
    let started = Instant::now();
    extract_target(&to(json!([{ "text": evil }])));
    assert!(
        started.elapsed().as_millis() < 1000,
        "the bound is not holding"
    );
}

#[test]
fn bounding_the_input_did_not_break_ordinary_references() {
    // The fix must not cost the feature. A reference after some preamble still
    // resolves, and one past the 2KB cap is simply not found rather than
    // scanned for.
    let near = extract_target(&to(
        json!([{ "text": format!("{}nyuchi/web-services#18", "word ".repeat(50)) }]),
    ));
    assert_eq!(
        (near.repo.as_deref(), near.number),
        (Some("nyuchi/web-services"), Some(18))
    );
    let far = extract_target(&to(
        json!([{ "text": format!("{} nyuchi/web-services#18", "x".repeat(3000)) }]),
    ));
    assert!(far.error.is_some());
}
