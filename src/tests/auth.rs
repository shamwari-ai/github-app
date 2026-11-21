//! Port of test/auth.test.ts: the WorkOS token gate, exercised against real
//! RS256 signatures.
//!
//! These cover the fail-closed behaviour specifically. The issuer and
//! audience checks were originally written as `if (env.X) { ...check... }`,
//! which reads as "check it when configured" and behaves as "accept anything
//! when an operator forgets it". That shipped, and the live worker ran for a
//! while verifying signature, org and role but neither issuer nor audience.
//! These tests exist so that cannot return.

use super::*;
use crate::auth::{caller_identity, verify_workos_token};

fn good() -> Value {
    json!({ "iss": ISSUER, "aud": AUDIENCE, "org_id": ORG, "role": "platform-team" })
}

fn with(base: Value, over: Value) -> Value {
    let mut b = base;
    for (k, v) in over.as_object().unwrap() {
        b[k] = v.clone();
    }
    b
}

async fn check(
    claims: Value,
    cfg: &Config,
    resource: Option<&str>,
) -> Result<crate::auth::Claims, String> {
    let p = Mock::default().with_jwks();
    verify_workos_token(&p, &mint_token(claims), cfg, resource)
        .await
        .map_err(|e| e.message)
}

fn rejects(claims: Value, cfg: &Config, expect: &str) {
    let e = run(check(claims, cfg, None)).expect_err("should be refused");
    assert!(e.contains(expect), "wanted {expect:?}, got {e:?}");
}

#[test]
fn a_correctly_scoped_token_is_accepted() {
    assert!(run(check(good(), &auth_config(), None)).is_ok());
}

#[test]
fn an_unset_workos_issuer_is_refused_not_skipped() {
    let c = Config {
        workos_issuer: None,
        ..auth_config()
    };
    rejects(good(), &c, "WORKOS_ISSUER unset");
}

#[test]
fn an_unset_workos_audience_is_refused_not_skipped() {
    let c = Config {
        workos_audience: None,
        ..auth_config()
    };
    rejects(good(), &c, "WORKOS_AUDIENCE unset");
}

#[test]
fn a_token_minted_for_another_mcp_resource_is_refused() {
    rejects(
        with(good(), json!({ "aud": "https://mongodb.nyuchi.dev/mcp" })),
        &auth_config(),
        "audience mismatch",
    );
}

#[test]
fn a_token_from_another_issuer_is_refused() {
    rejects(
        with(good(), json!({ "iss": "https://evil.example.com" })),
        &auth_config(),
        "issuer mismatch",
    );
}

#[test]
fn a_token_from_another_organization_is_refused() {
    rejects(
        with(good(), json!({ "org_id": "org_someone_else" })),
        &auth_config(),
        "organization not permitted",
    );
}

#[test]
fn an_org_member_with_neither_the_role_nor_the_permission_is_refused() {
    rejects(
        with(good(), json!({ "role": "member", "permissions": [] })),
        &auth_config(),
        "missing required platform role/permission",
    );
}

#[test]
fn the_permission_alone_satisfies_the_gate() {
    let c = with(
        good(),
        json!({ "role": null, "permissions": ["github:access"] }),
    );
    assert!(run(check(c, &auth_config(), None)).is_ok());
}

#[test]
fn the_retired_mongodb_access_permission_no_longer_satisfies_the_gate() {
    rejects(
        with(
            good(),
            json!({ "role": null, "permissions": ["mongodb:access"] }),
        ),
        &auth_config(),
        "missing required platform role/permission",
    );
}

#[test]
fn a_member_with_an_unrelated_permission_is_refused() {
    rejects(
        with(
            good(),
            json!({ "role": "member", "permissions": ["billing:read"] }),
        ),
        &auth_config(),
        "missing required platform role/permission",
    );
}

#[test]
fn an_expired_token_is_refused() {
    rejects(
        with(good(), json!({ "exp": NOW_SEC - 10 })),
        &auth_config(),
        "token expired",
    );
}

#[test]
fn a_token_not_yet_valid_is_refused() {
    rejects(
        with(good(), json!({ "nbf": NOW_SEC + 600 })),
        &auth_config(),
        "token not yet valid",
    );
}

#[test]
fn an_unset_workos_jwks_url_is_refused() {
    let c = Config {
        workos_jwks_url: None,
        ..auth_config()
    };
    rejects(good(), &c, "WORKOS_JWKS_URL unset");
}

#[test]
fn a_tampered_payload_fails_signature_verification() {
    let t = mint_token(good());
    let parts: Vec<&str> = t.split('.').collect();
    let forged = b64url_encode(json!({ "iss": ISSUER, "aud": AUDIENCE, "org_id": ORG, "role": "platform-team", "exp": NOW_SEC + 9999 }).to_string().as_bytes());
    let tampered = format!("{}.{forged}.{}", parts[0], parts[2]);
    let p = Mock::default().with_jwks();
    let e = run(verify_workos_token(&p, &tampered, &auth_config(), None)).unwrap_err();
    assert_eq!(e.message, "invalid token signature");
}

#[test]
fn a_non_rs256_token_and_a_malformed_token_are_refused() {
    let p = Mock::default().with_jwks();
    let hs = format!(
        "{}.{}.{}",
        b64url_encode(br#"{"alg":"HS256","typ":"JWT"}"#),
        b64url_encode(b"{}"),
        b64url_encode(b"sig")
    );
    let e = run(verify_workos_token(&p, &hs, &auth_config(), None)).unwrap_err();
    assert_eq!(e.message, "unsupported alg: HS256");
    let none = format!(
        "{}.{}.",
        b64url_encode(br#"{"alg":"none"}"#),
        b64url_encode(b"{}")
    );
    assert!(run(verify_workos_token(&p, &none, &auth_config(), None)).is_err());
    let e = run(verify_workos_token(
        &p,
        "not.a.jwt.at.all",
        &auth_config(),
        None,
    ))
    .unwrap_err();
    assert_eq!(e.message, "malformed token");
}

// --- WorkOS Agent Auth -----------------------------------------------------
//
// Agent tokens are signed by the SAME issuer and JWKS as user tokens, so they
// clear signature, issuer, audience and the org gate untouched. They then
// arrive at the permission gate carrying `scope` and no role at all, which is
// why an agent could authenticate and still never get in.

fn agent() -> Value {
    with(
        good(),
        json!({ "sub": "agent_reg_01ABCDEF", "scope": "github:access", "role": null, "roles": null }),
    )
}

#[test]
fn an_agent_token_is_accepted_on_its_scope_claim() {
    let claims = run(check(agent(), &auth_config(), None)).unwrap();
    assert_eq!(claims["sub"], "agent_reg_01ABCDEF");
}

#[test]
fn scope_is_space_separated_not_an_array_and_all_of_it_is_read() {
    // Reading it as an array silently yields nothing, and the agent is refused
    // for holding no permission, which looks identical to genuinely holding
    // none. Several scopes, the matching one last.
    let c = with(
        agent(),
        json!({ "scope": "repo:read issues:read github:access" }),
    );
    assert!(run(check(c, &auth_config(), None)).is_ok());
}

#[test]
fn an_agent_whose_scope_does_not_match_is_still_refused() {
    rejects(
        with(agent(), json!({ "scope": "something:else" })),
        &auth_config(),
        "missing required platform role/permission",
    );
}

#[test]
fn an_agent_from_another_organization_is_refused_as_a_person_would_be() {
    rejects(
        with(agent(), json!({ "org_id": "org_someone_else" })),
        &auth_config(),
        "organization not permitted",
    );
}

#[test]
fn an_agent_holding_only_the_retired_mongodb_access_scope_is_refused() {
    rejects(
        with(agent(), json!({ "scope": "mongodb:access" })),
        &auth_config(),
        "missing required platform role/permission",
    );
}

#[test]
fn accepting_scope_does_not_let_a_person_in_without_a_role() {
    // The change must widen the gate for agents only. A user token with
    // neither role nor permission still fails.
    rejects(
        with(good(), json!({ "role": "member", "permissions": [] })),
        &auth_config(),
        "missing required platform role/permission",
    );
}

#[test]
fn caller_identity_separates_an_agent_from_a_person() {
    let id = |v: Value| caller_identity(v.as_object().unwrap());
    assert_eq!(id(json!({ "sub": "agent_reg_01ABC" })).kind, "agent");
    assert_eq!(id(json!({ "sub": "user_01XYZ" })).kind, "user");
}

#[test]
fn caller_identity_records_who_the_agent_acts_for() {
    // RFC 8693: `act` is present only after a claim ceremony binds the agent
    // to a person. Autonomous agents have none, and that absence is the fact.
    let id = |v: Value| caller_identity(v.as_object().unwrap());
    let delegated =
        id(json!({ "sub": "agent_reg_01ABC", "act": { "sub": "user_01XYZ" }, "org_id": "org_1" }));
    assert_eq!(delegated.on_behalf_of.as_deref(), Some("user_01XYZ"));
    assert_eq!(delegated.org.as_deref(), Some("org_1"));
    let autonomous = id(json!({ "sub": "agent_reg_01ABC", "org_id": "org_1" }));
    assert_eq!(autonomous.on_behalf_of, None);
}

#[test]
fn a_token_for_the_served_resource_is_accepted_without_a_static_audience() {
    // The audience list used to be the only source of truth, and a typo in it
    // (or in MCP_RESOURCE_URL) locked every client out. The resource the
    // request was served under is always acceptable.
    let c = Config {
        workos_audience: None,
        ..auth_config()
    };
    let claims = run(check(
        with(good(), json!({ "aud": "https://github.nyuchi.dev/mcp" })),
        &c,
        Some("https://github.nyuchi.dev/mcp"),
    ))
    .unwrap();
    assert_eq!(claims["aud"], "https://github.nyuchi.dev/mcp");
}

#[test]
fn serving_a_resource_does_not_widen_the_audience_to_other_resources() {
    let e = run(check(
        with(good(), json!({ "aud": "https://mongodb.nyuchi.dev/mcp" })),
        &auth_config(),
        Some("https://github.nyuchi.dev/mcp"),
    ))
    .unwrap_err();
    assert!(e.contains("audience mismatch"));
}

#[test]
fn the_jwks_is_cached_between_verifications() {
    let p = Mock::default().with_jwks();
    for _ in 0..3 {
        assert!(run(verify_workos_token(
            &p,
            &mint_token(good()),
            &auth_config(),
            None
        ))
        .is_ok());
    }
    assert_eq!(p.count(JWKS_URL), 1);
}
