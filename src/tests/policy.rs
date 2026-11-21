//! Port of test/policy.test.ts: the two bounds that decide what this worker
//! can do, and the one thing it refuses.

use super::*;
use crate::auth::{authorization_server, normalise_authkit_domain, protected_resource_metadata};
use crate::error::Failure;
use crate::github::{
    create_review, missing_permissions, paginate, resolve_repo, slim_issue, slim_pull,
};
use crate::mcp::{tool_error, tools_list};
use serde_json::Map;

#[test]
fn a_repo_slug_resolves_to_owner_and_name() {
    assert_eq!(
        resolve_repo("nyuchi/api-gateway").unwrap(),
        ("nyuchi".to_owned(), "api-gateway".to_owned())
    );
}

#[test]
fn the_original_casing_is_preserved() {
    assert_eq!(
        resolve_repo("Nyuchi/API-Gateway").unwrap(),
        ("Nyuchi".to_owned(), "API-Gateway".to_owned())
    );
}

#[test]
fn a_malformed_slug_is_rejected_before_any_call_is_made() {
    let e = resolve_repo("api-gateway").unwrap_err();
    assert!(e.message.contains("expected owner/repo"), "{}", e.message);
}

#[test]
fn approve_is_refused_in_any_casing() {
    // An agent that can approve satisfies a branch protection review
    // requirement on its own, letting code reach a protected branch with no
    // human having read it. This must fail before any HTTP: the Mock has no
    // routes, so a request would error differently.
    let p = Mock::default();
    for event in ["APPROVE", "approve", "Approve"] {
        let e = run(create_review(
            &p,
            &Config::default(),
            "nyuchi/api-gateway",
            1,
            event,
            "looks good",
            vec![],
        ))
        .unwrap_err();
        assert!(
            e.to_string().contains("does not approve pull requests"),
            "{event}"
        );
    }
    assert!(p.requests.borrow().is_empty());
}

#[test]
fn an_unrecognised_review_event_is_refused() {
    let p = Mock::default();
    let e = run(create_review(
        &p,
        &Config::default(),
        "nyuchi/api-gateway",
        1,
        "MERGE",
        "x",
        vec![],
    ))
    .unwrap_err();
    assert!(e.to_string().contains("unsupported review event"));
}

// --- missing_permissions ---------------------------------------------------
//
// This decides whether shamwari_whoami reports a repository as ready. Its
// whole value is being trusted when a 422 appears, so the read/write asymmetry
// gets pinned rather than assumed.

fn m(pairs: &[(&str, &str)]) -> Map<String, Value> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), json!(v)))
        .collect()
}

#[test]
fn a_permission_the_installation_does_not_hold_at_all_is_missing() {
    assert_eq!(
        missing_permissions(
            &m(&[("pull_requests", "write"), ("issues", "write")]),
            &m(&[("pull_requests", "write")])
        ),
        vec!["issues:write"]
    );
}

#[test]
fn write_satisfies_a_read_request() {
    assert!(
        missing_permissions(&m(&[("contents", "read")]), &m(&[("contents", "write")])).is_empty()
    );
}

#[test]
fn read_does_not_satisfy_a_write_request() {
    assert_eq!(
        missing_permissions(&m(&[("issues", "write")]), &m(&[("issues", "read")])),
        vec!["issues:write"]
    );
}

#[test]
fn an_exact_match_is_not_missing() {
    let both = [
        ("pull_requests", "write"),
        ("contents", "read"),
        ("metadata", "read"),
    ];
    assert!(missing_permissions(&m(&both), &m(&both)).is_empty());
}

#[test]
fn extra_permissions_the_installation_holds_are_not_reported() {
    // The App is broader than the token asks for by design: that is the whole
    // point of the scoped mint, so surplus must never read as a problem.
    assert!(missing_permissions(
        &m(&[("contents", "read")]),
        &m(&[
            ("contents", "write"),
            ("workflows", "write"),
            ("administration", "write")
        ])
    )
    .is_empty());
}

#[test]
fn an_empty_installation_misses_everything_requested() {
    assert_eq!(
        missing_permissions(
            &m(&[("pull_requests", "write"), ("issues", "write")]),
            &Map::new()
        ),
        vec!["pull_requests:write", "issues:write"]
    );
}

// --- protected resource metadata -------------------------------------------

#[test]
fn the_metadata_advertises_no_scopes() {
    // Advertising a scope WorkOS does not define is worse than advertising
    // none: the client asks for it, WorkOS returns `error=invalid_scope` to the
    // client's callback, and the user never reaches a login page. This worker
    // gates on organization, role and permission claims, never on scopes.
    let c = Config {
        mcp_resource_url: Some("https://github.shamwari.ai/mcp".into()),
        workos_authorization_server: Some("https://identity.example.test/".into()),
        ..Default::default()
    };
    let meta = protected_resource_metadata(&c, "https://github.shamwari.ai/mcp").unwrap();
    assert!(meta.get("scopes_supported").is_none());
    assert_eq!(
        meta["authorization_servers"],
        json!(["https://identity.example.test"])
    );
    assert_eq!(meta["resource"], "https://github.shamwari.ai/mcp");
}

#[test]
fn resource_metadata_fails_closed_when_workos_authorization_server_is_unset() {
    let c = Config {
        mcp_resource_url: Some("https://github.shamwari.ai/mcp".into()),
        ..Default::default()
    };
    assert!(protected_resource_metadata(&c, "https://github.shamwari.ai/mcp").is_none());
}

#[test]
fn the_advertised_authorization_server_is_parsed_into_an_https_origin() {
    let at = |v: Option<&str>| {
        authorization_server(&Config {
            workos_authorization_server: v.map(str::to_owned),
            ..Default::default()
        })
    };
    assert_eq!(at(None), None);
    assert_eq!(at(Some("   ")), None);
    let good = Some("https://identity.example.test".to_owned());
    assert_eq!(at(Some("https://identity.example.test")), good);
    assert_eq!(at(Some("identity.example.test")), good);
    assert_eq!(at(Some("HTTPS://Identity.Example.Test")), good);
    assert_eq!(at(Some("https://identity.example.test/x/y?z=1#f")), good);
    for bad in [
        "http://identity.example.test",
        "javascript://identity.example.test",
        "https://user:pass@identity.example.test",
        "user@identity.example.test",
        "https://",
    ] {
        assert_eq!(at(Some(bad)), None, "{bad}");
        let c = Config {
            workos_authorization_server: Some(bad.into()),
            ..Default::default()
        };
        assert!(protected_resource_metadata(&c, "x").is_none(), "{bad}");
        let e = normalise_authkit_domain(Some(bad)).unwrap_err();
        assert!(
            e.starts_with("WORKOS_AUTHORIZATION_SERVER is not configured"),
            "{bad}: {e}"
        );
    }
}

// --- tool annotations ------------------------------------------------------
//
// Hints, not enforcement. But a client uses them to show which tools write
// before calling one, so a read tool mislabelled as a write (or worse, the
// reverse) misleads exactly when it matters.

#[test]
fn every_tool_carries_a_full_set_of_annotations() {
    for t in tools_list() {
        for k in [
            "readOnlyHint",
            "destructiveHint",
            "idempotentHint",
            "openWorldHint",
        ] {
            assert!(t["annotations"][k].is_boolean(), "{} {k}", t["name"]);
        }
    }
}

#[test]
fn the_read_tools_are_the_ones_that_read_and_nothing_else() {
    let mut read_only: Vec<String> = tools_list()
        .iter()
        .filter(|t| t["annotations"]["readOnlyHint"] == true)
        .map(|t| t["name"].as_str().unwrap().to_owned())
        .collect();
    read_only.sort();
    assert_eq!(
        read_only,
        [
            "shamwari_get_issue",
            "shamwari_get_pull_request",
            "shamwari_get_pull_request_diff",
            "shamwari_list_issues",
            "shamwari_list_pull_requests",
            "shamwari_whoami",
        ]
    );
}

#[test]
fn no_read_only_tool_is_marked_destructive_and_only_the_two_updates_are() {
    let tools = tools_list();
    for t in &tools {
        if t["annotations"]["readOnlyHint"] == true {
            assert_eq!(t["annotations"]["destructiveHint"], false, "{}", t["name"]);
        }
    }
    // The update tools overwrite existing fields; the create tools add.
    let mut updates: Vec<&str> = tools
        .iter()
        .filter(|t| t["annotations"]["destructiveHint"] == true)
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    updates.sort();
    assert_eq!(
        updates,
        ["shamwari_update_issue", "shamwari_update_pull_request"]
    );
}

#[test]
fn there_is_no_approve_tool_and_no_merge_tool() {
    for t in tools_list() {
        let name = t["name"].as_str().unwrap();
        assert!(
            !name.contains("approve") && !name.contains("merge"),
            "{name}"
        );
    }
}

#[test]
fn the_tool_names_are_exactly_the_ones_the_typescript_server_exposed() {
    let mut names: Vec<String> = tools_list()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "shamwari_comment",
            "shamwari_create_issue",
            "shamwari_create_pull_request",
            "shamwari_create_review",
            "shamwari_get_issue",
            "shamwari_get_pull_request",
            "shamwari_get_pull_request_diff",
            "shamwari_list_issues",
            "shamwari_list_pull_requests",
            "shamwari_review_pull_request",
            "shamwari_update_issue",
            "shamwari_update_pull_request",
            "shamwari_whoami",
        ]
    );
}

// --- list output shaping ---------------------------------------------------
//
// The list tools used to return raw GitHub objects: thirteen pull requests
// serialised to 276,801 bytes against 3,842 shaped, 99% of it structure
// nothing reads. That is context an agent cannot spend twice.

#[test]
fn paginate_reports_another_page_only_when_one_exists() {
    // Callers fetch limit+1; the extra row is the signal, not part of the page.
    let rows = |n: usize| (1..=n).map(|i| json!(i)).collect::<Vec<_>>();
    let over = paginate(rows(4), 3, 1);
    assert_eq!(over["items"], json!([1, 2, 3]));
    assert_eq!(over["count"], 3);
    assert_eq!(over["has_more"], true);
    assert_eq!(over["next_page"], 2);

    let exact = paginate(rows(3), 3, 1);
    assert_eq!(exact["has_more"], false);
    assert!(exact.get("next_page").is_none());

    let empty = paginate(vec![], 20, 1);
    assert_eq!(empty["items"], json!([]));
    assert_eq!(empty["has_more"], false);
}

#[test]
fn paginate_carries_the_page_number_through() {
    assert_eq!(paginate(vec![json!(1), json!(2)], 1, 4)["next_page"], 5);
}

#[test]
fn slim_pull_keeps_what_a_reviewer_needs_and_drops_the_rest() {
    let raw = json!({
        "number": 12,
        "title": "dual-era MCP",
        "state": "open",
        "draft": false,
        "user": { "login": "bryanfawcett", "id": 1, "avatar_url": "…", "node_id": "…" },
        "base": { "ref": "main", "repo": { "id": 1, "owner": {}, "permissions": {} } },
        "head": { "ref": "feat/x", "repo": { "id": 1, "owner": {}, "permissions": {} } },
        "labels": [{ "name": "enhancement", "color": "fff", "id": 9 }],
        "created_at": "2026-09-17T18:00:00Z",
        "updated_at": "2026-09-17T19:00:00Z",
        "html_url": "https://github.com/nyuchi/web-services/pull/12",
        "_links": { "self": {}, "html": {}, "comments": {} },
        "body": "x".repeat(5000),
    });
    let slim = slim_pull(&raw);
    assert_eq!(slim["number"], 12);
    assert_eq!(slim["author"], "bryanfawcett");
    assert_eq!(slim["base"], "main");
    assert_eq!(slim["head"], "feat/x");
    assert_eq!(slim["labels"], json!(["enhancement"]));
    // The expensive parts must not survive.
    for k in ["_links", "body", "user"] {
        assert!(slim.get(k).is_none(), "{k} should not be in the slim shape");
    }
    assert!(slim.to_string().len() < raw.to_string().len() / 5);
}

#[test]
fn slim_issue_flags_pull_requests_returned_by_the_issues_endpoint() {
    // GitHub returns PRs from /issues. A caller that misses this counts them
    // as issues, which is wrong in both directions.
    assert_eq!(
        slim_issue(&json!({ "number": 1, "pull_request": { "url": "…" } }))["is_pull_request"],
        true
    );
    assert_eq!(
        slim_issue(&json!({ "number": 2 }))["is_pull_request"],
        false
    );
}

// --- what a failed tool call may say ---------------------------------------
//
// The tools/call path once returned `e.message` for every throw: a TypeError's
// message names an internal property, a fetch failure names an internal URL.
// A GitHub error is different: its message is written for the caller and is
// the only thing that tells them which permission is missing.

#[test]
fn a_github_error_reaches_the_caller_because_it_is_the_actionable_one() {
    let e = Failure::GitHub(crate::error::GitHubError::new(
        "nyuchi/web-services: App not installed",
        404,
    ));
    let res = tool_error("shamwari_get_pull_request", &e);
    assert!(res.is_error);
    assert!(res.text.contains("App not installed"));
}

#[test]
fn any_other_failure_does_not_however_tempting_the_message() {
    let e = Failure::Internal("Cannot read properties of undefined (reading 'secret')".into());
    let res = tool_error("shamwari_get_pull_request", &e);
    assert!(res.is_error);
    for leak in ["secret", "TypeError", "undefined"] {
        assert!(!res.text.contains(leak), "{leak}");
    }
    assert!(res.text.contains("internal error"));
}

#[test]
fn an_internal_failure_carrying_a_token_is_not_stringified_into_the_response() {
    let e = Failure::Internal(r#"{"token":"ghs_leaked"}"#.into());
    assert!(!tool_error("shamwari_comment", &e).text.contains("ghs_"));
}

#[test]
fn an_argument_error_names_the_field_so_the_caller_can_fix_the_call() {
    let e = Failure::Argument(r#"missing or invalid "number": expected a number"#.into());
    let res = tool_error("shamwari_get_pull_request", &e);
    assert!(res.is_error);
    assert!(res.text.contains("\"number\"") && res.text.contains("expected a number"));
}
