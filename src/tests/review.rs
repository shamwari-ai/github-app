//! Port of test/review.test.ts: the review engine.
//!
//! Weighted towards `annotate_diff`, because that is where a defect is
//! invisible: a wrong line number does not fail, it posts a careful-looking
//! comment on unrelated code. The tests pin exact numbers against a diff whose
//! arithmetic is worked out by hand in the comments.

use super::*;
use crate::review::*;
use std::collections::BTreeSet;

fn lines(set: Option<&BTreeSet<u64>>) -> Vec<u64> {
    set.map(|s| s.iter().copied().collect()).unwrap_or_default()
}

// @@ -10,6 +10,7 @@ — the new side starts at line 10.
//
//   10  const a = 1;      context
//   11  const b = 2;      context
//   --  const c = 3;      REMOVED, no new-file line
//   12  const c = 4;      ADDED
//   13  const d = 5;      ADDED
//   14  const e = 6;      context
//   15  return a;         context
const DIFF: &str = "diff --git a/src/a.ts b/src/a.ts
index 1111111..2222222 100644
--- a/src/a.ts
+++ b/src/a.ts
@@ -10,6 +10,7 @@ function f() {
 const a = 1;
 const b = 2;
-const c = 3;
+const c = 4;
+const d = 5;
 const e = 6;
 return a;
";

#[test]
fn annotate_diff_numbers_added_lines_from_the_hunk_header() {
    let (_, added) = annotate_diff(DIFF);
    assert_eq!(lines(added.get("src/a.ts")), vec![12, 13]);
}

#[test]
fn a_removed_line_never_becomes_a_comment_target() {
    let (text, added) = annotate_diff(DIFF);
    // "const c = 3;" was removed. Nothing may anchor to it, and the line it
    // occupied (11 on the old side) belongs to `const b = 2;` on the new side.
    assert!(!added["src/a.ts"].contains(&11));
    assert!(
        text.lines().any(|l| l.starts_with("-     |const c = 3;")),
        "{text}"
    );
}

#[test]
fn context_lines_advance_the_counter_but_are_not_targets() {
    let (text, added) = annotate_diff(DIFF);
    assert!(text.lines().any(|l| l == "    14|const e = 6;"), "{text}");
    assert!(!added["src/a.ts"].contains(&14));
}

#[test]
fn the_annotated_text_is_exactly_what_the_model_is_shown() {
    let (text, _) = annotate_diff(DIFF);
    assert_eq!(
        text,
        "### src/a.ts\n@@ -10,6 +10,7 @@ function f() {\n    10|const a = 1;\n    11|const b = 2;\n-     |const c = 3;\n+   12|const c = 4;\n+   13|const d = 5;\n    14|const e = 6;\n    15|return a;\n    16|"
    );
    // The trailing "    16|" is the empty string after the diff's final
    // newline, treated as one more context line: the TypeScript did exactly
    // the same, and the model is told only "+" lines are valid targets.
}

#[test]
fn a_new_file_numbers_from_1() {
    let (_, added) = annotate_diff(
        "diff --git a/new.ts b/new.ts
new file mode 100644
index 0000000..3333333
--- /dev/null
+++ b/new.ts
@@ -0,0 +1,3 @@
+one
+two
+three
",
    );
    assert_eq!(lines(added.get("new.ts")), vec![1, 2, 3]);
}

#[test]
fn a_rename_attributes_added_lines_to_the_new_path_not_the_old() {
    let (_, added) = annotate_diff(
        "diff --git a/old.ts b/renamed.ts
similarity index 90%
rename from old.ts
rename to renamed.ts
index 4444444..5555555 100644
--- a/old.ts
+++ b/renamed.ts
@@ -1,2 +1,3 @@
 keep
+added
 keep2
",
    );
    assert_eq!(lines(added.get("renamed.ts")), vec![2]);
    assert!(!added.contains_key("old.ts"));
}

#[test]
fn several_hunks_in_one_file_each_restart_from_their_own_header() {
    let (_, added) = annotate_diff(
        "diff --git a/m.ts b/m.ts
index 6666666..7777777 100644
--- a/m.ts
+++ b/m.ts
@@ -1,2 +1,3 @@
 a
+b
 c
@@ -50,2 +51,3 @@
 x
+y
 z
",
    );
    assert_eq!(lines(added.get("m.ts")), vec![2, 52]);
}

#[test]
fn two_files_do_not_share_a_line_number_space() {
    let both = format!(
        "{DIFF}diff --git a/src/b.ts b/src/b.ts
index 8888888..9999999 100644
--- a/src/b.ts
+++ b/src/b.ts
@@ -1,1 +1,2 @@
 first
+second
"
    );
    let (_, added) = annotate_diff(&both);
    assert_eq!(lines(added.get("src/a.ts")), vec![12, 13]);
    assert_eq!(lines(added.get("src/b.ts")), vec![2]);
}

#[test]
fn a_binary_file_is_noted_not_numbered() {
    let (text, added) = annotate_diff(
        "diff --git a/logo.png b/logo.png
index aaa..bbb 100644
Binary files a/logo.png and b/logo.png differ
",
    );
    assert!(text.contains("binary file"));
    assert!(added.is_empty());
}

// --- anchoring ---------------------------------------------------------------

fn f(path: &str, line: u64, severity: Severity) -> Finding {
    Finding {
        path: path.into(),
        line,
        severity,
        title: "t".into(),
        body: "b".into(),
    }
}

#[test]
fn a_finding_on_a_line_the_diff_does_not_add_is_held_back_not_posted() {
    let (_, added) = annotate_diff(DIFF);
    let (anchored, unanchored) = anchor(
        vec![
            f("src/a.ts", 12, Severity::Note),
            f("src/a.ts", 99, Severity::Note),
            f("other.ts", 12, Severity::Note),
        ],
        &added,
    );
    let names: Vec<String> = anchored
        .iter()
        .map(|x| format!("{}:{}", x.path, x.line))
        .collect();
    assert_eq!(names, ["src/a.ts:12"]);
    // GitHub 422s the whole review call on one bad position, which would lose
    // every real finding alongside the invented one.
    assert_eq!(unanchored.len(), 2);
}

#[test]
fn findings_are_ranked_so_a_cap_keeps_the_serious_ones() {
    let ordered = rank(vec![
        f("a", 1, Severity::Note),
        f("a", 2, Severity::Blocking),
        f("a", 3, Severity::Concern),
    ]);
    let sev: Vec<Severity> = ordered.iter().map(|x| x.severity).collect();
    assert_eq!(sev, [Severity::Blocking, Severity::Concern, Severity::Note]);
}

// --- model output is not trusted ----------------------------------------------
//
// Cloudflare's JSON-mode docs say outright it "can't guarantee that the model
// responds according to the requested JSON Schema".

#[test]
fn a_json_string_response_is_parsed_an_object_response_is_taken_as_is() {
    let v = json!({ "summary": "s", "findings": [f("a.ts", 3, Severity::Note)] });
    let as_string = parse_findings(&json!(v.to_string())).unwrap();
    let as_object = parse_findings(&v).unwrap();
    assert_eq!(as_string, as_object);
}

#[test]
fn malformed_findings_are_dropped_individually_not_fatally() {
    let (_, findings) = parse_findings(&json!({
        "summary": "s",
        "findings": [
            { "path": "good.ts", "line": 5, "title": "t", "body": "b", "severity": "note" },
            { "path": "", "line": 5, "body": "x", "severity": "note" },
            { "path": "a.ts", "line": 0, "body": "x", "severity": "note" },
            { "path": "a.ts", "line": 2.5, "body": "x", "severity": "note" },
            { "path": "a.ts", "line": 5, "body": "", "severity": "note" },
            null,
            "not an object",
        ],
    }))
    .unwrap();
    let paths: Vec<&str> = findings.iter().map(|x| x.path.as_str()).collect();
    assert_eq!(paths, ["good.ts"]);
}

#[test]
fn a_line_given_as_a_numeric_string_is_accepted_as_javascript_number_did() {
    let (_, findings) = parse_findings(&json!({
        "summary": "", "findings": [{ "path": "a.ts", "line": "7", "body": "b", "severity": "note" }],
    }))
    .unwrap();
    assert_eq!(findings[0].line, 7);
}

#[test]
fn an_unknown_severity_degrades_to_note_rather_than_failing() {
    let (_, findings) = parse_findings(&json!({
        "summary": "",
        "findings": [{ "path": "a.ts", "line": 1, "body": "b", "severity": "CRITICAL!!" }],
    }))
    .unwrap();
    assert_eq!(findings[0].severity, Severity::Note);
}

#[test]
fn a_model_that_returns_prose_instead_of_json_fails_loudly() {
    let e = parse_findings(&json!("I reviewed the code and it looks fine!")).unwrap_err();
    assert!(e.message.contains("did not return JSON"));
    assert_eq!(e.status, 502);
}

#[test]
fn a_non_object_response_fails_loudly() {
    assert!(parse_findings(&json!(42))
        .unwrap_err()
        .message
        .contains("no object"));
}

#[test]
fn a_missing_findings_array_is_an_empty_review_not_a_crash() {
    let (summary, findings) = parse_findings(&json!({ "summary": "clean" })).unwrap();
    assert!(findings.is_empty());
    assert_eq!(summary, "clean");
}

// --- the body a human reads ----------------------------------------------------

#[test]
fn unanchored_findings_appear_in_the_body_instead_of_vanishing() {
    let mut u = f("src/a.ts", 99, Severity::Note);
    u.title = "possible null".into();
    let body = render_body("@cf/zai-org/glm-5.3", "Checked the diff.", &[], &[u], false);
    assert!(body.contains("src/a.ts:99"));
    assert!(body.contains("possible null"));
}

#[test]
fn the_body_says_the_reviewer_cannot_approve() {
    assert!(render_body("m", "s", &[], &[], false).contains("cannot approve"));
}

#[test]
fn the_body_carries_the_marker_that_makes_a_second_run_detectable() {
    assert!(render_body("m", "s", &[], &[], false).starts_with(REVIEW_MARKER));
}

#[test]
fn truncation_is_disclosed_because_a_partial_read_is_not_a_clean_review() {
    assert!(render_body("m", "s", &[], &[], true).contains("truncated"));
}

#[test]
fn truncate_cuts_on_a_line_boundary() {
    let (text, truncated) = truncate("aaaa\nbbbb\ncccc\n", 7);
    assert!(truncated);
    assert_eq!(text, "aaaa\n");
}

#[test]
fn truncate_never_splits_a_multibyte_character() {
    let (text, truncated) = truncate("héllo\nwörld\n", 2);
    assert!(truncated);
    assert!(text.is_char_boundary(text.len()));
}

#[test]
fn text_within_budget_is_returned_untouched() {
    let (text, truncated) = truncate("short", 100);
    assert!(!truncated);
    assert_eq!(text, "short");
}

// --- the guards that run before anything is spent -------------------------------

fn ai_ok() -> Mock {
    Mock::default()
        .with_ai(|_, _, _| Ok(json!({ "response": { "summary": "ok", "findings": [] } })))
}

#[test]
fn the_kill_switch_fails_closed_before_any_model_call() {
    let c = Config {
        review_enabled: Some("false".into()),
        ..Default::default()
    };
    let e = run(review_pull_request(
        &ai_ok(),
        &c,
        "nyuchi/web-services",
        1,
        &ReviewOptions::default(),
        None,
    ))
    .unwrap_err();
    assert!(e.to_string().contains("disabled"));
}

#[test]
fn a_missing_ai_binding_says_what_to_add_rather_than_failing_obscurely() {
    let c = Config {
        review_enabled: Some("true".into()),
        ..Default::default()
    };
    let e = run(review_pull_request(
        &Mock::default(),
        &c,
        "nyuchi/web-services",
        1,
        &ReviewOptions::default(),
        None,
    ))
    .unwrap_err();
    assert!(e.to_string().contains("wrangler.toml"));
}

// --- the gateway call -------------------------------------------------------------

#[test]
fn gateway_metadata_attributes_cost_without_naming_a_person() {
    let c = Config {
        ai_gateway_id: Some("fundi".into()),
        ..Default::default()
    };
    let opts = ReviewOptions {
        trigger: Some("mention:someone".into()),
        ..Default::default()
    };
    let g = gateway_options(&c, "nyuchi/web-services", &opts).unwrap();
    assert_eq!(g["gateway"]["id"], "fundi");
    assert_eq!(g["gateway"]["skipCache"], true);
    assert_eq!(
        g["gateway"]["metadata"],
        json!({ "worker": "shamwari-github-mcp", "job": "pr_review", "repo": "nyuchi/web-services", "trigger": "mention" })
    );
    // The gateway accepts at most five metadata entries.
    assert!(g["gateway"]["metadata"].as_object().unwrap().len() <= 5);
}

#[test]
fn no_gateway_configured_means_calling_workers_ai_directly() {
    assert!(gateway_options(
        &Config::default(),
        "nyuchi/web-services",
        &ReviewOptions::default()
    )
    .is_none());
}

#[test]
fn asking_to_post_without_a_head_sha_fails_before_the_model_is_paid() {
    let calls = std::rc::Rc::new(std::cell::Cell::new(0));
    let c2 = calls.clone();
    let p = Mock::default().with_ai(move |_, _, _| {
        c2.set(c2.get() + 1);
        Ok(json!({}))
    });
    let cfg = Config {
        review_enabled: Some("true".into()),
        ..Default::default()
    };
    let e = run(review_pull_request(
        &p,
        &cfg,
        "nyuchi/web-services",
        1,
        &ReviewOptions {
            post: true,
            ..Default::default()
        },
        None,
    ))
    .unwrap_err();
    assert!(e.to_string().contains("head commit sha"));
    assert_eq!(calls.get(), 0);
}

#[test]
fn a_dynamic_route_gets_the_openai_response_format_and_answer_shape() {
    let dynamic = response_format("dynamic/review");
    let keys: Vec<&String> = dynamic["json_schema"].as_object().unwrap().keys().collect();
    assert_eq!(keys, ["name", "schema"]);
    assert_eq!(
        response_format("@cf/zai-org/glm-5.3")["json_schema"]["type"],
        "object"
    );
    assert_eq!(
        model_output(&json!({ "choices": [{ "message": { "content": "{}" } }] })),
        json!("{}")
    );
    assert_eq!(
        model_output(&json!({ "response": { "summary": "" } })),
        json!({ "summary": "" })
    );
}

// --- the whole engine, end to end (new coverage: the TypeScript suite never
// exercised reviewDiff / post / already-reviewed with a mocked platform) ------

const HEAD: &str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

fn engine_cfg() -> Config {
    Config {
        github_app_id: Some("5579098".into()),
        github_app_private_key: Some(pem("PRIVATE KEY", &pkcs8_der(test_key()))),
        review_enabled: Some("true".into()),
        ai_gateway_id: Some("fundi".into()),
        ..Default::default()
    }
}

fn github_mock(existing_comments: Value) -> Mock {
    Mock::default().route(move |r| {
        let u = r.url.as_str();
        let ok = |body: Value| {
            Some(HttpResponse {
                status: 200,
                body: body.to_string(),
            })
        };
        if u.ends_with("/repos/nyuchi/web-services/installation") {
            return ok(json!({ "id": 99 }));
        }
        if u.ends_with("/app/installations/99/access_tokens") {
            return ok(json!({ "token": "ghs_test", "expires_at": "2027-01-01T00:00:00Z" }));
        }
        if u.ends_with("/pulls/7") {
            return Some(HttpResponse {
                status: 200,
                body: DIFF.into(),
            });
        }
        if u.contains("/commits/") && u.contains("/comments") {
            return if r.method == "POST" {
                Some(HttpResponse {
                    status: 201,
                    body: "{}".into(),
                })
            } else {
                ok(existing_comments.clone())
            };
        }
        None
    })
}

fn model_says(finding_line: u64) -> impl Fn(&str, &Value, Option<&Value>) -> Result<Value, String> {
    move |_, _, _| {
        Ok(json!({ "response": {
            "summary": "one blocker",
            "findings": [
                { "path": "src/a.ts", "line": finding_line, "severity": "blocking", "title": "bad", "body": "wrong" },
                { "path": "src/a.ts", "line": 999, "severity": "note", "title": "ghost", "body": "n/a" },
            ],
        }, "usage": { "prompt_tokens": 10, "completion_tokens": 5 } }))
    }
}

#[test]
fn a_dry_run_reviews_without_posting_and_passes_the_gateway_as_the_third_argument() {
    crate::github::clear_caches();
    let seen = std::rc::Rc::new(std::cell::RefCell::new(None));
    let s2 = seen.clone();
    let p = github_mock(json!([])).with_ai(move |model, input, options| {
        *s2.borrow_mut() = Some((model.to_owned(), input.clone(), options.cloned()));
        model_says(12)(model, input, options)
    });
    let r = run(review_pull_request(
        &p,
        &engine_cfg(),
        "nyuchi/web-services",
        7,
        &ReviewOptions::default(),
        None,
    ))
    .unwrap();
    assert!(!r.posted);
    assert_eq!(r.findings.len(), 1);
    assert_eq!(r.findings[0].line, 12);
    assert_eq!(r.unanchored.len(), 1);
    assert_eq!(
        p.count("/comments"),
        0,
        "a dry run must not touch commit comments"
    );
    let (model, input, options) = seen.borrow().clone().unwrap();
    assert_eq!(model, "@cf/zai-org/glm-5.3");
    assert!(
        input.get("gateway").is_none(),
        "the gateway is NOT part of the input"
    );
    assert_eq!(options.unwrap()["gateway"]["id"], "fundi");
    let user = input["messages"][1]["content"].as_str().unwrap();
    assert!(user.contains("+   12|const c = 4;"), "{user}");
}

#[test]
fn posting_writes_one_commit_comment_never_a_pull_request_review() {
    crate::github::clear_caches();
    let p = github_mock(json!([])).with_ai(model_says(12));
    let opts = ReviewOptions {
        post: true,
        trigger: Some("pull_request".into()),
        ..Default::default()
    };
    let r = run(review_pull_request(
        &p,
        &engine_cfg(),
        "nyuchi/web-services",
        7,
        &opts,
        Some(HEAD),
    ))
    .unwrap();
    assert!(r.posted);
    assert_eq!(r.sha.as_deref(), Some(HEAD));
    let posts: Vec<HttpRequest> = p
        .requests
        .borrow()
        .iter()
        .filter(|q| q.method == "POST" && q.url.contains("/comments"))
        .cloned()
        .collect();
    assert_eq!(posts.len(), 1);
    assert!(posts[0].url.ends_with(&format!("/commits/{HEAD}/comments")));
    assert!(posts[0].body.as_ref().unwrap().contains("nyuchi-review"));
    assert_eq!(
        p.count("/reviews"),
        0,
        "must never create a pull request review"
    );
}

#[test]
fn a_commit_that_already_carries_a_review_is_skipped_before_the_model_is_paid() {
    crate::github::clear_caches();
    let calls = std::rc::Rc::new(std::cell::Cell::new(0));
    let c2 = calls.clone();
    let p = github_mock(json!([{ "body": format!("{REVIEW_MARKER}\nold") }])).with_ai(
        move |m, i, o| {
            c2.set(c2.get() + 1);
            model_says(12)(m, i, o)
        },
    );
    let opts = ReviewOptions {
        post: true,
        ..Default::default()
    };
    let r = run(review_pull_request(
        &p,
        &engine_cfg(),
        "nyuchi/web-services",
        7,
        &opts,
        Some(HEAD),
    ))
    .unwrap();
    assert_eq!(r.skipped.as_deref(), Some("already reviewed"));
    assert!(!r.posted);
    assert_eq!(calls.get(), 0);
    // `force` (a person asking again by name) overrides it.
    let forced = ReviewOptions {
        post: true,
        force: true,
        ..Default::default()
    };
    let r = run(review_pull_request(
        &p,
        &engine_cfg(),
        "nyuchi/web-services",
        7,
        &forced,
        Some(HEAD),
    ))
    .unwrap();
    assert!(r.posted);
    assert_eq!(calls.get(), 1);
}

#[test]
fn an_oversized_diff_is_truncated_and_says_so() {
    crate::github::clear_caches();
    let p = github_mock(json!([])).with_ai(model_says(12));
    let opts = ReviewOptions {
        max_diff_bytes: Some(80),
        ..Default::default()
    };
    let r = run(review_pull_request(
        &p,
        &engine_cfg(),
        "nyuchi/web-services",
        7,
        &opts,
        None,
    ))
    .unwrap();
    assert!(r.truncated);
}

#[test]
fn the_installation_token_asks_for_the_scoped_permissions_and_one_repository() {
    crate::github::clear_caches();
    let p = github_mock(json!([])).with_ai(model_says(12));
    run(review_pull_request(
        &p,
        &engine_cfg(),
        "nyuchi/web-services",
        7,
        &ReviewOptions::default(),
        None,
    ))
    .unwrap();
    let mint = p
        .requests
        .borrow()
        .iter()
        .find(|q| q.url.ends_with("/access_tokens"))
        .cloned()
        .unwrap();
    let body: Value = serde_json::from_str(mint.body.as_ref().unwrap()).unwrap();
    assert_eq!(body["repositories"], json!(["web-services"]));
    assert_eq!(
        body["permissions"],
        json!({ "pull_requests": "write", "issues": "write", "contents": "read", "metadata": "read" })
    );
    assert!(body["permissions"].get("workflows").is_none());
    // The mint is authenticated with an App JWT, the REST call with the token.
    let auth = |q: &HttpRequest| {
        q.headers
            .iter()
            .find(|(k, _)| k == "Authorization")
            .map(|(_, v)| v.clone())
            .unwrap()
    };
    assert!(auth(&mint).starts_with("Bearer eyJ"));
    let diff = p
        .requests
        .borrow()
        .iter()
        .find(|q| q.url.ends_with("/pulls/7"))
        .cloned()
        .unwrap();
    assert_eq!(auth(&diff), "Bearer ghs_test");
}

#[test]
fn the_app_jwt_is_signed_with_the_configured_key_and_backdated() {
    crate::github::clear_caches();
    let p = Mock::default();
    let jwt = crate::github::app_jwt(&p, &engine_cfg()).unwrap();
    let parts: Vec<&str> = jwt.split('.').collect();
    let payload: Value =
        serde_json::from_slice(&crate::util::b64url_decode(parts[1]).unwrap()).unwrap();
    assert_eq!(payload["iss"], "5579098");
    assert_eq!(payload["iat"], NOW_SEC - 60);
    assert_eq!(payload["exp"], NOW_SEC + 540);
    // And it verifies against the matching public key.
    let ok = crate::auth::verify_rs256(
        &serde_json::from_value(jwk()).unwrap(),
        format!("{}.{}", parts[0], parts[1]).as_bytes(),
        &crate::util::b64url_decode(parts[2]).unwrap(),
    );
    assert!(ok);
}

#[test]
fn the_app_id_and_key_must_both_be_present() {
    crate::github::clear_caches();
    let p = Mock::default();
    let no_id = Config {
        github_app_id: None,
        ..engine_cfg()
    };
    assert!(crate::github::app_jwt(&p, &no_id)
        .unwrap_err()
        .message
        .contains("GITHUB_APP_ID is not set"));
    let no_key = Config {
        github_app_private_key: None,
        ..engine_cfg()
    };
    assert!(crate::github::app_jwt(&p, &no_key)
        .unwrap_err()
        .message
        .contains("GITHUB_APP_PRIVATE_KEY is not set"));
}

#[test]
fn a_pkcs1_pem_from_github_works_as_it_is_downloaded() {
    use rsa::pkcs1::EncodeRsaPrivateKey;
    crate::github::clear_caches();
    let pkcs1 = pem(
        "RSA PRIVATE KEY",
        test_key().to_pkcs1_der().unwrap().as_bytes(),
    );
    let c = Config {
        github_app_private_key: Some(pkcs1),
        ..engine_cfg()
    };
    assert!(crate::github::app_jwt(&Mock::default(), &c).is_ok());
}
