//! Port of test/webhook.test.ts: webhook ingest.
//!
//! Two rules carry the weight here. Nothing runs on a draft pull request, and
//! nothing runs on a delivery that is not signed. Both are cheap to assert and
//! expensive to get wrong: the first bills model calls against work nobody has
//! asked anyone to look at, the second lets a stranger bill them.

use super::*;
use crate::webhook::{
    decide, handle_webhook, mentions, verify_signature, Decision, DEFAULT_MENTION,
    DEFAULT_TRIGGER_ASSOCIATIONS,
};
use hmac::{Hmac, KeyInit, Mac};

fn assoc() -> Vec<String> {
    DEFAULT_TRIGGER_ASSOCIATIONS
        .iter()
        .map(|s| (*s).to_owned())
        .collect()
}

fn d(event: &str, payload: &Value) -> Decision {
    decide(event, payload, DEFAULT_MENTION, &assoc())
}

fn is_skip(d: &Decision) -> bool {
    matches!(d, Decision::Skip { .. })
}

fn reason(d: &Decision) -> &str {
    match d {
        Decision::Skip { reason } => reason,
        _ => "",
    }
}

fn pr_with(over: Value) -> Value {
    let mut v = json!({
        "action": "synchronize",
        "before": "a".repeat(40),
        "after": "b".repeat(40),
        "repository": { "full_name": "nyuchi/web-services" },
        "pull_request": { "number": 42, "draft": false, "state": "open", "head": { "sha": "b".repeat(40) } },
    });
    for (k, val) in over.as_object().unwrap() {
        v[k] = val.clone();
    }
    v
}

fn pr() -> Value {
    pr_with(json!({}))
}

fn draft() -> Value {
    json!({ "number": 42, "draft": true, "state": "open", "head": { "sha": "b".repeat(40) } })
}

// --- the draft rule --------------------------------------------------------

#[test]
fn a_draft_pull_request_is_not_reviewed() {
    let x = d("pull_request", &pr_with(json!({ "pull_request": draft() })));
    assert!(is_skip(&x));
    assert!(reason(&x).contains("draft"));
}

#[test]
fn a_draft_is_skipped_on_every_action_not_only_on_synchronize() {
    for action in ["synchronize", "opened", "ready_for_review"] {
        let x = d(
            "pull_request",
            &pr_with(json!({ "action": action, "pull_request": draft() })),
        );
        assert!(is_skip(&x), "{action} should skip a draft");
    }
}

#[test]
fn leaving_draft_reviews_the_whole_pull_request_not_just_the_last_push() {
    // The consequence of skipping drafts: everything pushed while the pull
    // request was a draft has never been read. Reviewing only the final push
    // would review the last typo fix and call the branch clean.
    let x = d(
        "pull_request",
        &pr_with(json!({ "action": "ready_for_review" })),
    );
    assert!(matches!(x, Decision::Full { .. }));
}

// --- what triggers a review ------------------------------------------------

#[test]
fn a_push_onto_an_open_non_draft_pull_request_reviews_that_push() {
    match d("pull_request", &pr()) {
        Decision::Push {
            repo,
            number,
            before,
            after,
        } => {
            assert_eq!(before, "a".repeat(40));
            assert_eq!(after, "b".repeat(40));
            assert_eq!(number, 42);
            assert_eq!(repo, "nyuchi/web-services");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn opening_a_ready_pull_request_reviews_the_whole_thing() {
    assert!(matches!(
        d("pull_request", &pr_with(json!({ "action": "opened" }))),
        Decision::Full { .. }
    ));
}

#[test]
fn an_all_zero_before_sha_falls_back_to_the_full_diff() {
    // A branch's first push has no predecessor to compare against.
    assert!(matches!(
        d(
            "pull_request",
            &pr_with(json!({ "before": "0".repeat(40) }))
        ),
        Decision::Full { .. }
    ));
}

#[test]
fn a_closed_pull_request_is_not_reviewed_on_a_late_delivery() {
    let closed = json!({ "number": 42, "draft": false, "state": "closed", "head": { "sha": "b".repeat(40) } });
    assert!(is_skip(&d(
        "pull_request",
        &pr_with(json!({ "pull_request": closed }))
    )));
}

#[test]
fn actions_that_are_not_a_new_commit_are_ignored() {
    for action in ["labeled", "edited", "closed", "assigned", "reopened"] {
        assert!(
            is_skip(&d("pull_request", &pr_with(json!({ "action": action })))),
            "{action}"
        );
    }
}

#[test]
fn other_event_types_are_ignored_including_a_bare_push() {
    // push is deliberately NOT handled: it cannot say whether its commits
    // belong to a pull request, let alone whether that pull request is a draft.
    for event in ["push", "issues", "issue_comment", "check_run"] {
        assert!(is_skip(&d(event, &pr())), "{event}");
    }
}

#[test]
fn a_ping_is_skipped_without_looking_like_a_failure() {
    assert!(is_skip(&d("ping", &json!({}))));
}

#[test]
fn a_payload_missing_what_a_review_needs_is_skipped_not_guessed_at() {
    assert!(is_skip(&d(
        "pull_request",
        &pr_with(json!({ "repository": {} }))
    )));
    let headless = json!({ "number": 42, "draft": false, "state": "open", "head": {} });
    assert!(is_skip(&d(
        "pull_request",
        &pr_with(json!({ "pull_request": headless }))
    )));
}

#[test]
fn a_garbage_payload_does_not_panic() {
    assert!(is_skip(&d("pull_request", &Value::Null)));
    assert!(is_skip(&d("pull_request", &json!("nope"))));
}

// --- signature -------------------------------------------------------------

const SECRET: &str = "it's a secret to everybody";

fn sign(secret: &str, body: &str) -> String {
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(body.as_bytes());
    let hex: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("sha256={hex}")
}

#[test]
fn a_known_vector_matches_githubs_documented_example() {
    // The worked example from GitHub's "Validating webhook deliveries".
    let sig = sign("It's a Secret to Everybody", "Hello, World!");
    assert_eq!(
        sig,
        "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
    );
    assert!(verify_signature(
        "It's a Secret to Everybody",
        "Hello, World!",
        Some(&sig)
    ));
}

#[test]
fn a_correctly_signed_body_verifies() {
    let body = pr().to_string();
    assert!(verify_signature(SECRET, &body, Some(&sign(SECRET, &body))));
}

#[test]
fn a_body_altered_after_signing_does_not() {
    let body = pr().to_string();
    let sig = sign(SECRET, &body);
    assert!(!verify_signature(SECRET, &format!("{body} "), Some(&sig)));
}

#[test]
fn a_signature_from_a_different_secret_does_not() {
    let body = pr().to_string();
    assert!(!verify_signature(
        SECRET,
        &body,
        Some(&sign("wrong secret", &body))
    ));
}

#[test]
fn a_missing_or_malformed_signature_header_does_not() {
    let truncated = format!("sha256={}", "a".repeat(63));
    let overlong = format!("sha256={}", "a".repeat(65));
    for header in [
        None,
        Some(""),
        Some("sha1=abcdef"),
        Some("sha256="),
        Some("sha256=nothex!!"),
        Some("abcdef"),
        // right shape, wrong length: a truncated digest must not pass
        Some(truncated.as_str()),
        Some(overlong.as_str()),
    ] {
        assert!(
            !verify_signature(SECRET, "{}", header),
            "header {header:?} must not verify"
        );
    }
}

#[test]
fn an_unset_secret_never_verifies_whatever_is_presented() {
    // Signed with a real secret, checked against none. An empty HMAC key must
    // refuse the delivery rather than quietly authenticate it.
    assert!(!verify_signature("", "{}", Some(&sign(SECRET, "{}"))));
    assert!(!verify_signature("", "{}", Some(&sign("", "{}"))));
}

// --- the HTTP-level ingest --------------------------------------------------

fn hook_cfg() -> Config {
    Config {
        github_webhook_secret: Some(SECRET.into()),
        ..Default::default()
    }
}

#[test]
fn an_unconfigured_webhook_answers_503_not_200() {
    let o = handle_webhook(
        &Config::default(),
        "POST",
        "{}",
        Some("sha256=x"),
        Some("ping"),
    );
    assert_eq!(o.status, 503);
}

#[test]
fn an_unsigned_or_badly_signed_delivery_is_401_and_runs_nothing() {
    let body = pr().to_string();
    for sig in [
        None,
        Some("sha256=deadbeef"),
        Some(sign("other", &body).as_str()),
    ] {
        let o = handle_webhook(&hook_cfg(), "POST", &body, sig, Some("pull_request"));
        assert_eq!(o.status, 401);
        assert!(o.job.is_none());
    }
}

#[test]
fn a_signed_non_json_body_is_400_and_get_is_405() {
    let body = "not json";
    let o = handle_webhook(
        &hook_cfg(),
        "POST",
        body,
        Some(&sign(SECRET, body)),
        Some("ping"),
    );
    assert_eq!(o.status, 400);
    assert_eq!(
        handle_webhook(&hook_cfg(), "GET", "", None, None).status,
        405
    );
}

#[test]
fn a_signed_pull_request_delivery_is_queued_with_202() {
    let body = pr().to_string();
    let o = handle_webhook(
        &hook_cfg(),
        "POST",
        &body,
        Some(&sign(SECRET, &body)),
        Some("pull_request"),
    );
    assert_eq!(o.status, 202);
    assert_eq!(o.body["queued"], "push");
    assert!(matches!(o.job, Some(Decision::Push { .. })));
}

#[test]
fn a_repository_from_any_installation_is_queued() {
    // No worker-side repository list: whoever installs the App chose the
    // repositories, so a delivery from any installed repository is queued.
    let body = pr_with(json!({ "repository": { "full_name": "other/repo" } })).to_string();
    let o = handle_webhook(
        &hook_cfg(),
        "POST",
        &body,
        Some(&sign(SECRET, &body)),
        Some("pull_request"),
    );
    assert_eq!(o.status, 202);
    assert_eq!(o.body["queued"], "push");
    assert_eq!(o.body["repo"], "other/repo");
    assert!(matches!(o.job, Some(Decision::Push { .. })));
}

#[test]
fn a_draft_delivery_is_acknowledged_but_not_queued() {
    let body = pr_with(json!({ "pull_request": draft() })).to_string();
    let o = handle_webhook(
        &hook_cfg(),
        "POST",
        &body,
        Some(&sign(SECRET, &body)),
        Some("pull_request"),
    );
    assert_eq!(o.status, 200);
    assert!(o.job.is_none());
}

// --- summoning by mention --------------------------------------------------
//
// issue_comment introduces a loop that did not exist before. A commit comment
// raises no pull_request event, so the agent could not previously trigger
// itself. The moment it, or any bot, writes its own handle in a comment, it
// can. That is what the Bot guard is for, and it is the test to break first.

fn comment_with(over: Value) -> Value {
    let mut v = json!({
        "action": "created",
        "repository": { "full_name": "nyuchi/web-services" },
        "issue": { "number": 42, "state": "open", "pull_request": { "url": "https://api.github.com/…/pulls/42" } },
        "comment": { "body": "@shamwari please take a look", "author_association": "OWNER", "user": { "login": "bryan", "type": "User" } },
    });
    for (k, val) in over.as_object().unwrap() {
        v[k] = val.clone();
    }
    v
}

fn comment(body: &str, assoc: &str, login: &str, ty: &str) -> Value {
    comment_with(
        json!({ "comment": { "body": body, "author_association": assoc, "user": { "login": login, "type": ty } } }),
    )
}

#[test]
fn a_mention_from_a_maintainer_summons_a_review() {
    match d("issue_comment", &comment_with(json!({}))) {
        Decision::Mention { repo, number, by } => {
            assert_eq!(repo, "nyuchi/web-services");
            assert_eq!(number, 42);
            assert_eq!(by, "bryan");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_bots_comment_never_summons_a_review_even_saying_the_handle() {
    // The loop. If this test goes green while the guard is gone, the agent can
    // summon itself indefinitely and bill every cycle.
    let x = d(
        "issue_comment",
        &comment(
            "@shamwari reviewed this commit",
            "OWNER",
            "shamwari[bot]",
            "Bot",
        ),
    );
    assert!(is_skip(&x));
    assert!(reason(&x).to_lowercase().contains("bot"));
}

#[test]
fn a_commenter_without_write_access_cannot_spend_a_review() {
    for a in ["NONE", "CONTRIBUTOR", "FIRST_TIMER"] {
        assert!(
            is_skip(&d(
                "issue_comment",
                &comment("@shamwari review please", a, "stranger", "User")
            )),
            "{a}"
        );
    }
}

#[test]
fn owner_member_and_collaborator_all_may() {
    for a in ["OWNER", "MEMBER", "COLLABORATOR"] {
        assert!(
            matches!(
                d("issue_comment", &comment("@shamwari", a, "someone", "User")),
                Decision::Mention { .. }
            ),
            "{a}"
        );
    }
}

#[test]
fn the_trigger_associations_are_configurable() {
    let only_owner = vec!["OWNER".to_owned()];
    let x = decide(
        "issue_comment",
        &comment("@shamwari", "MEMBER", "m", "User"),
        DEFAULT_MENTION,
        &only_owner,
    );
    assert!(is_skip(&x));
}

#[test]
fn a_comment_without_the_handle_is_ignored() {
    assert!(is_skip(&d(
        "issue_comment",
        &comment("looks good to me", "OWNER", "bryan", "User")
    )));
}

#[test]
fn a_comment_on_an_issue_is_not_a_pull_request_review() {
    assert!(is_skip(&d(
        "issue_comment",
        &comment_with(json!({ "issue": { "number": 42, "state": "open" } }))
    )));
}

#[test]
fn only_a_newly_created_comment_triggers_never_an_edit() {
    // Otherwise one comment could be re-triggered indefinitely by editing it.
    assert!(is_skip(&d(
        "issue_comment",
        &comment_with(json!({ "action": "edited" }))
    )));
    assert!(is_skip(&d(
        "issue_comment",
        &comment_with(json!({ "action": "deleted" }))
    )));
}

#[test]
fn a_mention_on_a_closed_pull_request_is_skipped() {
    let issue = json!({ "number": 42, "state": "closed", "pull_request": { "url": "x" } });
    assert!(is_skip(&d(
        "issue_comment",
        &comment_with(json!({ "issue": issue }))
    )));
}

#[test]
fn the_handle_matches_as_a_word_not_as_a_substring() {
    assert!(mentions(Some("@shamwari please review"), "@shamwari"));
    assert!(
        mentions(Some("hey @Shamwari"), "@shamwari"),
        "case-insensitive"
    );
    assert!(mentions(Some("(@shamwari)"), "@shamwari"));
    assert!(mentions(Some("@shamwari"), "@shamwari"));
    // These must NOT fire, or every mention of the brand becomes a review.
    assert!(!mentions(Some("see @shamwari-docs"), "@shamwari"));
    assert!(!mentions(
        Some("mail me at bryan@shamwari.com"),
        "@shamwari"
    ));
    assert!(!mentions(Some("shamwari is the brand"), "@shamwari"));
    assert!(!mentions(Some("@shamwariai"), "@shamwari"));
    assert!(!mentions(None, "@shamwari"));
    // A later occurrence still counts when an earlier one is a false match.
    assert!(mentions(
        Some("see @shamwari-docs, then @shamwari please"),
        "@shamwari"
    ));
}

#[test]
fn the_handle_is_configurable_because_the_brand_is() {
    let x = decide(
        "issue_comment",
        &comment("@nyuchi review this", "OWNER", "bryan", "User"),
        "@nyuchi",
        &assoc(),
    );
    assert!(matches!(x, Decision::Mention { .. }));
}
