//! Port of test/setup.test.ts: the GitHub App setup pages are public, inert,
//! and never reflect input they have not validated.

use super::*;
use crate::router::{handle, Req};
use crate::setup::{MANIFEST, NEW_APP_URL};

fn get(path: &str) -> crate::router::Resp {
    run(handle(
        &Mock::default(),
        &Config::default(),
        Req {
            method: "GET".into(),
            url: format!("https://github.shamwari.ai{path}"),
            ..Default::default()
        },
    ))
    .resp
}

#[test]
fn the_manifest_redirect_shows_the_convert_command_for_a_valid_code() {
    let res = get("/github-app/created?code=abc_DEF-123");
    assert_eq!(res.status, 200);
    assert_eq!(res.header("Cache-Control"), Some("no-store"));
    assert!(res
        .body
        .contains("scripts/github-app-convert.sh abc_DEF-123"));
}

#[test]
fn an_invalid_code_is_never_echoed() {
    let res = get("/github-app/created?code=%3Cscript%3Ex%3C%2Fscript%3E");
    assert!(!res.body.contains("<script>"));
    assert!(res.body.contains("No manifest code"));
    assert!(get("/github-app/created").body.contains("No manifest code"));
    assert!(
        get(&format!("/github-app/created?code={}", "a".repeat(101)))
            .body
            .contains("No manifest code")
    );
}

#[test]
fn there_is_no_post_install_page_the_installer_stays_on_github() {
    // No setup_url in the manifest: GitHub lands the installer on its own
    // install page, where repository access is chosen.
    let res = get("/github-app/installed");
    assert_eq!(res.status, 404);
}

fn manifest() -> Value {
    serde_json::from_str(MANIFEST).expect("app-manifest.json is valid JSON")
}

#[test]
fn the_app_manifest_is_least_privilege_and_on_the_canonical_host() {
    let m = manifest();
    assert_eq!(
        m["default_permissions"],
        json!({ "metadata": "read", "contents": "read", "checks": "read", "pull_requests": "write", "issues": "write" })
    );
    assert_eq!(
        m["default_events"],
        json!(["pull_request", "issue_comment"])
    );
    assert_eq!(
        m["hook_attributes"]["url"],
        "https://github.shamwari.ai/webhook"
    );
    assert_eq!(m["hook_attributes"]["active"], true);
    assert_eq!(
        m["redirect_url"],
        "https://github.shamwari.ai/github-app/created"
    );
    // No setup_url: GitHub's own install page receives the installer, not
    // this Worker.
    assert!(m.get("setup_url").is_none());
    assert!(m.get("setup_on_update").is_none());
    // No user-to-server OAuth: the App never acts as a person.
    assert_eq!(m["request_oauth_on_install"], false);
    assert!(m.get("callback_urls").is_none());
}

#[test]
fn the_manifest_never_asks_for_workflows_administration_or_contents_write() {
    let perms = manifest()["default_permissions"]
        .as_object()
        .unwrap()
        .clone();
    for banned in ["workflows", "administration", "organization_administration"] {
        assert!(!perms.contains_key(banned), "{banned}");
    }
    assert_eq!(perms["contents"], "read");
}

#[test]
fn the_one_click_page_posts_the_bundled_manifest_to_the_bundu_labs_enterprise() {
    let res = get("/github-app/new");
    assert_eq!(res.status, 200);
    assert!(res
        .header("Content-Security-Policy")
        .unwrap()
        .contains("form-action https://github.com"));
    assert_eq!(
        NEW_APP_URL,
        "https://github.com/enterprises/bundu-labs/settings/apps/new"
    );
    let marker = format!("action=\"{NEW_APP_URL}?state=");
    let i = res
        .body
        .find(&marker)
        .expect("form action targets the enterprise");
    let state = &res.body[i + marker.len()..i + marker.len() + 36];
    assert!(
        state.chars().all(|c| c.is_ascii_hexdigit() || c == '-'),
        "{state}"
    );
    // The organisation URL is gone.
    assert!(!res.body.contains("organizations/shamwari-ai"));
    let v = res
        .body
        .split("name=\"manifest\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let decoded = v
        .replace("&quot;", "\"")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&");
    let m: Value = serde_json::from_str(&decoded).unwrap();
    assert_eq!(m["name"], "Shamwari for GitHub");
    assert_eq!(
        m["hook_attributes"]["url"],
        "https://github.shamwari.ai/webhook"
    );
}

#[test]
fn each_new_page_load_carries_a_fresh_state() {
    let state = |b: &str| b.split("?state=").nth(1).unwrap()[..36].to_owned();
    assert_ne!(
        state(&get("/github-app/new").body),
        state(&get("/github-app/new").body)
    );
}
