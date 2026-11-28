//! Port of test/origin.test.ts.

use crate::origin::origin_allowed;

#[test]
fn origin_validation_allows_the_resources_own_origin_and_refuses_others() {
    let resource = "https://github.shamwari.ai/mcp";
    assert!(origin_allowed(Some("https://github.shamwari.ai"), resource));
    assert!(!origin_allowed(Some("https://evil.example.com"), resource));
}

#[test]
fn an_absent_origin_is_allowed() {
    // Non-browser MCP clients send none. Rejecting them would break every
    // legitimate caller to guard against an attack only browsers can mount.
    assert!(origin_allowed(None, "https://github.shamwari.ai/mcp"));
}
