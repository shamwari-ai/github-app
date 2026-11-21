//! Origin validation for the MCP endpoint (DNS-rebinding defence).

use url::Url;

/// Whether an Origin header is acceptable.
///
/// An absent Origin is allowed: non-browser MCP clients send none, and
/// rejecting them would break every legitimate caller to guard against an
/// attack only browsers can mount.
pub fn origin_allowed(origin: Option<&str>, resource_url: &str) -> bool {
    let Some(origin) = origin.filter(|o| !o.is_empty()) else {
        return true;
    };
    match Url::parse(resource_url) {
        Ok(u) => u.origin().ascii_serialization() == origin,
        Err(_) => false,
    }
}
