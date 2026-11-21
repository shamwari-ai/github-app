//! The pages GitHub sends a person to while the App is being set up.
//!
//!   GET /github-app/new          the one-click manifest form
//!   GET /github-app/created?code the manifest flow's redirect_url
//!   GET /github-app/installed    setup_url, after an installation
//!
//! None of them holds or exchanges anything. The manifest `code` is
//! single-use, expires in an hour, and turns into the App's private key,
//! webhook secret and client secret when exchanged, so the exchange happens on
//! the owner's machine (`scripts/github-app-convert.sh`), straight into
//! 1Password, and never here: a Worker that exchanged it would have to hold or
//! log those secrets. The code is only echoed back to the browser it was sent
//! to, never logged.

use crate::util::uuid_v4;

/// The reviewed App definition, bundled at build time so the form posts
/// exactly the file in the repository.
pub const MANIFEST: &str = include_str!("../app-manifest.json");

/// Where the manifest form posts: the **bundu-labs enterprise**, which owns
/// the App. GitHub's documentation describes the manifest flow for personal
/// and organisation accounts only; this is the enterprise analogue of those
/// URLs. If GitHub refuses it, register the App by hand
/// (docs/enterprise-app-setup.md, "Manual registration").
pub const NEW_APP_URL: &str = "https://github.com/enterprises/bundu-labs/settings/apps/new";

pub struct HtmlResponse {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    pub body: String,
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// A manifest `code`: 1 to 100 of `[A-Za-z0-9_-]`.
fn valid_code(code: &str) -> bool {
    (1..=100).contains(&code.len())
        && code
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn page(title: &str, body: &str, extra_csp: &str) -> HtmlResponse {
    let csp = if extra_csp.is_empty() {
        "default-src 'none'; style-src 'unsafe-inline'".to_owned()
    } else {
        format!("default-src 'none'; style-src 'unsafe-inline'; {extra_csp}")
    };
    HtmlResponse {
        status: 200,
        headers: vec![
            ("Content-Type", "text/html; charset=utf-8".into()),
            ("Cache-Control", "no-store".into()),
            ("Referrer-Policy", "no-referrer".into()),
            ("Content-Security-Policy", csp),
            ("X-Robots-Tag", "noindex".into()),
        ],
        body: format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<meta name=\"robots\" content=\"noindex\">\
<title>{title}</title></head>\
<body style=\"font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;line-height:1.5\">\
<h1>{title}</h1>{body}</body></html>"
        ),
    }
}

/// GET /github-app/new: the one-click manifest flow.
///
/// GitHub's manifest flow is a form POST of the manifest to the owner's "new
/// App" URL, so it cannot be a plain link. This page is that form, with
/// `app-manifest.json` and a random `state`. The person still confirms on
/// GitHub, and only an owner of the bundu-labs enterprise can complete it.
pub fn app_new() -> HtmlResponse {
    let manifest = serde_json::from_str::<serde_json::Value>(MANIFEST)
        .map(|v| v.to_string())
        .unwrap_or_else(|_| MANIFEST.to_owned());
    page(
        "Create Shamwari for GitHub",
        &format!(
            "<p>This registers the GitHub App described by <code>app-manifest.json</code> \
under the <b>bundu-labs</b> enterprise. GitHub asks you to confirm the name, then returns to \
this host with a one-hour code.</p>\
<form method=\"post\" action=\"{NEW_APP_URL}?state={}\">\
<input type=\"hidden\" name=\"manifest\" value=\"{}\">\
<button type=\"submit\">Create the App on GitHub</button></form>",
            uuid_v4(),
            escape_html(&manifest)
        ),
        "form-action https://github.com",
    )
}

/// The manifest flow's redirect: show the code and the one command to run.
pub fn app_created(code: Option<&str>) -> HtmlResponse {
    let Some(code) = code.filter(|c| valid_code(c)) else {
        return page(
            "No manifest code",
            "<p>This page is where GitHub returns after creating the App from \
<code>app-manifest.json</code>. It was opened without a valid <code>code</code>. \
Start again from docs/enterprise-app-setup.md.</p>",
            "",
        );
    };
    page(
        "Shamwari for GitHub: App created",
        &format!(
            "<p>Within the hour, on your own machine, signed in to 1Password and GitHub, \
from a clone of shamwari-ai/github-app:</p>\
<pre>scripts/github-app-convert.sh {code}</pre>\
<p>It exchanges this single-use code for the App's credentials and writes them to the \
1Password item <code>bundu-labs/shamwari-for-github</code> without printing them. Then follow \
the remaining owner steps in docs/enterprise-app-setup.md.</p>"
        ),
        "",
    )
}

/// The App's setup_url: where GitHub sends someone after installing it.
pub fn app_installed() -> HtmlResponse {
    page(
        "Shamwari for GitHub: installed",
        "<p>The App is installed. It acts only on repositories listed in \
<code>GITHUB_ALLOWED_REPOS</code> (wrangler.toml in shamwari-ai/github-app); add a \
repository there by pull request to switch it on.</p>",
        "",
    )
}
