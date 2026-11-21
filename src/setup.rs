//! The pages GitHub sends a person to while the App is being set up.
//!
//!   GET /github-app/new          the one-click manifest form
//!   GET /github-app/created?code the manifest flow's redirect_url
//!
//! There is deliberately no post-install page: the manifest carries no
//! `setup_url`, so GitHub lands the installer on its own install page, where
//! repository access is actually chosen.
//!
//! None of these pages holds or exchanges anything. The manifest `code` is
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

/// The shared stylesheet. Inline by necessity as much as design: the CSP
/// allows no external resource, so there is nothing to load, track or leak.
/// Light and dark both, through the system palette.
const STYLE: &str = "\
:root { color-scheme: light dark; }\
* { box-sizing: border-box; }\
body {\
  margin: 0; min-height: 100vh; padding: 2rem 1rem 3rem;\
  font: 16px/1.6 system-ui, -apple-system, 'Segoe UI', sans-serif;\
  background: #f6f8fa; color: #1f2328;\
}\
@media (prefers-color-scheme: dark) {\
  body { background: #0d1117; color: #e6edf3; }\
}\
main {\
  max-width: 40rem; margin: 0 auto; padding: 2rem;\
  background: #ffffff; border: 1px solid #d1d9e0; border-radius: 12px;\
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.06);\
}\
@media (prefers-color-scheme: dark) {\
  main { background: #151b23; border-color: #3d444d; box-shadow: none; }\
}\
.brand { display: flex; align-items: center; gap: 0.6rem; margin-bottom: 1.25rem; }\
.brand svg { width: 1.5rem; height: 1.5rem; flex: none; }\
.brand span { font-weight: 600; letter-spacing: -0.01em; }\
h1 { font-size: 1.35rem; line-height: 1.3; margin: 0 0 1rem; }\
p { margin: 0.75rem 0; }\
ul { margin: 0.75rem 0; padding-left: 1.25rem; }\
li { margin: 0.3rem 0; }\
code {\
  font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace;\
  font-size: 0.875em; padding: 0.15em 0.4em; border-radius: 6px;\
  background: rgba(129, 139, 152, 0.18);\
}\
pre {\
  margin: 1rem 0; padding: 1rem; border-radius: 8px; overflow-x: auto;\
  font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace;\
  font-size: 0.875rem; line-height: 1.5;\
  background: #1f2328; color: #e6edf3;\
}\
button {\
  font: inherit; font-weight: 500; cursor: pointer; margin-top: 0.75rem;\
  background: #1f883d; color: #ffffff; border: 1px solid rgba(31, 17, 10, 0.1);\
  border-radius: 8px; padding: 0.55rem 1.1rem;\
}\
button:hover { background: #1a7f37; }\
button:focus-visible { outline: 2px solid #1f883d; outline-offset: 2px; }\
footer { margin-top: 1.5rem; font-size: 0.8rem; text-align: center; color: #6b7280; }\
";

/// The small brand mark: a green circle with a tick, inline SVG so the CSP's
/// `default-src 'none'` stays honest (an <img> would need a source).
const MARK: &str = concat!(
    "<svg viewBox=\"0 0 24 24\" fill=\"none\" aria-hidden=\"true\">",
    "<circle cx=\"12\" cy=\"12\" r=\"10\" stroke=\"#1f883d\" stroke-width=\"2.5\"/>",
    "<path d=\"M8 12.5l2.7 2.7L16.5 9\" stroke=\"#1f883d\" stroke-width=\"2.5\" ",
    "stroke-linecap=\"round\" stroke-linejoin=\"round\"/></svg>",
);

fn page(title: &str, body: &str, extra_csp: &str) -> HtmlResponse {
    let csp = if extra_csp.is_empty() {
        "default-src 'none'; style-src 'unsafe-inline'".to_owned()
    } else {
        format!("default-src 'none'; style-src 'unsafe-inline'; {extra_csp}")
    };
    let title = escape_html(title);
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
            concat!(
                "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
                "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
                "<meta name=\"robots\" content=\"noindex\">",
                "<title>{t}</title><style>{s}</style></head>",
                "<body><main>",
                "<div class=\"brand\">{m}<span>Shamwari</span></div>",
                "<h1>{t}</h1>{b}",
                "</main><footer>github.shamwari.ai — the Shamwari for GitHub App</footer>",
                "</body></html>"
            ),
            t = title,
            s = STYLE,
            m = MARK,
            b = body,
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
under the <b>bundu-labs</b> enterprise: least-privilege permissions, two webhook events, \
installable by anyone. GitHub asks you to confirm the name, then returns to this host with \
a one-hour code that becomes the App's credentials on your machine.</p>\
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
<code>app-manifest.json</code>. It was opened without a valid <code>code</code>: the code \
is single-use and expires an hour after the App is created. Start again from \
docs/enterprise-app-setup.md.</p>",
            "",
        );
    };
    page(
        "Shamwari for GitHub: App created",
        &format!(
            "<p>Within the hour, on your own machine — signed in to 1Password and GitHub, \
from a clone of <code>shamwari-ai/github-app</code> — run:</p>\
<pre>scripts/github-app-convert.sh {code}</pre>\
<p>It exchanges this single-use code for the App's credentials and writes them to the \
1Password item <code>bundu-labs/shamwari-for-github</code> without printing them. Then:</p>\
<ul>\
<li>put the credentials on the Worker: <code>scripts/github-app-convert.sh secrets</code></li>\
<li>follow the remaining owner steps in <code>docs/enterprise-app-setup.md</code></li>\
</ul>",
        ),
        "",
    )
}
