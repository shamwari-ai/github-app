// The two pages GitHub sends a person to while the App is being set up.
//
//   GET /github-app/created?code=…   redirect_url of the App manifest flow
//   GET /github-app/installed        setup_url, after an installation
//
// Neither holds or exchanges anything. The manifest `code` is single-use,
// expires in an hour, and turns into the App's private key, webhook secret
// and client secret when exchanged, so the exchange happens on the owner's
// machine (scripts/github-app-convert.sh), straight into 1Password, and never
// here: a Worker that exchanged it would have to hold or log those secrets.
// The code is only echoed back to the browser it was sent to, never logged.

import manifest from "../app-manifest.json";

const CODE = /^[A-Za-z0-9_-]{1,100}$/;

const NEW_APP_URL =
  "https://github.com/organizations/shamwari-ai/settings/apps/new";

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

/**
 * GET /github-app/new: the one-click manifest flow.
 *
 * GitHub's manifest flow is a form POST of the manifest to the org's
 * "new App" URL, so it cannot be a plain link. This page is that form, with
 * app-manifest.json (bundled at build time, so it is exactly the reviewed
 * file) and a random `state`. The person still confirms on GitHub, and only
 * an owner of shamwari-ai can complete it.
 */
export function appNew(): Response {
  const state = crypto.randomUUID();
  return page(
    "Create Shamwari for GitHub",
    "<p>This registers the GitHub App described by " +
      "<code>app-manifest.json</code> under the <b>shamwari-ai</b> " +
      "organisation. GitHub asks you to confirm the name, then returns to " +
      "this host with a one-hour code.</p>" +
      `<form method="post" action="${NEW_APP_URL}?state=${state}">` +
      `<input type="hidden" name="manifest" value="${escapeHtml(JSON.stringify(manifest))}">` +
      `<button type="submit">Create the App on GitHub</button></form>`,
    `form-action https://github.com`,
  );
}

function page(title: string, body: string, extraCsp = ""): Response {
  return new Response(
    `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
      `<meta name="viewport" content="width=device-width,initial-scale=1">` +
      `<meta name="robots" content="noindex">` +
      `<title>${title}</title></head>` +
      `<body style="font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;line-height:1.5">` +
      `<h1>${title}</h1>${body}</body></html>`,
    {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": `default-src 'none'; style-src 'unsafe-inline'${extraCsp ? `; ${extraCsp}` : ""}`,
        "X-Robots-Tag": "noindex",
      },
    },
  );
}

/** The manifest flow's redirect: show the code and the one command to run. */
export function appCreated(url: URL): Response {
  const code = url.searchParams.get("code") ?? "";
  if (!CODE.test(code)) {
    return page(
      "No manifest code",
      "<p>This page is where GitHub returns after creating the App from " +
        "<code>app-manifest.json</code>. It was opened without a valid " +
        "<code>code</code>. Start again from docs/github-app.md.</p>",
    );
  }
  return page(
    "Shamwari for GitHub: App created",
    "<p>Within the hour, on your own machine, signed in to 1Password and " +
      "GitHub, from a clone of shamwari-ai/github-app:</p>" +
      `<pre>scripts/github-app-convert.sh ${code}</pre>` +
      "<p>It exchanges this single-use code for the App's credentials and " +
      "writes them to the 1Password item <code>shamwari-ai/github-app</code> " +
      "without printing them. Then follow the remaining owner steps in " +
      "docs/github-app.md.</p>",
  );
}

/** The App's setup_url: where GitHub sends someone after installing it. */
export function appInstalled(): Response {
  return page(
    "Shamwari for GitHub: installed",
    "<p>The App is installed. It acts only on repositories listed in " +
      "<code>GITHUB_ALLOWED_REPOS</code> (wrangler.toml in " +
      "shamwari-ai/github-app); add a repository there by pull request to " +
      "switch it on.</p>",
  );
}
