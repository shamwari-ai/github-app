// The GitHub App setup pages: public, inert, and never reflecting input
// they have not validated.

import { test } from "node:test";
import assert from "node:assert/strict";
import worker from "../src/index";
import type { Env } from "../src/env";

const get = (path: string) =>
  worker.fetch(
    new Request(`https://github.shamwari.ai${path}`),
    {} as Env,
    {} as ExecutionContext,
  );

void test("the manifest redirect shows the convert command for a valid code", async () => {
  const res = await get("/github-app/created?code=abc_DEF-123");
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("Cache-Control"), "no-store");
  const html = await res.text();
  assert.match(html, /scripts\/github-app-convert\.sh abc_DEF-123/);
});

void test("an invalid code is never echoed", async () => {
  const res = await get(
    "/github-app/created?code=" + encodeURIComponent("<script>x</script>"),
  );
  const html = await res.text();
  assert.doesNotMatch(html, /<script>/);
  assert.match(html, /No manifest code/);
});

void test("the post-install page is served", async () => {
  const res = await get("/github-app/installed");
  assert.equal(res.status, 200);
  assert.match(await res.text(), /GITHUB_ALLOWED_REPOS/);
});

void test("the app manifest is least-privilege and on the canonical host", async () => {
  const { readFile } = await import("node:fs/promises");
  const manifest = JSON.parse(
    await readFile(new URL("../app-manifest.json", import.meta.url), "utf8"),
  ) as Record<string, unknown>;
  assert.deepEqual(manifest.default_permissions, {
    metadata: "read",
    contents: "read",
    checks: "read",
    pull_requests: "write",
    issues: "write",
  });
  assert.deepEqual(manifest.default_events, ["pull_request", "issue_comment"]);
  const hook = manifest.hook_attributes as { url: string; active: boolean };
  assert.equal(hook.url, "https://github.shamwari.ai/webhook");
  assert.equal(
    manifest.redirect_url,
    "https://github.shamwari.ai/github-app/created",
  );
  assert.equal(
    manifest.setup_url,
    "https://github.shamwari.ai/github-app/installed",
  );
  // No user-to-server OAuth: the App never acts as a person.
  assert.equal(manifest.request_oauth_on_install, false);
  assert.equal("callback_urls" in manifest, false);
});

void test("the one-click page posts the bundled manifest to the shamwari-ai org", async () => {
  const res = await get("/github-app/new");
  assert.equal(res.status, 200);
  assert.match(
    res.headers.get("Content-Security-Policy") ?? "",
    /form-action https:\/\/github\.com/,
  );
  const html = await res.text();
  assert.match(
    html,
    /action="https:\/\/github\.com\/organizations\/shamwari-ai\/settings\/apps\/new\?state=[0-9a-f-]{36}"/,
  );
  const value = /name="manifest" value="([^"]*)"/.exec(html)?.[1] ?? "";
  const decoded = value
    .replace(/&quot;/g, '"')
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
  const m = JSON.parse(decoded) as {
    name: string;
    hook_attributes: { url: string };
  };
  assert.equal(m.name, "Shamwari for GitHub");
  assert.equal(m.hook_attributes.url, "https://github.shamwari.ai/webhook");
});
