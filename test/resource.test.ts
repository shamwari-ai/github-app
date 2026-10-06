// The resource metadata must name the URL it is served from.
//
// RFC 9728 requires `resource` to be the protected resource the client is
// talking to, and MCP clients abandon OAuth when it is not. The worker on
// github.nyuchi.dev advertised "https://github.shmwari.ai/mcp" (a typo in a
// dashboard variable) and every connection failed before reaching a login
// page. These tests pin the rule that makes that impossible: the metadata's
// resource is derived from the request, for every host this worker serves.

import { test } from "node:test";
import assert from "node:assert/strict";
import worker from "../src/index";
import type { Env } from "../src/env";
import { allowedResourceHosts, resourceUrlFor } from "../src/auth";

const env = (over: Partial<Env> = {}): Env =>
  ({
    WORKOS_AUTHORIZATION_SERVER: "https://accounts.mukoko.com",
    MCP_RESOURCE_URL: "https://github.shamwari.ai/mcp",
    MCP_RESOURCE_HOSTS: "github.shamwari.ai,github.nyuchi.dev",
    ...over,
  }) as Env;

async function metadata(url: string, e: Env = env()) {
  const res = await worker.fetch(new Request(url), e, {} as ExecutionContext);
  assert.equal(res.status, 200, url);
  return (await res.json()) as { resource: string };
}

for (const host of ["github.shamwari.ai", "github.nyuchi.dev"]) {
  for (const path of [
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-protected-resource/mcp",
  ]) {
    test(`metadata on ${host}${path} names the served origin`, async () => {
      const meta = await metadata(`https://${host}${path}`);
      assert.equal(meta.resource, `https://${host}/mcp`);
      assert.equal(new URL(meta.resource).origin, `https://${host}`);
    });
  }
}

test("a mistyped MCP_RESOURCE_URL cannot leak into an allowed host's metadata", async () => {
  // The exact misconfiguration found on 2026-10-06.
  const meta = await metadata(
    "https://github.nyuchi.dev/.well-known/oauth-protected-resource",
    env({ MCP_RESOURCE_URL: "https://github.shmwari.ai/mcp" }),
  );
  assert.equal(meta.resource, "https://github.nyuchi.dev/mcp");
});

test("the workers.dev preview names itself", async () => {
  const meta = await metadata(
    "https://staging-shamwari-github-mcp.nyuchi.workers.dev/.well-known/oauth-protected-resource",
  );
  assert.equal(
    meta.resource,
    "https://staging-shamwari-github-mcp.nyuchi.workers.dev/mcp",
  );
});

test("an unknown Host is never reflected; the canonical URL is used", () => {
  assert.equal(
    resourceUrlFor(new Request("https://evil.example/mcp"), env()),
    "https://github.shamwari.ai/mcp",
  );
});

test("hosts are matched case-insensitively and the canonical host is always allowed", () => {
  assert.equal(
    resourceUrlFor(new Request("https://GitHub.Nyuchi.Dev/mcp"), env()),
    "https://github.nyuchi.dev/mcp",
  );
  assert.deepEqual(allowedResourceHosts(env({ MCP_RESOURCE_HOSTS: "" })), [
    "github.shamwari.ai",
  ]);
});

test("the 401 challenge points at the served host's metadata", async () => {
  const res = await worker.fetch(
    new Request("https://github.nyuchi.dev/mcp", {
      method: "POST",
      body: "{}",
    }),
    env(),
    {} as ExecutionContext,
  );
  assert.equal(res.status, 401);
  assert.equal(
    res.headers.get("WWW-Authenticate"),
    'Bearer resource_metadata="https://github.nyuchi.dev/.well-known/oauth-protected-resource"',
  );
});

test("the committed wrangler.toml names only real hosts", async () => {
  // Guards the typo at its source: every configured resource host must be a
  // domain this worker is meant to serve.
  const { readFile } = await import("node:fs/promises");
  const toml = await readFile(
    new URL("../wrangler.toml", import.meta.url),
    "utf8",
  );
  const fromUrls = [...toml.matchAll(/https:\/\/([a-z0-9.-]+)\/mcp/g)].map(
    (m) => m[1],
  );
  const fromList = [...toml.matchAll(/^MCP_RESOURCE_HOSTS = "([^"]*)"/gm)]
    .flatMap((m) => m[1].split(","))
    .map((h) => h.trim());
  const hosts = [...fromUrls, ...fromList];
  assert.ok(hosts.length > 0);
  for (const h of hosts) {
    assert.match(h, /^github\.(shamwari\.ai|nyuchi\.dev)$/, h);
  }
});
