// The Streamable HTTP binding, exercised through the worker's own fetch
// handler with real RS256 tokens.
//
// The status codes are the point. 2026-07-28 assigns meaning to them — 404
// for an unknown method, 400 for a header mismatch or unsupported version,
// 405 for GET/DELETE — and a client uses them to decide whether the server is
// modern at all. Getting one wrong sends a client down the legacy fallback
// path, which is exactly the class of failure that cost this worker its first
// connection attempt.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, webcrypto } from "node:crypto";
import worker from "../src/index";
import type { Env } from "../src/env";
import { MODERN_VERSION, LEGACY_VERSION } from "../src/protocol";

const ISSUER = "https://accounts.mukoko.com";
const AUDIENCE = "https://github.nyuchi.dev/mcp";
const JWKS_URL = "https://accounts.mukoko.com/oauth2/jwks";
const ORG = "org_01KRDAB894DJF5V38PT5617TV1";
const META = "io.modelcontextprotocol/protocolVersion";

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
});
const pubJwk = publicKey.export({ format: "jwk" }) as Record<string, string>;
const KID = "t1";

const b64url = (b: Buffer | Uint8Array) =>
  Buffer.from(b)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

let TOKEN = "";
const realFetch = globalThis.fetch;

before(async () => {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT", kid: KID };
  const payload = {
    iat: now,
    exp: now + 3600,
    iss: ISSUER,
    aud: AUDIENCE,
    org_id: ORG,
    role: "platform-team",
  };
  const unsigned = `${b64url(Buffer.from(JSON.stringify(header)))}.${b64url(
    Buffer.from(JSON.stringify(payload)),
  )}`;
  const key = await webcrypto.subtle.importKey(
    "pkcs8",
    privateKey.export({ type: "pkcs8", format: "der" }) as Uint8Array,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await webcrypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(unsigned),
  );
  TOKEN = `${unsigned}.${b64url(new Uint8Array(sig))}`;

  globalThis.fetch = (async (url: string) => {
    if (String(url) === JWKS_URL) {
      return new Response(
        JSON.stringify({
          keys: [{ ...pubJwk, kid: KID, alg: "RS256", use: "sig" }],
        }),
        { status: 200 },
      );
    }
    // Nothing in these tests should reach GitHub; if something does, fail
    // loudly rather than silently making a network call.
    throw new Error(`unexpected fetch: ${url}`);
  }) as typeof fetch;
});
after(() => {
  globalThis.fetch = realFetch;
});

const env = (): Env =>
  ({
    WORKOS_JWKS_URL: JWKS_URL,
    WORKOS_ISSUER: ISSUER,
    WORKOS_AUDIENCE: AUDIENCE,
    WORKOS_ORG_ID: ORG,
    WORKOS_REQUIRED_ROLES: "platform-team",
    WORKOS_REQUIRED_PERMISSIONS: "mongodb:access",
    MCP_RESOURCE_URL: AUDIENCE,
    GITHUB_ALLOWED_REPOS: "nyuchi/web-services",
  }) as Env;

async function call(
  body: unknown,
  headers: Record<string, string> = {},
  method = "POST",
) {
  const req = new Request("https://github.nyuchi.dev/mcp", {
    method,
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      Authorization: `Bearer ${TOKEN}`,
      ...headers,
    },
    ...(method === "POST" ? { body: JSON.stringify(body) } : {}),
  });
  const res = await worker.fetch(req, env());
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

const modern = (method: string, params: Record<string, unknown> = {}) => ({
  jsonrpc: "2.0",
  id: 1,
  method,
  params: { ...params, _meta: { [META]: MODERN_VERSION } },
});

const modernHeaders = (method: string, extra: Record<string, string> = {}) => ({
  "MCP-Protocol-Version": MODERN_VERSION,
  "Mcp-Method": method,
  ...extra,
});

// --- transport-level -------------------------------------------------------

test("GET and DELETE on the MCP endpoint are 405", async () => {
  // Protocol-level sessions and the standalone GET stream were removed in
  // 2026-07-28.
  assert.equal((await call(null, {}, "GET")).status, 405);
  assert.equal((await call(null, {}, "DELETE")).status, 405);
});

test("a foreign Origin is refused with 403", async () => {
  const r = await call(modern("server/discover"), {
    ...modernHeaders("server/discover"),
    Origin: "https://evil.example.com",
  });
  assert.equal(r.status, 403);
});

test("the resource's own Origin is allowed", async () => {
  const r = await call(modern("server/discover"), {
    ...modernHeaders("server/discover"),
    Origin: "https://github.nyuchi.dev",
  });
  assert.equal(r.status, 200);
});

// --- modern era ------------------------------------------------------------

test("server/discover returns supported versions, capabilities and identity", async () => {
  const r = await call(
    modern("server/discover"),
    modernHeaders("server/discover"),
  );
  assert.equal(r.status, 200);
  assert.deepEqual(r.body.result.supportedVersions, [MODERN_VERSION]);
  assert.equal(r.body.result.resultType, "complete");
  assert.ok(r.body.result.capabilities.tools);
  assert.ok(r.body.result._meta["io.modelcontextprotocol/serverInfo"].name);
});

test("an unknown method is 404, not 200", async () => {
  // The JSON-RPC body is what distinguishes this from a 404 served by a URL
  // that is not an MCP endpoint at all.
  const r = await call(modern("nope/nope"), modernHeaders("nope/nope"));
  assert.equal(r.status, 404);
  assert.equal(r.body.error.code, -32601);
});

test("a missing Mcp-Method header is 400 with HeaderMismatch", async () => {
  const r = await call(modern("tools/list"), {
    "MCP-Protocol-Version": MODERN_VERSION,
  });
  assert.equal(r.status, 400);
  assert.equal(r.body.error.code, -32020);
});

test("an unsupported version is 400 with the supported list", async () => {
  const body = {
    jsonrpc: "2.0",
    id: 1,
    method: "tools/list",
    params: { _meta: { [META]: "1900-01-01" } },
  };
  const r = await call(body, {
    "MCP-Protocol-Version": "1900-01-01",
    "Mcp-Method": "tools/list",
  });
  assert.equal(r.status, 400);
  assert.equal(r.body.error.code, -32022);
  assert.deepEqual(r.body.error.data.supported, [MODERN_VERSION]);
});

test("tools/list works on the modern path", async () => {
  const r = await call(modern("tools/list"), modernHeaders("tools/list"));
  assert.equal(r.status, 200);
  assert.ok(r.body.result.tools.length > 0);
});

// --- legacy era ------------------------------------------------------------

test("initialize still answers with the legacy revision", async () => {
  // The regression that matters: a client that connected before this change
  // must keep connecting after it.
  const r = await call({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {},
  });
  assert.equal(r.status, 200);
  assert.equal(r.body.result.protocolVersion, LEGACY_VERSION);
});

test("a legacy request carries no headers and is not version-validated", async () => {
  const r = await call({ jsonrpc: "2.0", id: 2, method: "tools/list" });
  assert.equal(r.status, 200);
  assert.ok(r.body.result.tools.length > 0);
});

test("an unknown method stays 200 for a legacy client", async () => {
  // Legacy clients read the JSON-RPC error, not the HTTP status; returning
  // 404 to them would look like the endpoint had vanished.
  const r = await call({ jsonrpc: "2.0", id: 3, method: "nope/nope" });
  assert.equal(r.status, 200);
  assert.equal(r.body.error.code, -32601);
});

// --- auth still gates everything ------------------------------------------

test("no bearer token is still 401, whatever the era", async () => {
  const req = new Request("https://github.nyuchi.dev/mcp", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...modernHeaders("tools/list"),
    },
    body: JSON.stringify(modern("tools/list")),
  });
  const res = await worker.fetch(req, env());
  assert.equal(res.status, 401);
});

// --- error responses do not leak internals --------------------------------

test("an unexpected error is logged, not returned", async () => {
  // CodeQL: "information exposure through a stack trace". An arbitrary
  // exception's message can carry internal paths or upstream detail; only
  // GitHubError messages are written here deliberately for the caller.
  const { internalError } = await import("../src/index");
  const boom = new Error("ENOENT: /srv/secret/config.json line 42");
  const res = internalError(1, boom);
  const body = (await res.json()) as { error: { message: string } };
  assert.equal(res.status, 500);
  assert.equal(body.error.message, "internal error");
  assert.doesNotMatch(body.error.message, /ENOENT|secret|config\.json/);
});

test("a GitHubError message is returned, because it is written for the caller", async () => {
  const { internalError } = await import("../src/index");
  const { GitHubError } = await import("../src/github");
  const res = internalError(
    1,
    new GitHubError("repo not allowlisted", 403, null),
  );
  const body = (await res.json()) as { error: { message: string } };
  assert.equal(res.status, 502);
  assert.equal(body.error.message, "repo not allowlisted");
});
