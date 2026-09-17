// The two bounds that decide what this worker can do, and the one thing it
// refuses. These are the guards that matter: everything else is a REST call.

import { test } from "node:test";
import assert from "node:assert/strict";
import type { Env } from "../src/env";
import { protectedResourceMetadata } from "../src/auth";
import { createReview, missingPermissions, resolveRepo } from "../src/github";

const env = (over: Partial<Env> = {}): Env =>
  ({
    GITHUB_APP_PRIVATE_KEY: "",
    GITHUB_ALLOWED_REPOS: "nyuchi/web-services,nyuchi/api-gateway",
    ...over,
  }) as Env;

test("an allowlisted repo resolves to owner and name", () => {
  assert.deepEqual(resolveRepo(env(), "nyuchi/api-gateway"), {
    owner: "nyuchi",
    name: "api-gateway",
  });
});

test("the allowlist is case-insensitive", () => {
  assert.deepEqual(resolveRepo(env(), "Nyuchi/API-Gateway"), {
    owner: "Nyuchi",
    name: "API-Gateway",
  });
});

test("a repo outside the allowlist is refused", () => {
  assert.throws(
    () => resolveRepo(env(), "nyuchi/mukoko-platform"),
    /not allowlisted/,
  );
});

test("an unset allowlist denies everything rather than allowing everything", () => {
  // A misconfigured worker should be useless, not open. This is the assertion
  // that keeps a missing env var from becoming org-wide write access.
  assert.throws(
    () =>
      resolveRepo(
        env({ GITHUB_ALLOWED_REPOS: undefined }),
        "nyuchi/api-gateway",
      ),
    /refusing every repo/,
  );
  assert.throws(
    () => resolveRepo(env({ GITHUB_ALLOWED_REPOS: "" }), "nyuchi/api-gateway"),
    /refusing every repo/,
  );
  assert.throws(
    () =>
      resolveRepo(env({ GITHUB_ALLOWED_REPOS: "  ,  " }), "nyuchi/api-gateway"),
    /refusing every repo/,
  );
});

test("a malformed slug is rejected before any call is made", () => {
  assert.throws(
    () =>
      resolveRepo(env({ GITHUB_ALLOWED_REPOS: "api-gateway" }), "api-gateway"),
    /expected owner\/repo/,
  );
});

test("APPROVE is refused, in any casing", async () => {
  // An agent that can approve satisfies a branch protection review
  // requirement on its own, letting code reach a protected branch with no
  // human having read it. This must fail before the allowlist is even
  // consulted, so it cannot be reached by allowlisting a repo.
  for (const event of ["APPROVE", "approve", "Approve"]) {
    await assert.rejects(
      createReview(env(), "nyuchi/api-gateway", 1, {
        event: event as "COMMENT",
        body: "looks good",
      }),
      /does not approve pull requests/,
    );
  }
});

test("an unrecognised review event is refused", async () => {
  await assert.rejects(
    createReview(env(), "nyuchi/api-gateway", 1, {
      event: "MERGE" as "COMMENT",
      body: "x",
    }),
    /unsupported review event/,
  );
});

// --- missingPermissions --------------------------------------------------
//
// This decides whether nyuchi_whoami reports a repository as ready. Its whole
// value is being trusted when a 422 appears, so the read/write asymmetry gets
// pinned rather than assumed.

test("a permission the installation does not hold at all is missing", () => {
  assert.deepEqual(
    missingPermissions(
      { pull_requests: "write", issues: "write" },
      { pull_requests: "write" },
    ),
    ["issues:write"],
  );
});

test("write satisfies a read request", () => {
  assert.deepEqual(
    missingPermissions({ contents: "read" }, { contents: "write" }),
    [],
  );
});

test("read does not satisfy a write request", () => {
  assert.deepEqual(
    missingPermissions({ issues: "write" }, { issues: "read" }),
    ["issues:write"],
  );
});

test("an exact match is not missing", () => {
  assert.deepEqual(
    missingPermissions(
      { pull_requests: "write", contents: "read", metadata: "read" },
      { pull_requests: "write", contents: "read", metadata: "read" },
    ),
    [],
  );
});

test("extra permissions the installation holds are not reported", () => {
  // The App is broader than the token asks for by design — that is the whole
  // point of the scoped mint, so surplus must never read as a problem.
  assert.deepEqual(
    missingPermissions(
      { contents: "read" },
      { contents: "write", workflows: "write", administration: "write" },
    ),
    [],
  );
});

test("an empty installation misses everything requested", () => {
  assert.deepEqual(
    missingPermissions({ pull_requests: "write", issues: "write" }, {}),
    ["pull_requests:write", "issues:write"],
  );
});

// --- protected resource metadata -----------------------------------------

test("the metadata advertises no scopes", () => {
  // Advertising a scope WorkOS does not define is worse than advertising
  // none: the client asks for it, WorkOS returns `error=invalid_scope` to the
  // client's callback, and the user never reaches a login page. This worker
  // gates on organization, role and permission claims, never on scopes.
  //
  // Measured against the live authorization server:
  //   scope=(none)                 -> 302 to the AuthKit login page
  //   scope=openid profile email   -> 302 to the AuthKit login page
  //   scope=github:read            -> 302 ?error=invalid_scope
  const meta = protectedResourceMetadata({
    MCP_RESOURCE_URL: "https://github.nyuchi.dev/mcp",
    WORKOS_AUTHORIZATION_SERVER: "https://accounts.mukoko.com",
  } as Env);
  assert.equal("scopes_supported" in meta, false);
  assert.deepEqual(meta.authorization_servers, ["https://accounts.mukoko.com"]);
  assert.equal(meta.resource, "https://github.nyuchi.dev/mcp");
});
