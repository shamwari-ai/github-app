// The two bounds that decide what this worker can do, and the one thing it
// refuses. These are the guards that matter: everything else is a REST call.

import { test } from "node:test";
import assert from "node:assert/strict";
import type { Env } from "../src/env";
import { createReview, resolveRepo } from "../src/github";

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
