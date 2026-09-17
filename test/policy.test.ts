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

// --- tool annotations -----------------------------------------------------
//
// Hints, not enforcement — the real guarantees are the scoped token and
// createReview refusing APPROVE. But a client uses them to show which tools
// write before calling one, so a read tool mislabelled as a write (or worse,
// the reverse) misleads exactly when it matters.

test("every tool carries a full set of annotations", async () => {
  const { TOOLS } = await import("../src/mcp");
  for (const t of TOOLS) {
    assert.ok(t.annotations, `${t.name} has no annotations`);
    for (const k of [
      "readOnlyHint",
      "destructiveHint",
      "idempotentHint",
      "openWorldHint",
    ] as const) {
      assert.equal(
        typeof t.annotations[k],
        "boolean",
        `${t.name}.${k} is not a boolean`,
      );
    }
  }
});

test("the read tools are the ones that read, and nothing else", async () => {
  const { TOOLS } = await import("../src/mcp");
  const readOnly = TOOLS.filter((t) => t.annotations.readOnlyHint)
    .map((t) => t.name)
    .sort();
  assert.deepEqual(readOnly, [
    "nyuchi_get_issue",
    "nyuchi_get_pull_request",
    "nyuchi_get_pull_request_diff",
    "nyuchi_list_issues",
    "nyuchi_list_pull_requests",
    "nyuchi_whoami",
  ]);
});

test("no read-only tool is marked destructive, and no writer is marked read-only", async () => {
  const { TOOLS } = await import("../src/mcp");
  for (const t of TOOLS) {
    if (t.annotations.readOnlyHint) {
      assert.equal(t.annotations.destructiveHint, false, `${t.name}`);
    }
  }
  // The update tools overwrite existing fields; the create tools add.
  const updates = TOOLS.filter((t) => t.annotations.destructiveHint).map(
    (t) => t.name,
  );
  assert.deepEqual(updates.sort(), [
    "nyuchi_update_issue",
    "nyuchi_update_pull_request",
  ]);
});

test("tools/list advertises the annotations, not just the schema", async () => {
  const { handleRpc } = await import("../src/mcp");
  const res = (await handleRpc(
    { jsonrpc: "2.0", id: 1, method: "tools/list" } as never,
    {} as Env,
  )) as { result: { tools: Array<Record<string, unknown>> } };
  assert.ok(res.result.tools.every((t) => t.annotations));
});

// --- list output shaping --------------------------------------------------
//
// The list tools used to return raw GitHub objects. Measured on this
// repository, thirteen pull requests serialised to 276,801 bytes against
// 3,842 shaped — 99% of it structure nothing reads (_links, a full repository
// object per row, the author object repeated). That is context an agent
// cannot spend twice, so the shaping is pinned here.

test("paginate reports another page only when one exists", async () => {
  const { paginate } = await import("../src/github");
  // Callers fetch limit+1; the extra row is the signal, not part of the page.
  const over = paginate([1, 2, 3, 4], 3, 1);
  assert.deepEqual(over.items, [1, 2, 3]);
  assert.equal(over.count, 3);
  assert.equal(over.has_more, true);
  assert.equal(over.next_page, 2);

  const exact = paginate([1, 2, 3], 3, 1);
  assert.equal(exact.has_more, false);
  assert.equal(exact.next_page, undefined);

  const empty = paginate([], 20, 1);
  assert.deepEqual(empty.items, []);
  assert.equal(empty.has_more, false);
});

test("paginate carries the page number through", async () => {
  const { paginate } = await import("../src/github");
  assert.equal(paginate([1, 2], 1, 4).next_page, 5);
});

test("slimPull keeps what a reviewer needs and drops the rest", async () => {
  const { slimPull } = await import("../src/github");
  const raw = {
    number: 12,
    title: "dual-era MCP",
    state: "open",
    draft: false,
    user: { login: "bryanfawcett", id: 1, avatar_url: "…", node_id: "…" },
    base: { ref: "main", repo: { id: 1, owner: {}, permissions: {} } },
    head: { ref: "feat/x", repo: { id: 1, owner: {}, permissions: {} } },
    labels: [{ name: "enhancement", color: "fff", id: 9 }],
    created_at: "2026-09-17T18:00:00Z",
    updated_at: "2026-09-17T19:00:00Z",
    html_url: "https://github.com/nyuchi/web-services/pull/12",
    _links: { self: {}, html: {}, comments: {} },
    body: "x".repeat(5000),
  };
  const slim = slimPull(raw);
  assert.equal(slim.number, 12);
  assert.equal(slim.author, "bryanfawcett");
  assert.equal(slim.base, "main");
  assert.equal(slim.head, "feat/x");
  assert.deepEqual(slim.labels, ["enhancement"]);
  // The expensive parts must not survive.
  for (const k of ["_links", "body", "user"]) {
    assert.equal(k in slim, false, `${k} should not be in the slim shape`);
  }
  assert.ok(JSON.stringify(slim).length < JSON.stringify(raw).length / 5);
});

test("slimIssue flags pull requests returned by the issues endpoint", async () => {
  const { slimIssue } = await import("../src/github");
  // GitHub returns PRs from /issues. A caller that misses this counts them
  // as issues, which is wrong in both directions.
  assert.equal(
    slimIssue({ number: 1, pull_request: { url: "…" } }).is_pull_request,
    true,
  );
  assert.equal(slimIssue({ number: 2 }).is_pull_request, false);
});
