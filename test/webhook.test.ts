// Webhook ingest.
//
// Two rules carry the weight here. Nothing runs on a draft pull request, and
// nothing runs on a delivery that is not signed. Both are cheap to assert and
// expensive to get wrong: the first bills model calls against work nobody has
// asked anyone to look at, the second lets a stranger bill them.

import { test } from "node:test";
import assert from "node:assert/strict";
import { decide, mentions, verifySignature } from "../src/webhook";

const pr = (over: Record<string, unknown> = {}) => ({
  action: "synchronize",
  before: "a".repeat(40),
  after: "b".repeat(40),
  repository: { full_name: "nyuchi/web-services" },
  pull_request: {
    number: 42,
    draft: false,
    state: "open",
    head: { sha: "b".repeat(40) },
  },
  ...over,
});

// --- the draft rule -------------------------------------------------------

test("a draft pull request is not reviewed", () => {
  const d = decide(
    "pull_request",
    pr({
      pull_request: {
        number: 42,
        draft: true,
        state: "open",
        head: { sha: "b".repeat(40) },
      },
    }),
  );
  assert.equal(d.run, "skip");
  assert.match(d.run === "skip" ? d.reason : "", /draft/);
});

test("a draft is skipped on every action, not only on synchronize", () => {
  for (const action of ["synchronize", "opened", "ready_for_review"]) {
    const d = decide(
      "pull_request",
      pr({
        action,
        pull_request: {
          number: 42,
          draft: true,
          state: "open",
          head: { sha: "b".repeat(40) },
        },
      }),
    );
    assert.equal(d.run, "skip", `${action} should skip a draft`);
  }
});

test("leaving draft reviews the WHOLE pull request, not just the last push", () => {
  // The consequence of skipping drafts: everything pushed while the pull
  // request was a draft has never been read. Reviewing only the final push
  // would review the last typo fix and call the branch clean.
  const d = decide("pull_request", pr({ action: "ready_for_review" }));
  assert.equal(d.run, "full");
});

// --- what triggers a review ----------------------------------------------

test("a push onto an open, non-draft pull request reviews that push", () => {
  const d = decide("pull_request", pr());
  assert.equal(d.run, "push");
  if (d.run === "push") {
    assert.equal(d.before, "a".repeat(40));
    assert.equal(d.after, "b".repeat(40));
    assert.equal(d.number, 42);
    assert.equal(d.repo, "nyuchi/web-services");
  }
});

test("opening a ready pull request reviews the whole thing", () => {
  const d = decide("pull_request", pr({ action: "opened" }));
  assert.equal(d.run, "full");
});

test("an all-zero before sha falls back to the full diff", () => {
  // A branch's first push has no predecessor to compare against.
  const d = decide("pull_request", pr({ before: "0".repeat(40) }));
  assert.equal(d.run, "full");
});

test("a closed pull request is not reviewed on a late delivery", () => {
  const d = decide(
    "pull_request",
    pr({
      pull_request: {
        number: 42,
        draft: false,
        state: "closed",
        head: { sha: "b".repeat(40) },
      },
    }),
  );
  assert.equal(d.run, "skip");
});

test("actions that are not a new commit are ignored", () => {
  for (const action of [
    "labeled",
    "edited",
    "closed",
    "assigned",
    "reopened",
  ]) {
    assert.equal(decide("pull_request", pr({ action })).run, "skip", action);
  }
});

test("other event types are ignored, including a bare push", () => {
  // push is deliberately NOT handled: it cannot say whether its commits
  // belong to a pull request, let alone whether that pull request is a draft.
  for (const event of ["push", "issues", "issue_comment", "check_run"]) {
    assert.equal(decide(event, pr()).run, "skip", event);
  }
});

test("a ping is skipped without looking like a failure", () => {
  assert.equal(decide("ping", {}).run, "skip");
});

test("a payload missing what a review needs is skipped, not guessed at", () => {
  assert.equal(decide("pull_request", pr({ repository: {} })).run, "skip");
  assert.equal(
    decide(
      "pull_request",
      pr({
        pull_request: { number: 42, draft: false, state: "open", head: {} },
      }),
    ).run,
    "skip",
  );
});

test("a garbage payload does not throw", () => {
  assert.equal(decide("pull_request", null).run, "skip");
  assert.equal(decide("pull_request", "nope").run, "skip");
});

// --- signature ------------------------------------------------------------

const SECRET = "it's a secret to everybody";

async function sign(secret: string, body: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const mac = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(body),
  );
  return (
    "sha256=" +
    [...new Uint8Array(mac)]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
  );
}

test("a correctly signed body verifies", async () => {
  const body = JSON.stringify(pr());
  assert.equal(
    await verifySignature(SECRET, body, await sign(SECRET, body)),
    true,
  );
});

test("a body altered after signing does not", async () => {
  const body = JSON.stringify(pr());
  const sig = await sign(SECRET, body);
  assert.equal(await verifySignature(SECRET, body + " ", sig), false);
});

test("a signature from a different secret does not", async () => {
  const body = JSON.stringify(pr());
  assert.equal(
    await verifySignature(SECRET, body, await sign("wrong secret", body)),
    false,
  );
});

test("a missing or malformed signature header does not", async () => {
  const body = "{}";
  for (const header of [
    null,
    "",
    "sha1=abcdef",
    "sha256=",
    "sha256=nothex!!",
    "abcdef",
    // right shape, wrong length — a truncated digest must not pass
    "sha256=" + "a".repeat(63),
    "sha256=" + "a".repeat(65),
  ]) {
    assert.equal(
      await verifySignature(SECRET, body, header),
      false,
      `header ${JSON.stringify(header)} must not verify`,
    );
  }
});

test("an unset secret never verifies, whatever is presented", async () => {
  // Signed with a real secret, checked against none. The guard has to return
  // before importKey: WebCrypto rejects a zero-length HMAC key outright, so
  // without the guard an unconfigured worker would throw on every delivery
  // rather than refuse it.
  const body = "{}";
  assert.equal(
    await verifySignature("", body, await sign(SECRET, body)),
    false,
  );
});

// --- summoning by mention -------------------------------------------------
//
// issue_comment introduces a loop that did not exist before. A commit comment
// raises no pull_request event, so the agent could not previously trigger
// itself. The moment it — or any bot — writes its own handle in a comment, it
// can. That is what the Bot guard is for, and it is the test to break first.

const comment = (over: Record<string, unknown> = {}) => ({
  action: "created",
  repository: { full_name: "nyuchi/web-services" },
  issue: {
    number: 42,
    state: "open",
    pull_request: { url: "https://api.github.com/…/pulls/42" },
  },
  comment: {
    body: "@shamwari please take a look",
    author_association: "OWNER",
    user: { login: "bryan", type: "User" },
  },
  ...over,
});

test("a mention from a maintainer summons a review", () => {
  const d = decide("issue_comment", comment());
  assert.equal(d.run, "mention");
  if (d.run === "mention") {
    assert.equal(d.repo, "nyuchi/web-services");
    assert.equal(d.number, 42);
    assert.equal(d.by, "bryan");
  }
});

test("a bot's comment NEVER summons a review, even saying the handle", () => {
  // The loop. If this test goes green while the guard is gone, the agent can
  // summon itself indefinitely and bill every cycle.
  const d = decide(
    "issue_comment",
    comment({
      comment: {
        body: "@shamwari reviewed this commit",
        author_association: "OWNER",
        user: { login: "shamwari[bot]", type: "Bot" },
      },
    }),
  );
  assert.equal(d.run, "skip");
  assert.match(d.run === "skip" ? d.reason : "", /bot/i);
});

test("a commenter without write access cannot spend a review", () => {
  for (const author_association of ["NONE", "CONTRIBUTOR", "FIRST_TIMER"]) {
    const d = decide(
      "issue_comment",
      comment({
        comment: {
          body: "@shamwari review please",
          author_association,
          user: { login: "stranger", type: "User" },
        },
      }),
    );
    assert.equal(d.run, "skip", author_association);
  }
});

test("OWNER, MEMBER and COLLABORATOR all may", () => {
  for (const author_association of ["OWNER", "MEMBER", "COLLABORATOR"]) {
    const d = decide(
      "issue_comment",
      comment({
        comment: {
          body: "@shamwari",
          author_association,
          user: { login: "someone", type: "User" },
        },
      }),
    );
    assert.equal(d.run, "mention", author_association);
  }
});

test("a comment without the handle is ignored", () => {
  const d = decide(
    "issue_comment",
    comment({
      comment: {
        body: "looks good to me",
        author_association: "OWNER",
        user: { login: "bryan", type: "User" },
      },
    }),
  );
  assert.equal(d.run, "skip");
});

test("a comment on an issue is not a pull request review", () => {
  const d = decide(
    "issue_comment",
    comment({ issue: { number: 42, state: "open" } }),
  );
  assert.equal(d.run, "skip");
});

test("only a newly created comment triggers, never an edit", () => {
  // Otherwise one comment could be re-triggered indefinitely by editing it.
  assert.equal(
    decide("issue_comment", comment({ action: "edited" })).run,
    "skip",
  );
  assert.equal(
    decide("issue_comment", comment({ action: "deleted" })).run,
    "skip",
  );
});

test("the handle matches as a word, not as a substring", () => {
  assert.equal(mentions("@shamwari please review", "@shamwari"), true);
  assert.equal(
    mentions("hey @Shamwari", "@shamwari"),
    true,
    "case-insensitive",
  );
  assert.equal(mentions("(@shamwari)", "@shamwari"), true);
  // These must NOT fire, or every mention of the brand becomes a review.
  assert.equal(mentions("see @shamwari-docs", "@shamwari"), false);
  assert.equal(mentions("mail me at bryan@shamwari.com", "@shamwari"), false);
  assert.equal(mentions("shamwari is the brand", "@shamwari"), false);
  assert.equal(mentions("@shamwariai", "@shamwari"), false);
  assert.equal(mentions(undefined, "@shamwari"), false);
});

test("the handle is configurable, because the brand is", () => {
  const d = decide(
    "issue_comment",
    comment({
      comment: {
        body: "@nyuchi review this",
        author_association: "OWNER",
        user: { login: "bryan", type: "User" },
      },
    }),
    "@nyuchi",
  );
  assert.equal(d.run, "mention");
});
