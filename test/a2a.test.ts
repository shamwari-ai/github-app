// The A2A surface.
//
// Weighted towards the wire format, because A2A 1.0 removed the `kind`
// discriminator everywhere and the old shape still looks plausible. A part
// written as `{ kind: 'text', text }` serialises fine, reads fine, and no
// current client parses it — a defect that is invisible until an actual
// agent tries to talk to us.

import { test } from "node:test";
import assert from "node:assert/strict";
import type { Env } from "../src/env";
import {
  A2A_PROTOCOL_VERSION,
  TASK_FAILED,
  TASK_REJECTED,
  agentCard,
  extractTarget,
  handleA2A,
} from "../src/a2a";

const env = () =>
  ({
    WORKOS_AUTHORIZATION_SERVER: "https://accounts.mukoko.com",
  }) as unknown as Env;

const send = (parts: unknown[], over: Record<string, unknown> = {}) => ({
  jsonrpc: "2.0",
  id: 1,
  method: "SendMessage",
  params: { message: { messageId: "m1", role: "ROLE_USER", parts }, ...over },
});

// --- the card -------------------------------------------------------------

test("the card declares the 1.0 protocol version", () => {
  const c = agentCard(env(), "https://github.shamwari.ai");
  assert.equal(c.protocolVersion, A2A_PROTOCOL_VERSION);
  assert.equal(c.url, "https://github.shamwari.ai/a2a");
});

test("the card advertises only what is implemented", () => {
  // An agent card that overstates is worse than a small one: a client
  // believes it and waits for events that never come.
  const c = agentCard(env(), "https://github.shamwari.ai") as Record<
    string,
    Record<string, unknown>
  >;
  assert.equal(c.capabilities.streaming, false);
  assert.equal(c.capabilities.pushNotifications, false);
  assert.equal(c.capabilities.extendedAgentCard, false);
});

test("the security scheme uses the v1.0 member-name discriminator", () => {
  // Not { type: 'openIdConnect' } — 1.0 identifies the scheme by which member
  // is present, exactly as it does for parts.
  const c = agentCard(env(), "https://x.test") as Record<string, never>;
  const schemes = c.securitySchemes as unknown as Record<
    string,
    Record<string, { openIdConnectUrl?: string }>
  >;
  assert.ok(schemes.workos.openIdConnectSecurityScheme);
  assert.match(
    schemes.workos.openIdConnectSecurityScheme.openIdConnectUrl ?? "",
    /accounts\.mukoko\.com\/\.well-known\/openid-configuration/,
  );
});

test("the card says plainly that it cannot approve", () => {
  const c = agentCard(env(), "https://x.test");
  assert.match(String(c.description), /[Cc]annot approve/);
});

// --- finding the pull request --------------------------------------------

test("a data part is read in preference to prose", () => {
  const t = extractTarget({
    message: { parts: [{ data: { repo: "nyuchi/web-services", number: 18 } }] },
  });
  assert.deepEqual([t.repo, t.number], ["nyuchi/web-services", 18]);
});

test("owner/repo#number is understood", () => {
  const t = extractTarget({
    message: { parts: [{ text: "please review nyuchi/web-services#18" }] },
  });
  assert.deepEqual([t.repo, t.number], ["nyuchi/web-services", 18]);
});

test("a looser sentence still resolves", () => {
  const t = extractTarget({
    message: { parts: [{ text: "take a look at nyuchi/api-gateway PR 95" }] },
  });
  assert.deepEqual([t.repo, t.number], ["nyuchi/api-gateway", 95]);
});

test("a bare number is refused rather than guessed at", () => {
  // Guessing the repository would review the wrong thing confidently, which
  // is the failure mode this whole agent is built to avoid.
  const t = extractTarget({ message: { parts: [{ text: "review PR 18" }] } });
  assert.ok(t.error);
  assert.equal(t.repo, undefined);
});

test("a data part naming a repo but no number is an error, not a guess", () => {
  const t = extractTarget({
    message: { parts: [{ data: { repo: "nyuchi/web-services" } }] },
  });
  assert.match(t.error ?? "", /integer `number`/);
});

test("an empty message is refused", () => {
  assert.ok(extractTarget({ message: { parts: [] } }).error);
  assert.ok(extractTarget({}).error);
});

// --- task shape -----------------------------------------------------------

test("an unusable request is REJECTED, not FAILED", async () => {
  // Different facts: rejected means understood and declined; failed means
  // tried and broke. A client retries one and not the other.
  const res = (await handleA2A(
    send([{ text: "review something" }]),
    env(),
  )) as {
    result: { status: { state: string }; id: string; contextId: string };
  };
  assert.equal(res.result.status.state, TASK_REJECTED);
  assert.ok(res.result.id);
  assert.ok(res.result.contextId);
});

test("a Task carries no `kind` field — 1.0 removed the discriminator", async () => {
  const res = (await handleA2A(send([{ text: "nope" }]), env())) as {
    result: Record<string, unknown>;
  };
  assert.equal("kind" in res.result, false);
});

test("a text part is { text }, not { kind, text }", async () => {
  const res = (await handleA2A(send([{ text: "nope" }]), env())) as {
    result: { status: { message: { parts: Record<string, unknown>[] } } };
  };
  const part = res.result.status.message.parts[0];
  assert.ok("text" in part);
  assert.equal("kind" in part, false);
});

test("a caller-supplied contextId is preserved across the exchange", async () => {
  const res = (await handleA2A(
    send([{ text: "nope" }], { contextId: "ctx-123" }),
    env(),
  )) as { result: { contextId: string } };
  assert.equal(res.result.contextId, "ctx-123");
});

test("a review that throws becomes a FAILED task, not a transport error", async () => {
  // No AI binding, so reviewPullRequest throws. A2A expresses that as task
  // state; a JSON-RPC error would tell the client the protocol broke.
  const res = (await handleA2A(
    send([{ text: "review nyuchi/web-services#18" }]),
    { REVIEW_ENABLED: "true" } as unknown as Env,
  )) as { result: { status: { state: string } } };
  assert.equal(res.result.status.state, TASK_FAILED);
});

test("an unknown method is a JSON-RPC error that says what is served", async () => {
  const res = (await handleA2A(
    { jsonrpc: "2.0", id: 1, method: "GetTask", params: {} },
    env(),
  )) as { error: { code: number; message: string } };
  assert.equal(res.error.code, -32601);
  // GetTask is absent on purpose, and the message has to say why rather than
  // let a client conclude its task was lost.
  assert.match(res.error.message, /terminal|SendMessage/);
});

// --- the regexes run on input from whoever holds a token ------------------
//
// CodeQL flagged both of these as polynomial backtracking. The text comes
// from an A2A message, so it is attacker-controlled: an unbounded
// `[\w.-]+\/[\w.-]+` scans quadratically over a long run of dashes that never
// reaches a slash. The quantifiers are bounded to GitHub's own limits (owner
// 39, repo 100) and the text is capped before matching.

test("a pathological input does not hang the extractor", () => {
  // 100k dashes with no slash: the shape that makes an unbounded pattern
  // backtrack. Bounded, this returns immediately.
  const evil = "-".repeat(100_000);
  const started = Date.now();
  const t = extractTarget({ message: { parts: [{ text: evil }] } });
  const ms = Date.now() - started;
  assert.ok(t.error, "should find no pull request");
  assert.ok(ms < 1000, `took ${ms}ms — the bound is not holding`);
});

test("the near-miss shape is fast too", () => {
  // Many dashes, then a slash, then many more: worse for a naive pattern
  // because the prefix can match in many ways before failing.
  const evil = `${"-".repeat(50_000)}/${"-".repeat(50_000)}`;
  const started = Date.now();
  extractTarget({ message: { parts: [{ text: evil }] } });
  const ms = Date.now() - started;
  assert.ok(ms < 1000, `took ${ms}ms — the bound is not holding`);
});

test("bounding the input did not break ordinary references", () => {
  // The fix must not cost the feature. A reference after some preamble still
  // resolves, and one past the 2KB cap is simply not found rather than
  // scanned for.
  const near = extractTarget({
    message: {
      parts: [{ text: `${"word ".repeat(50)}nyuchi/web-services#18` }],
    },
  });
  assert.deepEqual([near.repo, near.number], ["nyuchi/web-services", 18]);

  const far = extractTarget({
    message: {
      parts: [{ text: `${"x".repeat(3000)} nyuchi/web-services#18` }],
    },
  });
  assert.ok(far.error);
});
