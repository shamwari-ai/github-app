// GitHub webhook ingest — the autonomous half of the review agent.
//
// The rule this implements: a review runs after a commit, its output goes in
// a comment on that commit, and nothing runs on a draft pull request.
//
// "Nothing runs on a draft" has a consequence that is easy to miss and is
// handled here: everything pushed while a pull request was a draft is never
// read, so leaving draft has to review the whole pull request rather than
// only the last push. Otherwise marking a long-lived draft ready gets you a
// review of its final typo fix and nothing else.

import type { Env } from "./env";
import { splitCsv } from "./env";
import { getPullRequestHead } from "./github";
import { reviewPullRequest, reviewPush } from "./review";

/**
 * The handle that summons a review, e.g. "@shamwari".
 *
 * Configurable because this agent is heading for a brand of its own, and the
 * handle people type is the most visible thing about it — it should not need
 * a code change to follow the product.
 */
export const DEFAULT_MENTION = "@shamwari";

/**
 * Who may summon a review by mention.
 *
 * GitHub states the commenter's relationship to the repository in the
 * payload, so this costs no extra call. It matters more than it looks: on a
 * public repository ANYONE can comment, and without this gate a stranger
 * typing the handle repeatedly bills model calls to the repository owner. The
 * default is the three associations that mean "has write access or owns the
 * place".
 */
export const DEFAULT_TRIGGER_ASSOCIATIONS = ["OWNER", "MEMBER", "COLLABORATOR"];

/** What a delivery should cause. Pure, so the rules are testable. */
export type Decision =
  | { run: "push"; repo: string; number: number; before: string; after: string }
  | { run: "full"; repo: string; number: number; head: string }
  | { run: "mention"; repo: string; number: number; by: string }
  | { run: "skip"; reason: string };

const REVIEWED_ACTIONS = new Set(["synchronize", "opened", "ready_for_review"]);

/**
 * Decide what a delivery means.
 *
 * `pull_request` rather than `push`, for two reasons. A raw push event does
 * not know whether its commits belong to a pull request, let alone whether
 * that pull request is a draft — answering either would cost a lookup per
 * push, including for branches with no pull request at all. And
 * `synchronize` carries `before` and `after`, which is exactly the range
 * "after a commit" means.
 */
export function decide(
  event: string,
  payload: unknown,
  mention = DEFAULT_MENTION,
  allowedAssociations = DEFAULT_TRIGGER_ASSOCIATIONS,
): Decision {
  if (event === "ping") return { run: "skip", reason: "ping" };
  if (event === "issue_comment") {
    const d = decideMention(payload, mention);
    // Checked after the mention matched, so an ordinary comment from an
    // outside contributor is "no mention" rather than "not permitted" — the
    // gate should be invisible to everyone not trying to use the handle.
    if (d.run === "mention" && !mayTrigger(payload, allowedAssociations)) {
      return { run: "skip", reason: "commenter may not trigger a review" };
    }
    return d;
  }
  if (event !== "pull_request") {
    return { run: "skip", reason: `event not handled: ${event}` };
  }

  const p = (payload ?? {}) as Record<string, unknown>;
  const action = typeof p.action === "string" ? p.action : "";
  if (!REVIEWED_ACTIONS.has(action)) {
    return { run: "skip", reason: `action not handled: ${action || "(none)"}` };
  }

  const pr = (p.pull_request ?? {}) as Record<string, unknown>;

  // THE DRAFT RULE. Checked before anything is fetched or spent, and checked
  // on the payload rather than on a later lookup, so a pull request that is
  // marked ready mid-delivery cannot slip a draft review through.
  if (pr.draft === true) {
    return { run: "skip", reason: "draft pull request" };
  }

  // A closed or merged pull request can still emit synchronize on a race.
  if (pr.state && pr.state !== "open") {
    return { run: "skip", reason: `pull request is ${String(pr.state)}` };
  }

  const repo = (p.repository as { full_name?: string } | undefined)?.full_name;
  const number = typeof pr.number === "number" ? pr.number : NaN;
  const head = (pr.head as { sha?: string } | undefined)?.sha;

  if (!repo || !Number.isInteger(number) || !head) {
    return {
      run: "skip",
      reason: "payload missing repository, number or head",
    };
  }

  const before = typeof p.before === "string" ? p.before : "";
  const after = typeof p.after === "string" ? p.after : "";

  // A push onto an open, non-draft pull request: read what just arrived.
  if (action === "synchronize" && before && after && !isZero(before)) {
    return { run: "push", repo, number, before, after };
  }

  // Opened, or leaving draft: read the whole thing. On ready_for_review this
  // is the catch-up for every commit the draft rule skipped.
  return { run: "full", repo, number, head };
}

const isZero = (sha: string) => /^0{7,40}$/.test(sha);

/**
 * Does this text summon the agent?
 *
 * Word-boundary matched and case-insensitive, so "@shamwari" fires and
 * "@shamwari-docs" or "email@shamwari.com" do not. A bare substring search
 * would make every mention of the brand a review request.
 */
export function mentions(body: unknown, handle: string): boolean {
  if (typeof body !== "string" || !body) return false;
  const h = handle.replace(/^@/, "");
  return new RegExp(`(^|[^\\w@/-])@${escapeRe(h)}(?![\\w-])`, "i").test(body);
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * A comment asking for a review.
 *
 * Two guards do the real work here.
 *
 * THE LOOP. Until now there was none to guard: a commit comment raises no
 * pull_request event, so the agent could not trigger itself. issue_comment
 * changes that — the moment this agent (or any bot) writes its own handle in
 * a comment, it summons itself, and nothing in the flow would stop it. So
 * every comment from a Bot account is ignored, full stop.
 *
 * THE DRAFT RULE DOES NOT APPLY. Automatic review skips drafts because
 * nobody asked for it. Here somebody did, by name. Refusing a person who has
 * explicitly requested a review of their work in progress would be obeying
 * the letter of the rule against its entire purpose — the rule exists to stop
 * unasked-for noise, and this is the opposite of unasked-for.
 */
function decideMention(payload: unknown, mention: string): Decision {
  const p = (payload ?? {}) as Record<string, unknown>;
  if (p.action !== "created") {
    // "edited" is excluded deliberately: editing a comment to add the handle
    // would let one comment be re-triggered indefinitely.
    return {
      run: "skip",
      reason: `comment action not handled: ${String(p.action)}`,
    };
  }

  const comment = (p.comment ?? {}) as Record<string, unknown>;
  const user = (comment.user ?? {}) as Record<string, unknown>;

  if (user.type === "Bot") {
    return { run: "skip", reason: "comment is from a bot" };
  }
  if (!mentions(comment.body, mention)) {
    return { run: "skip", reason: "no mention" };
  }

  const issue = (p.issue ?? {}) as Record<string, unknown>;
  if (!issue.pull_request) {
    return {
      run: "skip",
      reason: "comment is on an issue, not a pull request",
    };
  }
  if (issue.state && issue.state !== "open") {
    return { run: "skip", reason: `pull request is ${String(issue.state)}` };
  }

  const repo = (p.repository as { full_name?: string } | undefined)?.full_name;
  const number = typeof issue.number === "number" ? issue.number : NaN;
  if (!repo || !Number.isInteger(number)) {
    return { run: "skip", reason: "payload missing repository or number" };
  }

  return {
    run: "mention",
    repo,
    number,
    by: typeof user.login === "string" ? user.login : "",
  };
}

/** Is this commenter allowed to spend a review? */
export function mayTrigger(
  payload: unknown,
  allowed: string[] = DEFAULT_TRIGGER_ASSOCIATIONS,
): boolean {
  const c = ((payload as Record<string, unknown> | null)?.comment ??
    {}) as Record<string, unknown>;
  const assoc =
    typeof c.author_association === "string" ? c.author_association : "";
  return allowed.includes(assoc);
}

/**
 * Verify GitHub's HMAC-SHA256 signature over the raw body.
 *
 * crypto.subtle.verify rather than a string comparison: the comparison is
 * constant-time, so a signature cannot be recovered a byte at a time by
 * timing the response. The raw body text must be the bytes GitHub signed,
 * which is why the caller reads text() once and parses it afterwards rather
 * than json()-ing the request and re-serialising.
 */
export async function verifySignature(
  secret: string,
  rawBody: string,
  header: string | null,
): Promise<boolean> {
  if (!secret || !header) return false;
  const [scheme, hex] = header.split("=");
  if (scheme !== "sha256" || !hex || !/^[0-9a-f]+$/i.test(hex)) return false;
  // A stated precondition, not the thing that makes this safe: a digest of
  // the wrong length yields the wrong bytes and fails the comparison anyway.
  // Removing this line leaves every test in webhook.test.ts green.
  if (hex.length !== 64) return false;

  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++)
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify(
    "HMAC",
    key,
    bytes,
    new TextEncoder().encode(rawBody),
  );
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });

/**
 * Handle one delivery.
 *
 * Answers GitHub immediately and does the review in waitUntil. A review is a
 * model call over a diff and takes far longer than the ten seconds GitHub
 * allows a webhook to respond in, so the work cannot happen inline.
 *
 * The honest limit: waitUntil has no retry and no backpressure. If the worker
 * is evicted mid-review, that review is lost — the commit simply never gets a
 * comment, which is a visible absence rather than a silent wrong answer, and
 * re-requesting the delivery from GitHub's UI re-runs it. Cloudflare Queues
 * is the upgrade when review volume justifies provisioning one.
 */
export async function handleWebhook(
  request: Request,
  env: Env,
  ctx: { waitUntil(p: Promise<unknown>): void },
): Promise<Response> {
  if (request.method !== "POST") {
    return json({ error: "method not allowed" }, 405);
  }
  if (!env.GITHUB_WEBHOOK_SECRET) {
    // Fail closed. An unset secret means every delivery is unauthenticated,
    // and an endpoint that reviews on unauthenticated input is an endpoint
    // anyone can bill to this account.
    return json({ error: "webhook not configured" }, 503);
  }

  const raw = await request.text();
  const ok = await verifySignature(
    env.GITHUB_WEBHOOK_SECRET,
    raw,
    request.headers.get("X-Hub-Signature-256"),
  );
  if (!ok) return json({ error: "bad signature" }, 401);

  let payload: unknown;
  try {
    payload = JSON.parse(raw);
  } catch {
    return json({ error: "body is not JSON" }, 400);
  }

  const event = request.headers.get("X-GitHub-Event") || "";
  const decision = decide(
    event,
    payload,
    env.REVIEW_MENTION || DEFAULT_MENTION,
    splitCsv(env.REVIEW_TRIGGER_ASSOCIATIONS).length
      ? splitCsv(env.REVIEW_TRIGGER_ASSOCIATIONS)
      : DEFAULT_TRIGGER_ASSOCIATIONS,
  );

  if (decision.run === "skip") {
    return json({ ok: true, skipped: decision.reason });
  }

  // The same allowlist every tool call passes. Checked here as well as inside
  // github.ts so a repository outside it costs nothing rather than failing
  // after a token mint.
  const allowed = splitCsv(env.GITHUB_ALLOWED_REPOS);
  if (!allowed.includes(decision.repo)) {
    return json({ ok: true, skipped: `repository not allowlisted` });
  }

  ctx.waitUntil(run(env, decision));
  return json(
    {
      ok: true,
      queued: decision.run,
      repo: decision.repo,
      pull_request: decision.number,
    },
    202,
  );
}

async function run(env: Env, d: Decision): Promise<void> {
  if (d.run === "skip") return;
  try {
    let result;
    if (d.run === "push") {
      result = await reviewPush(env, d.repo, d.before, d.after, {
        post: true,
        trigger: "push",
      });
    } else if (d.run === "mention") {
      // One lookup: the comment payload carries no head sha. The draft flag
      // it returns is deliberately NOT consulted — a person asking by name
      // overrides a rule that exists to prevent unasked-for reviews.
      const head = await getPullRequestHead(env, d.repo, d.number);
      result = await reviewPullRequest(
        env,
        d.repo,
        d.number,
        // force: asking again is the entire point of asking.
        { post: true, force: true, trigger: `mention:${d.by}` },
        head.sha,
      );
    } else {
      result = await reviewPullRequest(
        env,
        d.repo,
        d.number,
        { post: true, trigger: "pull_request" },
        d.head,
      );
    }
    console.log(
      `reviewed ${d.repo}#${d.number}`,
      JSON.stringify({
        posted: result.posted,
        skipped: result.skipped,
        findings: result.findings.length,
        unanchored: result.unanchored.length,
        model: result.model,
      }),
    );
  } catch (e) {
    // A failed review must not retry itself: a model call that failed on a
    // malformed diff will fail the same way, and this path is not rate
    // limited. The absence of a comment is the signal.
    console.error(
      `review failed for ${d.repo}#${d.number}:`,
      e instanceof Error ? (e.stack ?? e.message) : String(e),
    );
  }
}
