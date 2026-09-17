// The code review engine.
//
// Milestone 2's brain, in the form Milestone 1 already established: a plain
// function over github.ts, wrapped thinly by the MCP layer. A webhook
// consumer can call reviewPullRequest() directly later without a second
// implementation appearing.
//
// The model runs on Workers AI, so there is no third-party API key to hold
// and no egress — the inference happens on the same platform as the worker
// and is billed to the Cloudflare account.
//
// What this deliberately does NOT do: approve. It submits through
// createReview(), which refuses APPROVE before the allowlist is consulted, so
// the agent inherits that guarantee rather than re-stating it.

import type { Env } from "./env";
import { GitHubError, createReview, getPullRequestDiff } from "./github";

/** Workers AI models known to do function calling and structured output. */
export const REVIEW_MODELS = {
  "glm-5.3": "@cf/zai-org/glm-5.3",
  "glm-5.3-flash": "@cf/zai-org/glm-5.3-flash",
  "kimi-k2.7-code": "@cf/moonshotai/kimi-k2.7-code",
} as const;

export type ReviewModelName = keyof typeof REVIEW_MODELS;

export const DEFAULT_MODEL: ReviewModelName = "glm-5.3";

/**
 * How much annotated diff to send.
 *
 * Every candidate model has at least a 262K-token window, so this is not a
 * context limit — it is a quality and cost limit. A 400KB diff is a rename
 * sweep or a lockfile, and a review of it is noise at any price. Measured on
 * this repository the largest real diff was 35,955 bytes, so 200KB leaves
 * roughly 5x headroom before anything is dropped.
 */
export const DEFAULT_MAX_DIFF_BYTES = 200_000;

/** A single thing the model wants to say about a specific line. */
export interface Finding {
  path: string;
  line: number;
  severity: "blocking" | "concern" | "note";
  title: string;
  body: string;
}

export interface ReviewResult {
  model: string;
  summary: string;
  /** Findings that landed on a real added line, ready for inline comments. */
  findings: Finding[];
  /**
   * Findings the model produced that name a line the diff does not add.
   * Kept rather than dropped: a model pointing at a line it cannot see is a
   * signal about the review, and silently discarding them would hide it.
   */
  unanchored: Finding[];
  truncated: boolean;
  posted: boolean;
  event?: "COMMENT" | "REQUEST_CHANGES";
}

// --- diff annotation ------------------------------------------------------

/**
 * The whole reason inline comments land in the right place.
 *
 * A unified diff does not carry per-line numbers; it carries hunk headers
 * (`@@ -a,b +c,d @@`) and leaves the arithmetic to the reader. Asking a
 * language model to do that arithmetic is asking for off-by-N comments on
 * unrelated lines, which is worse than no comment at all — it is a review
 * that looks careful and points at the wrong code.
 *
 * So the number is computed here and written into the text the model reads.
 * Each line becomes `<marker><new line number>|<content>`:
 *
 *     +142|  const token = await mintToken(env);
 *      141|  export async function run() {
 *     -   |  const token = env.TOKEN;
 *
 * Removed lines get no number because they do not exist in the new file and
 * GitHub cannot anchor a comment to them.
 */
export function annotateDiff(diff: string): {
  text: string;
  /** path -> the set of new-file lines this diff ADDS, the commentable ones. */
  addedLines: Map<string, Set<number>>;
} {
  const out: string[] = [];
  const addedLines = new Map<string, Set<number>>();

  let path = "";
  let newLine = 0;

  for (const raw of diff.split("\n")) {
    if (raw.startsWith("diff --git")) {
      // "diff --git a/x b/x" — take the b-side, which is the new path.
      const m = raw.match(/ b\/(.+)$/);
      path = m ? m[1] : "";
      newLine = 0;
      out.push(`\n### ${path || raw}`);
      continue;
    }
    // +++ carries the authoritative new path and survives a rename.
    if (raw.startsWith("+++ ")) {
      const p = raw.slice(4).trim();
      if (p !== "/dev/null") path = p.replace(/^b\//, "");
      continue;
    }
    if (raw.startsWith("--- ")) continue;
    if (
      raw.startsWith("index ") ||
      raw.startsWith("new file mode") ||
      raw.startsWith("deleted file mode") ||
      raw.startsWith("similarity index") ||
      raw.startsWith("rename from") ||
      raw.startsWith("rename to") ||
      raw.startsWith("old mode") ||
      raw.startsWith("new mode")
    ) {
      continue;
    }
    if (raw.startsWith("Binary files")) {
      out.push("(binary file, not shown)");
      continue;
    }
    if (raw.startsWith("@@")) {
      // @@ -oldStart,oldCount +newStart,newCount @@ optional context
      const m = raw.match(/@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
      newLine = m ? Number(m[1]) : 0;
      out.push(raw);
      continue;
    }
    if (newLine === 0) continue; // outside any hunk

    if (raw.startsWith("+")) {
      out.push(`+${String(newLine).padStart(5)}|${raw.slice(1)}`);
      if (path) {
        const set = addedLines.get(path) ?? new Set<number>();
        set.add(newLine);
        addedLines.set(path, set);
      }
      newLine++;
    } else if (raw.startsWith("-")) {
      out.push(`-     |${raw.slice(1)}`);
    } else if (raw.startsWith("\\")) {
      out.push(raw); // "\ No newline at end of file"
    } else {
      // A context line. The leading space is the diff marker, not content.
      out.push(` ${String(newLine).padStart(5)}|${raw.slice(1)}`);
      newLine++;
    }
  }

  return { text: out.join("\n").trim(), addedLines };
}

/** Cut the annotated diff to a byte budget on a line boundary. */
export function truncate(
  text: string,
  maxBytes: number,
): { text: string; truncated: boolean } {
  if (text.length <= maxBytes) return { text, truncated: false };
  const cut = text.slice(0, maxBytes);
  const lastNewline = cut.lastIndexOf("\n");
  return {
    text: (lastNewline > 0 ? cut.slice(0, lastNewline) : cut) + "\n",
    truncated: true,
  };
}

// --- the prompt -----------------------------------------------------------

/**
 * What separates a review worth reading from a review everybody mutes.
 *
 * The failure mode of an automated reviewer is not being wrong — it is being
 * voluminous. A bot that posts nine style nits and one real bug has buried
 * the bug, and after two weeks nobody opens its comments. So the instruction
 * that matters most is the one telling it to return nothing when there is
 * nothing: an empty review is a correct and valuable outcome.
 *
 * Formatting is excluded because prettier and markdownlint already gate every
 * pull request in this org. A comment about a missing trailing comma is a
 * comment about a check that would have failed anyway.
 */
export const SYSTEM_PROMPT = `You review a single pull request diff for the Nyuchi engineering org. You are one reviewer among humans, not a gate.

REPORT, and only these:
- Correctness bugs: wrong logic, off-by-one, unhandled null/undefined, a promise not awaited, a race, a case the code claims to handle but does not.
- Security: injected input reaching a URL, query or command; a credential or token in a log, an error message or a response; authentication or authorization that fails open (a check written so that missing configuration means "allow").
- Resource and error handling: an unclosed handle, an unbounded loop or fetch, a swallowed error, a retry with no ceiling.
- API misuse: a call whose arguments cannot mean what the code assumes.
- Tests that assert nothing, or that would still pass if the behaviour they name were removed.

DO NOT REPORT:
- Formatting, whitespace, quote style, import order, line length. Prettier and markdownlint gate every pull request here; a comment about them is a comment about a check that already runs.
- Naming preferences, "consider extracting this", "consider adding a comment", or any suggestion whose benefit is taste.
- Anything you cannot see. You have a diff, not the repository. If a call looks wrong only because you cannot see the function it calls, say nothing.
- Praise, summaries of what the diff does, or restatements of the title.

RULES:
- Every finding must name a line the diff ADDS. Those lines are marked with a leading "+" and carry their new-file line number before the "|". Use exactly that number. Context lines (leading space) and removed lines (leading "-") are NOT valid targets; if your point concerns one, put it in the summary instead.
- Quote the specific expression you mean. A finding that could apply to any code is not a finding.
- Say what goes wrong and under what input or state. "This could be a problem" is not a finding; "if headers is empty this throws on .get" is.
- Severity: "blocking" means it is wrong and will misbehave in production. "concern" means it is likely wrong or is a real risk under a plausible input. "note" is a genuine defect that is minor. If you are reaching for a reason to report something, do not report it.
- Returning zero findings is a correct and expected outcome. Do not pad. Do not invent a "note" so the review looks thorough. A clean diff should get an empty findings array and a one-sentence summary saying so.
- The summary is at most three sentences and says what you checked and what you concluded. It is not a description of the change.`;

/** The shape the model is asked to return, and the shape we validate against. */
export const FINDINGS_SCHEMA = {
  type: "object",
  properties: {
    summary: { type: "string" },
    findings: {
      type: "array",
      items: {
        type: "object",
        properties: {
          path: { type: "string" },
          line: { type: "number" },
          severity: {
            type: "string",
            enum: ["blocking", "concern", "note"],
          },
          title: { type: "string" },
          body: { type: "string" },
        },
        required: ["path", "line", "severity", "title", "body"],
      },
    },
  },
  required: ["summary", "findings"],
} as const;

// --- validation -----------------------------------------------------------

/**
 * Cloudflare's own JSON-mode documentation says it "can't guarantee that the
 * model responds according to the requested JSON Schema". So the schema is a
 * request, and this is the enforcement.
 */
export function parseFindings(response: unknown): {
  summary: string;
  findings: Finding[];
} {
  // The binding returns an object for some models and a JSON string for
  // others. Both are normal; neither is trusted.
  let value: unknown = response;
  if (typeof value === "string") {
    try {
      value = JSON.parse(value);
    } catch {
      throw new GitHubError(
        "the review model did not return JSON",
        502,
        String(response).slice(0, 500),
      );
    }
  }
  if (!value || typeof value !== "object") {
    throw new GitHubError("the review model returned no object", 502, null);
  }

  const obj = value as Record<string, unknown>;
  const summary = typeof obj.summary === "string" ? obj.summary : "";
  const raw = Array.isArray(obj.findings) ? obj.findings : [];

  const findings: Finding[] = [];
  for (const item of raw) {
    if (!item || typeof item !== "object") continue;
    const f = item as Record<string, unknown>;
    const line = typeof f.line === "number" ? f.line : Number(f.line);
    if (
      typeof f.path !== "string" ||
      !f.path ||
      !Number.isInteger(line) ||
      line < 1 ||
      typeof f.body !== "string" ||
      !f.body
    ) {
      continue;
    }
    const severity =
      f.severity === "blocking" || f.severity === "concern"
        ? f.severity
        : "note";
    findings.push({
      path: f.path,
      line,
      severity,
      title: typeof f.title === "string" ? f.title : "",
      body: f.body,
    });
  }
  return { summary, findings };
}

/**
 * Split findings by whether GitHub can actually anchor them.
 *
 * A comment on a line the diff does not add is rejected by the API with a 422
 * that fails the whole review call — one hallucinated line number would
 * otherwise lose every real finding alongside it.
 */
export function anchor(
  findings: Finding[],
  addedLines: Map<string, Set<number>>,
): { anchored: Finding[]; unanchored: Finding[] } {
  const anchored: Finding[] = [];
  const unanchored: Finding[] = [];
  for (const f of findings) {
    if (addedLines.get(f.path)?.has(f.line)) anchored.push(f);
    else unanchored.push(f);
  }
  return { anchored, unanchored };
}

const RANK = { blocking: 0, concern: 1, note: 2 } as const;

/** Most serious first, so a capped review keeps the findings that matter. */
export function rank(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => RANK[a.severity] - RANK[b.severity]);
}

/** Render the review body a human reads before the inline comments. */
export function renderBody(r: {
  model: string;
  summary: string;
  findings: Finding[];
  unanchored: Finding[];
  truncated: boolean;
}): string {
  const lines = [r.summary.trim() || "No summary returned."];

  if (r.unanchored.length) {
    lines.push(
      "",
      "**Not anchored to a changed line** — reported here rather than dropped:",
      "",
      ...r.unanchored.map(
        (f) => `- \`${f.path}:${f.line}\` — ${f.title || f.body}`,
      ),
    );
  }
  if (r.truncated) {
    lines.push(
      "",
      "> The diff was larger than this reviewer's budget and was truncated. " +
        "Files after the cut were not read.",
    );
  }
  lines.push(
    "",
    "---",
    "",
    `_Automated review · \`${r.model}\` on Workers AI · this reviewer cannot approve._`,
  );
  return lines.join("\n");
}

// --- the engine -----------------------------------------------------------

export interface ReviewOptions {
  model?: string;
  /** Post the review to GitHub. Default false: a dry run is the safe default. */
  post?: boolean;
  /** Review event when posting. Default COMMENT — see reviewPullRequest. */
  event?: "COMMENT" | "REQUEST_CHANGES";
  maxFindings?: number;
  maxDiffBytes?: number;
}

/**
 * Review one pull request.
 *
 * Defaults to a DRY RUN. Posting is opt-in per call because the first thing
 * anyone should do with a new reviewer is read what it would have said, and
 * because it lets the same tool compare two models on the same pull request
 * without either of them writing to it.
 *
 * Defaults to COMMENT even when findings are blocking. REQUEST_CHANGES puts a
 * red mark on the pull request that a person then has to dismiss, so it is
 * something this reviewer should earn on evidence rather than assume on its
 * first day; pass it explicitly once you trust the output.
 */
export async function reviewPullRequest(
  env: Env,
  repo: string,
  number: number,
  opts: ReviewOptions = {},
): Promise<ReviewResult> {
  if (env.REVIEW_ENABLED === "false") {
    throw new GitHubError(
      "the review agent is disabled (REVIEW_ENABLED=false)",
      503,
      null,
    );
  }
  if (!env.AI) {
    throw new GitHubError(
      'no Workers AI binding: add [ai] binding = "AI" to wrangler.toml and redeploy',
      500,
      null,
    );
  }

  const model = opts.model || env.REVIEW_MODEL || REVIEW_MODELS[DEFAULT_MODEL];
  const maxDiffBytes =
    opts.maxDiffBytes ||
    Number(env.REVIEW_MAX_DIFF_BYTES) ||
    DEFAULT_MAX_DIFF_BYTES;
  const maxFindings = opts.maxFindings ?? 10;

  const diff = await getPullRequestDiff(env, repo, number);
  const { text, addedLines } = annotateDiff(diff);
  const { text: sent, truncated } = truncate(text, maxDiffBytes);

  if (!sent.trim()) {
    return {
      model,
      summary: "The diff is empty — nothing to review.",
      findings: [],
      unanchored: [],
      truncated,
      posted: false,
    };
  }

  const out = (await env.AI.run(model, {
    messages: [
      { role: "system", content: SYSTEM_PROMPT },
      {
        role: "user",
        content: `Repository: ${repo}\nPull request: #${number}\n\nAnnotated diff. Lines the diff ADDS start with "+" and carry their new-file line number before the "|"; only those are valid finding targets.\n\n${sent}`,
      },
    ],
    response_format: { type: "json_schema", json_schema: FINDINGS_SCHEMA },
  })) as { response?: unknown };

  const { summary, findings } = parseFindings(out?.response);
  const { anchored, unanchored } = anchor(findings, addedLines);
  const kept = rank(anchored).slice(0, maxFindings);

  const result: ReviewResult = {
    model,
    summary,
    findings: kept,
    unanchored,
    truncated,
    posted: false,
  };

  if (!opts.post) return result;

  const event =
    opts.event === "REQUEST_CHANGES" ? "REQUEST_CHANGES" : "COMMENT";
  await createReview(env, repo, number, {
    event,
    body: renderBody(result),
    comments: kept.map((f) => ({
      path: f.path,
      line: f.line,
      body: `**${f.severity}** — ${f.title}\n\n${f.body}`,
    })),
  });

  return { ...result, posted: true, event };
}
