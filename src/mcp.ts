// MCP (Model Context Protocol) surface for the GitHub worker.
//
// Served by the MCP TypeScript SDK (v2): createMcpHandler gives both protocol
// eras (the 2026-07-28 per-request revision and the legacy initialize one)
// from one factory, statelessly. Authentication, the Origin check and the
// OAuth metadata stay in index.ts, in front of it.
//
// Read tools, PR tools and issue tools. There is no approve tool and no merge
// tool: see createReview() in github.ts for why approval is refused, and note
// that merging needs `contents: write`, which the scoped token does not ask
// for — so a merge tool could not work here even if one existed.

import type { Env } from "./env";
import { reviewPullRequest } from "./review";
import { McpServer, createMcpHandler } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import {
  GitHubError,
  createComment,
  createIssue,
  createPullRequest,
  createReview,
  getIssue,
  getPullRequest,
  getPullRequestDiff,
  listIssues,
  listPullRequests,
  updateIssue,
  updatePullRequest,
  whoami,
} from "./github";

export const SERVER_INFO = {
  name: "shamwari-github-mcp",
  version: "0.1.0",
} as const;

const INSTRUCTIONS =
  "GitHub review, pull request and issue operations for allowlisted Nyuchi repositories. Call shamwari_whoami first: it reports, per repository, whether the App is installed and whether that installation grants the permissions the scoped token requests.";

/**
 * Behaviour hints a client can surface before running a tool.
 *
 * They are hints, not enforcement — the real guarantees are the scoped token
 * (contents:read, no workflows) and createReview refusing APPROVE. These let a
 * client show which tools write before it calls one.
 */
interface Annotations {
  readOnlyHint: boolean;
  destructiveHint: boolean;
  idempotentHint: boolean;
  openWorldHint: boolean;
}

/** Reads nothing but the API; safe to repeat. */
const READ: Annotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
};

/** Adds something new each call — a second call makes a second thing. */
const CREATE: Annotations = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: false,
  openWorldHint: true,
};

/** Overwrites existing fields, so repeating is safe but the old value is gone. */
const UPDATE: Annotations = {
  readOnlyHint: false,
  destructiveHint: true,
  idempotentHint: true,
  openWorldHint: true,
};

/**
 * A caller sent arguments the tool cannot use.
 *
 * Distinct from every other throw because the message is the whole point: it
 * names the field, so the caller can fix the call and try again. toolError()
 * lets it through for exactly that reason, where an unexpected throw is
 * answered generically.
 */
export class ArgumentError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ArgumentError";
  }
}

const REPO = z
  .string()
  .min(1)
  .describe("Repository as owner/repo. Must be in the worker's allowlist.");
const NUMBER = z.number().int().positive();
const STATE3 = z.enum(["open", "closed", "all"]).default("open");
const STATE2 = z.enum(["open", "closed"]);
const LIMIT = z.number().int().min(1).max(100).default(20);
const PAGE = z.number().int().min(1).optional().describe("Page, from 1.");

/** What a tool returns: the result as one JSON (or plain) text block. */
function text(result: unknown) {
  return {
    content: [
      {
        type: "text" as const,
        text:
          typeof result === "string" ? result : JSON.stringify(result, null, 2),
      },
    ],
  };
}

/**
 * What a failed tools/call returns.
 *
 * An ArgumentError names the field the caller got wrong, and a GitHubError
 * names the repository, permission or status — both are written to be read by
 * the caller and acted on, so both pass through. Anything
 * else is an unexpected throw whose message is internal detail: a stack
 * fragment, a property name, an internal URL. Log it, return a generic
 * string. This is the same rule index.ts applies on the transport path; the
 * two error paths should not disagree about what a caller may see.
 */
export function toolError(name: string, e: unknown) {
  if (e instanceof ArgumentError || e instanceof GitHubError) {
    return {
      content: [{ type: "text" as const, text: `Error: ${e.message}` }],
      isError: true,
    };
  }
  console.error(
    `tools/call ${name} failed:`,
    e instanceof Error ? (e.stack ?? e.message) : String(e),
  );
  return {
    content: [
      {
        type: "text" as const,
        text: "Error: internal error. The cause is in the worker log, not in the arguments — the same call will fail the same way.",
      },
    ],
    isError: true,
  };
}

/** Everything a PATCH-style tool needs: at least one field must change. */
function onlyDefined<K extends string>(
  a: Record<string, unknown>,
  keys: readonly K[],
): Record<string, unknown> {
  const patch: Record<string, unknown> = {};
  for (const k of keys) if (a[k] !== undefined) patch[k] = a[k];
  if (Object.keys(patch).length === 0)
    throw new ArgumentError(
      "nothing to update: pass at least one field to change",
    );
  return patch;
}

/**
 * Build the MCP server for one request. The SDK calls the factory per request
 * (stateless), so `env` is closed over rather than stored anywhere.
 */
export function buildServer(env: Env): McpServer {
  const server = new McpServer(SERVER_INFO, { instructions: INSTRUCTIONS });

  /** Register a tool whose handler throws on failure. */
  function tool<S extends z.ZodObject<z.ZodRawShape>>(
    name: string,
    config: { description: string; inputSchema: S; annotations: Annotations },
    run: (args: z.infer<S>) => Promise<unknown>,
  ) {
    // The cast is only at the SDK boundary: each handler's `args` is still
    // typed from its own Zod schema through `S`, and the SDK validates the
    // arguments against that schema before this callback runs.
    (
      server.registerTool as unknown as (
        name: string,
        config: unknown,
        cb: (args: unknown) => Promise<unknown>,
      ) => unknown
    ).call(server, name, config, async (args: unknown) => {
      try {
        return text(await run(args as z.infer<S>));
      } catch (e) {
        return toolError(name, e);
      }
    });
  }

  tool(
    "shamwari_whoami",
    {
      annotations: READ,
      description:
        "Verify the GitHub App credentials and report, for EVERY allowlisted repository, whether the App is installed there and whether that installation grants the permissions the scoped token asks for. Use this first when anything returns 422 or 404: a token mint requests the whole permission set in one call, so a single gap fails every tool on that repository, and a permission the App declares is not held until the installation owner accepts it.",
      inputSchema: z.object({}),
    },
    () => whoami(env),
  );

  tool(
    "shamwari_list_pull_requests",
    {
      annotations: READ,
      description:
        "List pull requests, most recently updated first. Returns {items, count, page, has_more, next_page} with each entry trimmed to number, title, state, draft, author, base, head, labels, timestamps and url — call shamwari_get_pull_request for the rest.",
      inputSchema: z.object({
        repo: REPO,
        state: STATE3,
        limit: LIMIT,
        page: PAGE,
      }),
    },
    (a) => listPullRequests(env, a.repo, a.state, a.limit, a.page ?? 1),
  );

  tool(
    "shamwari_get_pull_request",
    {
      annotations: READ,
      description:
        "One pull request in review-ready form: metadata, mergeability, the changed-file list, and a check-run rollup naming what is failing and what is still pending.",
      inputSchema: z.object({ repo: REPO, number: NUMBER }),
    },
    (a) => getPullRequest(env, a.repo, a.number),
  );

  tool(
    "shamwari_get_pull_request_diff",
    {
      annotations: READ,
      description:
        "The unified diff for a pull request. This is the text to actually review; fetch it before writing a review rather than reasoning from the file list alone.",
      inputSchema: z.object({ repo: REPO, number: NUMBER }),
    },
    (a) => getPullRequestDiff(env, a.repo, a.number),
  );

  tool(
    "shamwari_create_review",
    {
      annotations: CREATE,
      description:
        "Submit a pull request review with an optional set of inline comments. Events are COMMENT or REQUEST_CHANGES only — this server refuses to approve pull requests, so a review from here never satisfies a branch protection review requirement.",
      inputSchema: z.object({
        repo: REPO,
        number: NUMBER,
        event: z.enum(["COMMENT", "REQUEST_CHANGES"]),
        body: z.string().min(1).describe("The review summary."),
        comments: z
          .array(
            z.object({
              path: z.string().min(1),
              line: z.number().int().positive(),
              body: z.string().min(1),
            }),
          )
          .optional()
          .describe("Inline comments. `line` is a line in the diff of `path`."),
      }),
    },
    (a) =>
      createReview(env, a.repo, a.number, {
        event: a.event,
        body: a.body,
        comments: a.comments,
      }),
  );

  tool(
    "shamwari_create_pull_request",
    {
      annotations: CREATE,
      description:
        "Open a pull request. Draft unless draft is explicitly false, so an agent-opened PR does not demand review attention before a human has looked at it.",
      inputSchema: z.object({
        repo: REPO,
        title: z.string().min(1),
        head: z.string().min(1).describe("The branch with the changes."),
        base: z.string().min(1).describe("The branch to merge into."),
        body: z.string().optional(),
        draft: z.boolean().default(true),
      }),
    },
    (a) =>
      createPullRequest(env, a.repo, {
        title: a.title,
        head: a.head,
        base: a.base,
        body: a.body,
        draft: a.draft,
      }),
  );

  tool(
    "shamwari_update_pull_request",
    {
      annotations: UPDATE,
      description:
        "Change a pull request's title, body, base branch, or state (open/closed). Cannot merge: the scoped token holds contents:read only.",
      inputSchema: z.object({
        repo: REPO,
        number: NUMBER,
        title: z.string().optional(),
        body: z.string().optional(),
        base: z.string().optional(),
        state: STATE2.optional(),
      }),
    },
    (a) =>
      updatePullRequest(
        env,
        a.repo,
        a.number,
        onlyDefined(a, ["title", "body", "base", "state"] as const),
      ),
  );

  tool(
    "shamwari_list_issues",
    {
      annotations: READ,
      description:
        "List issues, most recently updated first. Returns {items, count, page, has_more, next_page}; each entry carries is_pull_request because GitHub returns pull requests from this endpoint too.",
      inputSchema: z.object({
        repo: REPO,
        state: STATE3,
        limit: LIMIT,
        page: PAGE,
      }),
    },
    (a) => listIssues(env, a.repo, a.state, a.limit, a.page ?? 1),
  );

  tool(
    "shamwari_get_issue",
    {
      annotations: READ,
      description: "One issue in full.",
      inputSchema: z.object({ repo: REPO, number: NUMBER }),
    },
    (a) => getIssue(env, a.repo, a.number),
  );

  tool(
    "shamwari_create_issue",
    {
      annotations: CREATE,
      description: "File an issue.",
      inputSchema: z.object({
        repo: REPO,
        title: z.string().min(1),
        body: z.string().optional(),
        labels: z.array(z.string()).optional(),
        assignees: z.array(z.string()).optional(),
      }),
    },
    (a) =>
      createIssue(env, a.repo, {
        title: a.title,
        body: a.body,
        labels: a.labels,
        assignees: a.assignees,
      }),
  );

  tool(
    "shamwari_update_issue",
    {
      annotations: UPDATE,
      description:
        "Retitle, re-body, relabel, reassign, or open/close an issue.",
      inputSchema: z.object({
        repo: REPO,
        number: NUMBER,
        title: z.string().optional(),
        body: z.string().optional(),
        state: STATE2.optional(),
        labels: z.array(z.string()).optional(),
        assignees: z.array(z.string()).optional(),
      }),
    },
    (a) =>
      updateIssue(
        env,
        a.repo,
        a.number,
        onlyDefined(a, [
          "title",
          "body",
          "state",
          "labels",
          "assignees",
        ] as const),
      ),
  );

  tool(
    "shamwari_comment",
    {
      annotations: CREATE,
      description:
        "Post a comment on an issue or a pull request (they share a numbering space and an endpoint).",
      inputSchema: z.object({
        repo: REPO,
        number: NUMBER,
        body: z.string().min(1),
      }),
    },
    (a) => createComment(env, a.repo, a.number, a.body),
  );

  tool(
    "shamwari_review_pull_request",
    {
      // CREATE rather than READ because this tool CAN post. It defaults to a
      // dry run, but an annotation describes what a tool may do, not what it
      // usually does — a client deciding whether to confirm needs the ceiling.
      annotations: CREATE,
      description:
        "Review a pull request with a model running on Workers AI and return the findings, each naming a line the diff adds. DRY RUN by default: nothing is posted unless post is true, so the same call can compare two models on one pull request without either writing to it. When it does post, it posts ONE comment on the head commit — never a pull request review — so it cannot approve, cannot request changes, and cannot affect merge state. Findings come back most serious first and capped; anything the model aimed at a line the diff does not add is returned separately under unanchored rather than dropped.",
      inputSchema: z.object({
        repo: REPO,
        number: NUMBER,
        model: z
          .string()
          .optional()
          .describe(
            'Workers AI model id, e.g. "@cf/zai-org/glm-5.3", "@cf/zai-org/glm-5.3-flash" or "@cf/moonshotai/kimi-k2.7-code". Defaults to REVIEW_MODEL. Pass it explicitly to compare models on the same pull request.',
          ),
        post: z
          .boolean()
          .optional()
          .describe(
            "Post the review to GitHub. Default false — read the findings first.",
          ),
        head_sha: z
          .string()
          .optional()
          .describe(
            "The commit to comment on. Required only when post is true — the review is posted as a comment on that commit, never as a pull request review.",
          ),
        max_findings: z
          .number()
          .int()
          .positive()
          .optional()
          .describe("Cap on reported findings. Default 10."),
        force: z
          .boolean()
          .optional()
          .describe(
            "Post even if this commit already carries a review. Default false.",
          ),
      }),
    },
    (a) =>
      reviewPullRequest(
        env,
        a.repo,
        a.number,
        {
          model: a.model,
          post: a.post === true,
          force: a.force === true,
          maxFindings: a.max_findings,
        },
        a.head_sha,
      ),
  );

  return server;
}

/**
 * The MCP endpoint for one request. `authInfo` is whatever the caller already
 * verified (index.ts verifies the WorkOS token); the SDK never reads it from
 * headers.
 */
export function handleMcp(
  request: Request,
  env: Env,
  authInfo: {
    token: string;
    clientId: string;
    scopes: string[];
    extra?: Record<string, unknown>;
  },
): Promise<Response> {
  return createMcpHandler(() => buildServer(env)).fetch(request, { authInfo });
}
