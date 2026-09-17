// MCP (Model Context Protocol) surface for the GitHub worker.
//
// Streamable-HTTP / JSON-RPC 2.0 — the same transport nyuchi-fly-mcp and the
// docs MCP worker use, so an existing client config points at this with only
// a URL change.
//
// Read tools, PR tools and issue tools. There is no approve tool and no merge
// tool: see createReview() in github.ts for why approval is refused, and note
// that merging needs `contents: write`, which the scoped token does not ask
// for — so a merge tool could not work here even if one existed.

import type { Env } from "./env";
import { reviewPullRequest } from "./review";
import {
  LEGACY_VERSION,
  META_SERVER_INFO,
  METHOD_NOT_FOUND,
  SUPPORTED_MODERN_VERSIONS,
} from "./protocol";
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

/**
 * The version reported in an `initialize` result.
 *
 * This is the LEGACY revision, and deliberately so: only a legacy client sends
 * `initialize`, and answering it with the modern revision would tell that
 * client to speak a protocol it cannot. Modern clients learn the version from
 * `server/discover` or simply declare it per request.
 */
export const PROTOCOL_VERSION = LEGACY_VERSION;

export const SERVER_INFO = {
  name: "nyuchi-github-mcp",
  version: "0.1.0",
} as const;

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

interface Tool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  annotations: Annotations;
  handler: (env: Env, args: Record<string, unknown>) => Promise<unknown>;
}

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

const str = (v: unknown, field: string): string => {
  if (typeof v !== "string" || !v)
    throw new ArgumentError(
      `missing or invalid "${field}": expected a non-empty string`,
    );
  return v;
};

const num = (v: unknown, field: string): number => {
  if (typeof v !== "number" || !Number.isFinite(v))
    throw new ArgumentError(`missing or invalid "${field}": expected a number`);
  return v;
};

const REPO_PROP = {
  type: "string",
  description: "Repository as owner/repo. Must be in the worker's allowlist.",
} as const;

export const TOOLS: Tool[] = [
  {
    name: "nyuchi_whoami",
    annotations: READ,
    description:
      "Verify the GitHub App credentials and report, for EVERY allowlisted repository, whether the App is installed there and whether that installation grants the permissions the scoped token asks for. Use this first when anything returns 422 or 404: a token mint requests the whole permission set in one call, so a single gap fails every tool on that repository, and a permission the App declares is not held until the installation owner accepts it.",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false,
    },
    handler: (env) => whoami(env),
  },
  {
    name: "nyuchi_list_pull_requests",
    annotations: READ,
    description:
      "List pull requests, most recently updated first. Returns {items, count, page, has_more, next_page} with each entry trimmed to number, title, state, draft, author, base, head, labels, timestamps and url — call nyuchi_get_pull_request for the rest.",
    inputSchema: {
      type: "object",
      properties: {
        repo: REPO_PROP,
        state: {
          type: "string",
          enum: ["open", "closed", "all"],
          default: "open",
        },
        limit: { type: "number", default: 20, maximum: 100 },
      },
      required: ["repo"],
      additionalProperties: false,
    },
    handler: (env, a) =>
      listPullRequests(
        env,
        str(a.repo, "repo"),
        typeof a.state === "string" ? a.state : "open",
        typeof a.limit === "number" ? Math.min(a.limit, 100) : 20,
        typeof a.page === "number" ? Math.max(1, a.page) : 1,
      ),
  },
  {
    name: "nyuchi_get_pull_request",
    annotations: READ,
    description:
      "One pull request in review-ready form: metadata, mergeability, the changed-file list, and a check-run rollup naming what is failing and what is still pending.",
    inputSchema: {
      type: "object",
      properties: { repo: REPO_PROP, number: { type: "number" } },
      required: ["repo", "number"],
      additionalProperties: false,
    },
    handler: (env, a) =>
      getPullRequest(env, str(a.repo, "repo"), num(a.number, "number")),
  },
  {
    name: "nyuchi_get_pull_request_diff",
    annotations: READ,
    description:
      "The unified diff for a pull request. This is the text to actually review; fetch it before writing a review rather than reasoning from the file list alone.",
    inputSchema: {
      type: "object",
      properties: { repo: REPO_PROP, number: { type: "number" } },
      required: ["repo", "number"],
      additionalProperties: false,
    },
    handler: (env, a) =>
      getPullRequestDiff(env, str(a.repo, "repo"), num(a.number, "number")),
  },
  {
    name: "nyuchi_create_review",
    annotations: CREATE,
    description:
      "Submit a pull request review with an optional set of inline comments. Events are COMMENT or REQUEST_CHANGES only — this server refuses to approve pull requests, so a review from here never satisfies a branch protection review requirement.",
    inputSchema: {
      type: "object",
      properties: {
        repo: REPO_PROP,
        number: { type: "number" },
        event: { type: "string", enum: ["COMMENT", "REQUEST_CHANGES"] },
        body: { type: "string", description: "The review summary." },
        comments: {
          type: "array",
          description:
            "Inline comments. `line` is a line in the diff of `path`.",
          items: {
            type: "object",
            properties: {
              path: { type: "string" },
              line: { type: "number" },
              body: { type: "string" },
            },
            required: ["path", "line", "body"],
            additionalProperties: false,
          },
        },
      },
      required: ["repo", "number", "event", "body"],
      additionalProperties: false,
    },
    handler: (env, a) =>
      createReview(env, str(a.repo, "repo"), num(a.number, "number"), {
        event: str(a.event, "event") as "COMMENT" | "REQUEST_CHANGES",
        body: str(a.body, "body"),
        comments: a.comments as
          | Array<{ path: string; line: number; body: string }>
          | undefined,
      }),
  },
  {
    name: "nyuchi_create_pull_request",
    annotations: CREATE,
    description:
      "Open a pull request. Draft unless draft is explicitly false, so an agent-opened PR does not demand review attention before a human has looked at it.",
    inputSchema: {
      type: "object",
      properties: {
        repo: REPO_PROP,
        title: { type: "string" },
        head: { type: "string", description: "The branch with the changes." },
        base: { type: "string", description: "The branch to merge into." },
        body: { type: "string" },
        draft: { type: "boolean", default: true },
      },
      required: ["repo", "title", "head", "base"],
      additionalProperties: false,
    },
    handler: (env, a) =>
      createPullRequest(env, str(a.repo, "repo"), {
        title: str(a.title, "title"),
        head: str(a.head, "head"),
        base: str(a.base, "base"),
        body: typeof a.body === "string" ? a.body : undefined,
        draft: typeof a.draft === "boolean" ? a.draft : true,
      }),
  },
  {
    name: "nyuchi_update_pull_request",
    annotations: UPDATE,
    description:
      "Change a pull request's title, body, base branch, or state (open/closed). Cannot merge: the scoped token holds contents:read only.",
    inputSchema: {
      type: "object",
      properties: {
        repo: REPO_PROP,
        number: { type: "number" },
        title: { type: "string" },
        body: { type: "string" },
        base: { type: "string" },
        state: { type: "string", enum: ["open", "closed"] },
      },
      required: ["repo", "number"],
      additionalProperties: false,
    },
    handler: (env, a) => {
      const patch: Record<string, unknown> = {};
      for (const k of ["title", "body", "base", "state"] as const) {
        if (a[k] !== undefined) patch[k] = a[k];
      }
      if (Object.keys(patch).length === 0)
        throw new ArgumentError(
          "nothing to update: pass at least one field to change",
        );
      return updatePullRequest(
        env,
        str(a.repo, "repo"),
        num(a.number, "number"),
        patch,
      );
    },
  },
  {
    name: "nyuchi_list_issues",
    annotations: READ,
    description:
      "List issues, most recently updated first. Returns {items, count, page, has_more, next_page}; each entry carries is_pull_request because GitHub returns pull requests from this endpoint too.",
    inputSchema: {
      type: "object",
      properties: {
        repo: REPO_PROP,
        state: {
          type: "string",
          enum: ["open", "closed", "all"],
          default: "open",
        },
        limit: { type: "number", default: 20, maximum: 100 },
      },
      required: ["repo"],
      additionalProperties: false,
    },
    handler: (env, a) =>
      listIssues(
        env,
        str(a.repo, "repo"),
        typeof a.state === "string" ? a.state : "open",
        typeof a.limit === "number" ? Math.min(a.limit, 100) : 20,
        typeof a.page === "number" ? Math.max(1, a.page) : 1,
      ),
  },
  {
    name: "nyuchi_get_issue",
    annotations: READ,
    description: "One issue in full.",
    inputSchema: {
      type: "object",
      properties: { repo: REPO_PROP, number: { type: "number" } },
      required: ["repo", "number"],
      additionalProperties: false,
    },
    handler: (env, a) =>
      getIssue(env, str(a.repo, "repo"), num(a.number, "number")),
  },
  {
    name: "nyuchi_create_issue",
    annotations: CREATE,
    description: "File an issue.",
    inputSchema: {
      type: "object",
      properties: {
        repo: REPO_PROP,
        title: { type: "string" },
        body: { type: "string" },
        labels: { type: "array", items: { type: "string" } },
        assignees: { type: "array", items: { type: "string" } },
      },
      required: ["repo", "title"],
      additionalProperties: false,
    },
    handler: (env, a) =>
      createIssue(env, str(a.repo, "repo"), {
        title: str(a.title, "title"),
        body: typeof a.body === "string" ? a.body : undefined,
        labels: a.labels as string[] | undefined,
        assignees: a.assignees as string[] | undefined,
      }),
  },
  {
    name: "nyuchi_update_issue",
    annotations: UPDATE,
    description: "Retitle, re-body, relabel, reassign, or open/close an issue.",
    inputSchema: {
      type: "object",
      properties: {
        repo: REPO_PROP,
        number: { type: "number" },
        title: { type: "string" },
        body: { type: "string" },
        state: { type: "string", enum: ["open", "closed"] },
        labels: { type: "array", items: { type: "string" } },
        assignees: { type: "array", items: { type: "string" } },
      },
      required: ["repo", "number"],
      additionalProperties: false,
    },
    handler: (env, a) => {
      const patch: Record<string, unknown> = {};
      for (const k of [
        "title",
        "body",
        "state",
        "labels",
        "assignees",
      ] as const) {
        if (a[k] !== undefined) patch[k] = a[k];
      }
      if (Object.keys(patch).length === 0)
        throw new ArgumentError(
          "nothing to update: pass at least one field to change",
        );
      return updateIssue(
        env,
        str(a.repo, "repo"),
        num(a.number, "number"),
        patch,
      );
    },
  },
  {
    name: "nyuchi_comment",
    annotations: CREATE,
    description:
      "Post a comment on an issue or a pull request (they share a numbering space and an endpoint).",
    inputSchema: {
      type: "object",
      properties: {
        repo: REPO_PROP,
        number: { type: "number" },
        body: { type: "string" },
      },
      required: ["repo", "number", "body"],
      additionalProperties: false,
    },
    handler: (env, a) =>
      createComment(
        env,
        str(a.repo, "repo"),
        num(a.number, "number"),
        str(a.body, "body"),
      ),
  },
  {
    name: "nyuchi_review_pull_request",
    // CREATE rather than READ because this tool CAN post. It defaults to a
    // dry run, but an annotation describes what a tool may do, not what it
    // usually does — a client deciding whether to confirm needs the ceiling.
    annotations: CREATE,
    description:
      "Review a pull request with a model running on Workers AI and return the findings, each anchored to a line the diff adds. DRY RUN by default: nothing is posted unless post is true, so the same call can compare two models on one pull request without either writing to it. Cannot approve — it submits through the same path that refuses APPROVE. Findings are returned most serious first and capped; anything the model aimed at a line the diff does not add is returned separately under unanchored rather than dropped.",
    inputSchema: {
      type: "object",
      properties: {
        repo: REPO_PROP,
        number: { type: "number" },
        model: {
          type: "string",
          description:
            'Workers AI model id, e.g. "@cf/zai-org/glm-5.3", "@cf/zai-org/glm-5.3-flash" or "@cf/moonshotai/kimi-k2.7-code". Defaults to REVIEW_MODEL. Pass it explicitly to compare models on the same pull request.',
        },
        post: {
          type: "boolean",
          description:
            "Post the review to GitHub. Default false — read the findings first.",
        },
        event: {
          type: "string",
          enum: ["COMMENT", "REQUEST_CHANGES"],
          description:
            "Review event when posting. Default COMMENT. REQUEST_CHANGES leaves a mark a person must dismiss, so pass it only once the reviewer has earned it.",
        },
        max_findings: {
          type: "number",
          description: "Cap on inline findings. Default 10.",
        },
      },
      required: ["repo", "number"],
      additionalProperties: false,
    },
    handler: (env, a) =>
      reviewPullRequest(env, str(a.repo, "repo"), num(a.number, "number"), {
        model: typeof a.model === "string" ? a.model : undefined,
        post: a.post === true,
        event: a.event === "REQUEST_CHANGES" ? "REQUEST_CHANGES" : "COMMENT",
        maxFindings:
          typeof a.max_findings === "number" ? a.max_findings : undefined,
      }),
  },
];

const TOOL_MAP = new Map(TOOLS.map((t) => [t.name, t]));

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

function ok(id: unknown, result: unknown) {
  return { jsonrpc: "2.0", id: id ?? null, result };
}

function err(id: unknown, code: number, message: string) {
  return { jsonrpc: "2.0", id: id ?? null, error: { code, message } };
}

/**
 * Handle a single JSON-RPC message. Returns null for notifications.
 *
 * Era-independent: version negotiation happens in index.ts before this is
 * called, and both eras dispatch the same tools. Only two methods are
 * era-specific — `initialize` (legacy) and `server/discover` (modern) — and
 * each is simply an unknown method to the other era's clients.
 */
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
      content: [{ type: "text", text: `Error: ${e.message}` }],
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
        type: "text",
        text: "Error: internal error. The cause is in the worker log, not in the arguments — the same call will fail the same way.",
      },
    ],
    isError: true,
  };
}

export async function handleRpc(
  req: JsonRpcRequest,
  env: Env,
): Promise<object | null> {
  switch (req.method) {
    case "initialize":
      // Legacy handshake. Modern clients never send this.
      return ok(req.id, {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: { tools: {} },
        serverInfo: SERVER_INFO,
      });
    case "server/discover":
      // Modern. Servers MUST implement it: one request returns the supported
      // versions, capabilities and identity a client would otherwise have to
      // probe for.
      return ok(req.id, {
        resultType: "complete",
        supportedVersions: [...SUPPORTED_MODERN_VERSIONS],
        capabilities: { tools: {} },
        _meta: { [META_SERVER_INFO]: SERVER_INFO },
        instructions:
          "GitHub review, pull request and issue operations for allowlisted Nyuchi repositories. Call nyuchi_whoami first: it reports, per repository, whether the App is installed and whether that installation grants the permissions the scoped token requests.",
      });
    case "notifications/initialized":
    case "notifications/cancelled":
      return null; // notifications get no response
    case "ping":
      return ok(req.id, {});
    case "tools/list":
      return ok(req.id, {
        tools: TOOLS.map((t) => ({
          name: t.name,
          description: t.description,
          inputSchema: t.inputSchema,
          annotations: t.annotations,
        })),
      });
    case "tools/call": {
      const name = req.params?.name as string;
      const args = (req.params?.arguments as Record<string, unknown>) || {};
      const tool = TOOL_MAP.get(name);
      if (!tool) return err(req.id, -32602, `unknown tool: ${name}`);
      try {
        const result = await tool.handler(env, args);
        const text =
          typeof result === "string" ? result : JSON.stringify(result, null, 2);
        return ok(req.id, { content: [{ type: "text", text }] });
      } catch (e) {
        return ok(req.id, toolError(name, e));
      }
    }
    default:
      // In the modern revision this maps to HTTP 404 (see index.ts); the
      // JSON-RPC body is what distinguishes it from a 404 served by something
      // that is not an MCP endpoint at all.
      return err(req.id, METHOD_NOT_FOUND, `method not found: ${req.method}`);
  }
}
