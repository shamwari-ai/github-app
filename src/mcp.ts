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
import {
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

export const PROTOCOL_VERSION = "2025-06-18";

export const SERVER_INFO = {
  name: "nyuchi-github-mcp",
  version: "0.1.0",
} as const;

interface Tool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  handler: (env: Env, args: Record<string, unknown>) => Promise<unknown>;
}

const str = (v: unknown, field: string): string => {
  if (typeof v !== "string" || !v)
    throw new Error(`missing/invalid "${field}"`);
  return v;
};

const num = (v: unknown, field: string): number => {
  if (typeof v !== "number" || !Number.isFinite(v))
    throw new Error(`missing/invalid "${field}"`);
  return v;
};

const REPO_PROP = {
  type: "string",
  description: "Repository as owner/repo. Must be in the worker's allowlist.",
} as const;

export const TOOLS: Tool[] = [
  {
    name: "github_whoami",
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
    name: "github_list_pull_requests",
    description: "List pull requests, most recently updated first.",
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
      ),
  },
  {
    name: "github_get_pull_request",
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
    name: "github_get_pull_request_diff",
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
    name: "github_create_review",
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
    name: "github_create_pull_request",
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
    name: "github_update_pull_request",
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
      if (Object.keys(patch).length === 0) throw new Error("nothing to update");
      return updatePullRequest(
        env,
        str(a.repo, "repo"),
        num(a.number, "number"),
        patch,
      );
    },
  },
  {
    name: "github_list_issues",
    description:
      "List issues, most recently updated first. Note GitHub returns pull requests here too; entries carrying a pull_request field are PRs.",
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
      ),
  },
  {
    name: "github_get_issue",
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
    name: "github_create_issue",
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
    name: "github_update_issue",
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
      if (Object.keys(patch).length === 0) throw new Error("nothing to update");
      return updateIssue(
        env,
        str(a.repo, "repo"),
        num(a.number, "number"),
        patch,
      );
    },
  },
  {
    name: "github_comment",
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

/** Handle a single JSON-RPC message. Returns null for notifications. */
export async function handleRpc(
  req: JsonRpcRequest,
  env: Env,
): Promise<object | null> {
  switch (req.method) {
    case "initialize":
      return ok(req.id, {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: { tools: {} },
        serverInfo: SERVER_INFO,
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
        const message = e instanceof Error ? e.message : String(e);
        return ok(req.id, {
          content: [{ type: "text", text: `Error: ${message}` }],
          isError: true,
        });
      }
    }
    default:
      return err(req.id, -32601, `method not found: ${req.method}`);
  }
}
