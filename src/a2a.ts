// A2A (Agent2Agent) surface — how other agents reach this reviewer.
//
// MCP is tool-oriented: a client calls a function and gets a return value.
// A2A is task-oriented: a client sends a message and gets back a Task with a
// lifecycle. A code review is genuinely a task, so this is the better fit of
// the two for agent callers — and it is the same review engine underneath,
// wrapped, not reimplemented.
//
// SYNCHRONOUS, DELIBERATELY. The spec says a non-blocking send "MUST wait
// until the task reaches a terminal state before returning", so a review that
// finishes inside the request may be returned COMPLETED with its result
// inline. That is what this does, and it is why there is no storage binding
// here: durable tasks need one, a synchronous task does not, and adding a
// Durable Object would mean bumping compatibility_date on a Worker that is
// live and working. Streaming and push are advertised as false because they
// are not implemented — an agent card that overstates is worse than a small
// one, since a client believes it.
//
// WIRE FORMAT IS v1.0. A2A 1.0 removed the `kind` discriminator everywhere:
// a text part is `{ text }`, not `{ kind: 'text', text }`, and the JSON
// member name is the discriminator. Writing the older shape produces
// something that looks right and no current client will parse.

import type { Env } from "./env";
import { GitHubError } from "./github";
import { reviewPullRequest, REVIEW_MODELS, DEFAULT_MODEL } from "./review";

export const A2A_PROTOCOL_VERSION = "1.0";

/** Terminal and interrupted task states this server can produce. */
export const TASK_COMPLETED = "TASK_STATE_COMPLETED";
export const TASK_FAILED = "TASK_STATE_FAILED";
export const TASK_REJECTED = "TASK_STATE_REJECTED";

/** JSON-RPC error codes. A2A rides the standard ones. */
export const INVALID_PARAMS = -32602;
export const METHOD_NOT_FOUND = -32601;

export interface A2ARequest {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: Record<string, unknown>;
}

/**
 * The Agent Card — how an agent discovers what this is and how to talk to it.
 *
 * Served unauthenticated, like the OAuth resource metadata beside it: a
 * client cannot authenticate until it has read which scheme to use. Nothing
 * here is secret, and the skills it lists are the ones actually implemented.
 */
export function agentCard(env: Env, baseUrl: string): Record<string, unknown> {
  const authServer =
    env.WORKOS_AUTHORIZATION_SERVER || "https://accounts.mukoko.com";
  return {
    name: "Shamwari for GitHub",
    description:
      "Reviews a pull request and reports what is wrong with it. Cannot approve, request changes, or affect merge state: findings are posted as a comment on the commit, which carries no review event.",
    version: "0.1.0",
    provider: { organization: "Nyuchi Africa", url: "https://nyuchi.com" },
    protocolVersion: A2A_PROTOCOL_VERSION,
    url: `${baseUrl}/a2a`,
    // Advertised honestly: neither is implemented, and a client that believes
    // otherwise will wait for events that never arrive.
    capabilities: {
      streaming: false,
      pushNotifications: false,
      extendedAgentCard: false,
    },
    defaultInputModes: ["text/plain"],
    defaultOutputModes: ["text/plain", "application/json"],
    // v1.0: the member name is the discriminator, not a `kind` field.
    securitySchemes: {
      workos: {
        openIdConnectSecurityScheme: {
          openIdConnectUrl: `${authServer}/.well-known/openid-configuration`,
        },
      },
    },
    security: [{ workos: [] }],
    skills: [
      {
        id: "review_pull_request",
        name: "Review a pull request",
        description:
          "Read a pull request's diff and report correctness, security and resource-handling defects, each naming a line the diff adds. Returns no findings when there are none, which is a correct outcome rather than a failure.",
        tags: ["code-review", "github", "static-analysis"],
        examples: [
          "Review nyuchi/web-services#18",
          "Check PR 42 in nyuchi/api-gateway for security problems",
        ],
        inputModes: ["text/plain"],
        outputModes: ["application/json"],
      },
    ],
  };
}

/** A v1.0 text part: the member name is the discriminator. */
const textPart = (text: string) => ({ text });

/** A v1.0 data part, which carries its own media type. */
const dataPart = (data: unknown) => ({
  data,
  mediaType: "application/json",
});

function message(role: "ROLE_AGENT" | "ROLE_USER", parts: unknown[]) {
  return { messageId: crypto.randomUUID(), role, parts };
}

/**
 * Pull `owner/repo` and a pull request number out of a message.
 *
 * Accepts a structured data part first, because an agent that can be precise
 * should not be made to phrase a sentence. Free text is the fallback, and it
 * is matched strictly: a bare number with no repository is ambiguous and is
 * refused rather than guessed at.
 */
export function extractTarget(params: Record<string, unknown>): {
  repo?: string;
  number?: number;
  error?: string;
} {
  const msg = params.message as Record<string, unknown> | undefined;
  const parts = Array.isArray(msg?.parts) ? (msg!.parts as unknown[]) : [];

  for (const p of parts) {
    const part = p as Record<string, unknown>;
    const data = part.data as Record<string, unknown> | undefined;
    if (data && typeof data.repo === "string") {
      const n = typeof data.number === "number" ? data.number : NaN;
      if (!Number.isInteger(n)) {
        return { error: "data part has `repo` but no integer `number`" };
      }
      return { repo: data.repo, number: n };
    }
  }

  const text = parts
    .map((p) => (p as Record<string, unknown>).text)
    .filter((t): t is string => typeof t === "string")
    .join(" ");
  if (!text.trim()) {
    return { error: "message has no text or data part naming a pull request" };
  }

  // owner/repo#N, or owner/repo followed by a number somewhere after it.
  const hash = text.match(/([\w.-]+\/[\w.-]+)#(\d+)/);
  if (hash) return { repo: hash[1], number: Number(hash[2]) };
  const loose = text.match(/([\w.-]+\/[\w.-]+)\D+(\d+)/);
  if (loose) return { repo: loose[1], number: Number(loose[2]) };

  return {
    error:
      "could not find a pull request. Give `owner/repo#number`, or a data part with { repo, number }.",
  };
}

const now = () => new Date().toISOString();

function task(
  id: string,
  contextId: string,
  state: string,
  parts: unknown[],
  artifacts?: unknown[],
) {
  return {
    id,
    contextId,
    // No `kind` field: A2A 1.0 removed the discriminator from Task.
    status: {
      state,
      message: message("ROLE_AGENT", parts),
      timestamp: now(),
    },
    ...(artifacts ? { artifacts } : {}),
  };
}

const ok = (id: unknown, result: unknown) => ({
  jsonrpc: "2.0",
  id: id ?? null,
  result,
});

const err = (id: unknown, code: number, message: string) => ({
  jsonrpc: "2.0",
  id: id ?? null,
  error: { code, message },
});

/**
 * Handle one A2A JSON-RPC message.
 *
 * GetTask is deliberately absent rather than stubbed. Every task this server
 * produces is already terminal when SendMessage returns, so there is nothing
 * to poll for — and answering GetTask with a fabricated "not found" would
 * tell a client its task was lost when in fact it was handed back.
 */
export async function handleA2A(
  req: A2ARequest,
  env: Env,
): Promise<object | null> {
  switch (req.method) {
    case "SendMessage": {
      const params = req.params ?? {};
      const contextId =
        typeof params.contextId === "string"
          ? params.contextId
          : crypto.randomUUID();
      const id = crypto.randomUUID();

      const { repo, number, error } = extractTarget(params);
      if (error || !repo || number === undefined) {
        // REJECTED, not FAILED: the agent understood the request and declined
        // it, which is a different thing from trying and breaking.
        return ok(
          req.id,
          task(id, contextId, TASK_REJECTED, [
            textPart(error ?? "no pull request named"),
          ]),
        );
      }

      const model =
        typeof params.model === "string"
          ? params.model
          : env.REVIEW_MODEL || REVIEW_MODELS[DEFAULT_MODEL];

      try {
        const result = await reviewPullRequest(env, repo, number, {
          model,
          // A2A callers get a dry run. Posting is the webhook path's job, and
          // an agent asking to see a review is not the same as asking for one
          // to be published under this App's name.
          post: false,
          trigger: "a2a",
        });
        return ok(
          req.id,
          task(
            id,
            contextId,
            TASK_COMPLETED,
            [textPart(result.summary || "Review complete.")],
            [
              {
                artifactId: crypto.randomUUID(),
                name: `review-${repo.replace("/", "-")}-${number}`,
                parts: [dataPart(result)],
              },
            ],
          ),
        );
      } catch (e) {
        const detail =
          e instanceof GitHubError
            ? e.message
            : "the review failed; the cause is in the worker log";
        if (!(e instanceof GitHubError)) {
          console.error(
            "a2a review failed:",
            e instanceof Error ? (e.stack ?? e.message) : String(e),
          );
        }
        return ok(req.id, task(id, contextId, TASK_FAILED, [textPart(detail)]));
      }
    }
    default:
      return err(
        req.id,
        METHOD_NOT_FOUND,
        `method not supported: ${req.method}. This agent implements SendMessage; every task it returns is already terminal, so there is nothing to poll.`,
      );
  }
}
