// shamwari-github-mcp — a Cloudflare Worker that exposes GitHub review, pull
// request and issue operations as an MCP server, guarded by WorkOS Connect.
//
// The GitHub App private key lives here as a Worker secret; callers
// authenticate with a WorkOS-issued access token, and every GitHub call runs
// on an installation token scoped down to one allowlisted repository.
//
//   POST /mcp                                    MCP Streamable HTTP (JSON-RPC 2.0)
//   GET  /.well-known/oauth-protected-resource   OAuth resource metadata
//   GET  /health                                 liveness probe (no auth)

import type { Env } from "./env";
import { GitHubError } from "./github";
import {
  AuthError,
  protectedResourceMetadata,
  resourceUrl,
  verifyWorkosToken,
} from "./auth";
import { handleRpc } from "./mcp";
import {
  HEADER_MISMATCH,
  METHOD_NOT_FOUND,
  UNSUPPORTED_PROTOCOL_VERSION,
  detectEra,
  originAllowed,
  validateModernRequest,
  type JsonRpcLike,
} from "./protocol";
import { handleWebhook } from "./webhook";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
  // Mcp-Method and Mcp-Name are the 2026-07-28 mirrored headers; without them
  // listed here a browser-based client's preflight fails before the request
  // this server is meant to validate ever arrives.
  "Access-Control-Allow-Headers":
    "Authorization, Content-Type, Mcp-Session-Id, Mcp-Protocol-Version, MCP-Protocol-Version, Mcp-Method, Mcp-Name",
  "Access-Control-Expose-Headers": "WWW-Authenticate",
} as const;

/** A JSON-RPC error response with the HTTP status the modern revision requires. */
function rpcError(
  id: unknown,
  code: number,
  message: string,
  status: number,
  data?: unknown,
): Response {
  const error: Record<string, unknown> = { code, message };
  if (data !== undefined) error.data = data;
  return new Response(
    JSON.stringify({ jsonrpc: "2.0", id: id ?? null, error }),
    { status, headers: { "Content-Type": "application/json", ...CORS } },
  );
}

/**
 * A 5xx that does not hand the caller an exception message.
 *
 * An unexpected error's message can carry internal paths, stack frames, or
 * upstream detail the caller has no business seeing — CodeQL flags exactly
 * this as "information exposure through a stack trace". GitHubError messages
 * are constructed in this codebase from GitHub's own API response and are
 * meant to be actionable, so they are returned; anything else is logged in
 * full and answered generically.
 */
export function internalError(id: unknown, e: unknown): Response {
  if (e instanceof GitHubError) {
    return rpcError(id, -32603, e.message, 502);
  }
  console.error(
    "unhandled error:",
    e instanceof Error ? (e.stack ?? e.message) : String(e),
  );
  return rpcError(id, -32603, "internal error", 500);
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...CORS },
  });
}

/** 401 pointing MCP clients at the OAuth resource metadata (WorkOS). */
function unauthorized(env: Env, message: string): Response {
  const metaUrl = new URL(
    "/.well-known/oauth-protected-resource",
    resourceUrl(env),
  ).toString();
  return new Response(
    JSON.stringify({
      jsonrpc: "2.0",
      id: null,
      error: { code: -32001, message },
    }),
    {
      status: 401,
      headers: {
        "Content-Type": "application/json",
        "WWW-Authenticate": `Bearer resource_metadata="${metaUrl}"`,
        ...CORS,
      },
    },
  );
}

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS });
    }

    if (url.pathname === "/health") {
      return json({ status: "ok", server: "shamwari-github-mcp" });
    }

    // GitHub webhook ingest. NOT behind the WorkOS bearer check: GitHub does
    // not carry one. It authenticates with its own HMAC signature over the
    // raw body instead, which handleWebhook verifies before reading anything
    // else from the request.
    if (url.pathname === "/webhook") {
      return handleWebhook(request, env, ctx);
    }

    // OAuth 2.0 Protected Resource Metadata — public, so clients can discover
    // WorkOS as the authorization server.
    if (url.pathname === "/.well-known/oauth-protected-resource") {
      return json(protectedResourceMetadata(env));
    }

    if (url.pathname !== "/mcp") {
      return json({ error: "not found" }, 404);
    }

    // Protocol-level sessions and the standalone GET stream were removed in
    // 2026-07-28. A server that only speaks this revision answers GET and
    // DELETE on the MCP endpoint with 405.
    if (request.method === "GET" || request.method === "DELETE") {
      return json({ error: "method not allowed" }, 405);
    }

    // Servers MUST validate Origin to prevent DNS rebinding. Absent Origin is
    // allowed: non-browser MCP clients do not send one.
    if (!originAllowed(request.headers.get("Origin"), resourceUrl(env))) {
      return json({ error: "forbidden origin" }, 403);
    }

    // WorkOS Connect: verify the caller's access token on every /mcp request.
    const header = request.headers.get("Authorization") || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : "";
    if (!token) {
      // Logged because Cloudflare redacts the Authorization header, so the
      // request log alone cannot distinguish "client sent no token" from
      // "token was rejected" — and those have completely different causes.
      console.warn("auth rejected: no bearer token presented");
      return unauthorized(env, "missing bearer token");
    }
    try {
      await verifyWorkosToken(token, env);
    } catch (e) {
      const message = e instanceof AuthError ? e.message : "unauthorized";
      const detail = e instanceof AuthError ? e.detail : undefined;
      // The response stays generic; the log names the gate and what the token
      // carried. Never log the token itself.
      console.warn(`auth rejected: ${message}${detail ? ` — ${detail}` : ""}`);
      return unauthorized(env, message);
    }

    if (request.method !== "POST") {
      return json({ error: "method not allowed" }, 405);
    }

    let payload: unknown;
    try {
      payload = await request.json();
    } catch {
      return json(
        {
          jsonrpc: "2.0",
          id: null,
          error: { code: -32700, message: "parse error" },
        },
        400,
      );
    }

    // 2026-07-28 sends one JSON-RPC message per POST. Batches belong to the
    // legacy revision, so they are answered but never version-validated.
    if (Array.isArray(payload)) {
      try {
        const responses = (
          await Promise.all(payload.map((m) => handleRpc(m, env)))
        ).filter((r): r is object => r !== null);
        return json(responses);
      } catch (e) {
        return internalError(null, e);
      }
    }

    const body = payload as JsonRpcLike;
    const era = detectEra(body);

    // Modern requests mirror version, method and name into headers so
    // intermediaries can route without parsing the body. Validating them here
    // is what stops a proxy and this worker acting on different values.
    if (era === "modern") {
      const problem = validateModernRequest(request.headers, body);
      if (problem) {
        return rpcError(
          body.id,
          problem.code,
          problem.message,
          problem.status,
          problem.data,
        );
      }
    }

    try {
      const response = await handleRpc(body as never, env);
      if (response === null)
        return new Response(null, { status: 202, headers: CORS });

      // An unknown method is 404 in the modern revision; the JSON-RPC body is
      // what tells a client this is an MCP endpoint that lacks the method,
      // rather than a URL that is not an MCP endpoint at all. Legacy clients
      // keep getting 200, as their revision expects.
      const rpcErr = (response as { error?: { code?: number } }).error;
      if (era === "modern" && rpcErr?.code === METHOD_NOT_FOUND) {
        return json(response, 404);
      }
      if (
        era === "modern" &&
        (rpcErr?.code === HEADER_MISMATCH ||
          rpcErr?.code === UNSUPPORTED_PROTOCOL_VERSION)
      ) {
        return json(response, 400);
      }
      return json(response);
    } catch (e) {
      return internalError(body.id, e);
    }
  },
};
