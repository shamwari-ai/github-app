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
  callerIdentity,
  AUTHORIZATION_SERVER_MISSING,
  protectedResourceMetadata,
  resourceUrlFor,
  verifyWorkosToken,
} from "./auth";
import { handleMcp } from "./mcp";
import { originAllowed } from "./origin";
import { handleWebhook } from "./webhook";
import { agentCard, handleA2A, type A2ARequest } from "./a2a";
import { appCreated, appInstalled, appNew } from "./setup";

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
function unauthorized(
  resource: string,
  message: string,
  invalidToken = false,
): Response {
  const metaUrl = new URL(
    "/.well-known/oauth-protected-resource",
    resource,
  ).toString();
  // RFC 6750: a presented-but-rejected token is `invalid_token`, and the
  // description names the gate that refused it (never the token or its
  // claims) so a client-side "authorization failed" can be diagnosed.
  const challenge = invalidToken
    ? `Bearer resource_metadata="${metaUrl}", error="invalid_token", error_description="${message.replace(/["\\]/g, "")}"`
    : `Bearer resource_metadata="${metaUrl}"`;
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
        "WWW-Authenticate": challenge,
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

    // A2A Agent Card — public, for the same reason the OAuth metadata below
    // is: a client cannot authenticate until it has read which scheme to use.
    // Both paths are served. `agent-card.json` is the 1.0 name and
    // `agent.json` the one before it, which is the same dual-era courtesy the
    // MCP layer extends and costs one line.
    if (
      url.pathname === "/.well-known/agent-card.json" ||
      url.pathname === "/.well-known/agent.json"
    ) {
      const card = agentCard(env, url.origin);
      // Fail closed: the authorization server comes only from configuration.
      if (!card) return json({ error: AUTHORIZATION_SERVER_MISSING }, 503);
      return json(card);
    }

    // OAuth 2.0 Protected Resource Metadata — public, so clients can discover
    // WorkOS as the authorization server.
    // Served at the root form and at the path-suffixed form RFC 9728 derives
    // from the resource URL (/.well-known/oauth-protected-resource/mcp); some
    // clients ask for one, some the other.
    const resource = resourceUrlFor(request, env);
    if (
      url.pathname === "/.well-known/oauth-protected-resource" ||
      url.pathname === "/.well-known/oauth-protected-resource/mcp"
    ) {
      const meta = protectedResourceMetadata(env, resource);
      if (!meta) return json({ error: AUTHORIZATION_SERVER_MISSING }, 503);
      return json(meta);
    }

    // GitHub App setup pages (manifest redirect and post-install). Public:
    // GitHub sends a browser here, and neither page holds or exchanges
    // anything. See src/setup.ts.
    if (request.method === "GET" && url.pathname === "/github-app/created") {
      return appCreated(url);
    }
    if (request.method === "GET" && url.pathname === "/github-app/new") {
      return appNew();
    }
    if (request.method === "GET" && url.pathname === "/github-app/installed") {
      return appInstalled();
    }

    const isA2A = url.pathname === "/a2a";
    if (url.pathname !== "/mcp" && !isA2A) {
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
    if (!originAllowed(request.headers.get("Origin"), resource)) {
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
      return unauthorized(resource, "missing bearer token");
    }
    let authInfo: {
      token: string;
      clientId: string;
      scopes: string[];
      extra?: Record<string, unknown>;
    };
    try {
      const claims = await verifyWorkosToken(token, env, resource);
      const scope = (claims as Record<string, unknown>).scope;
      authInfo = {
        token,
        clientId: String(
          (claims as Record<string, unknown>).client_id ?? claims.sub ?? "",
        ),
        scopes:
          typeof scope === "string" ? scope.split(" ").filter(Boolean) : [],
      };
      // Logged on every accepted call, because "an agent did this" and "an
      // agent did this FOR someone" are different answers to the question
      // asked after something goes wrong, and the token is the only place
      // that distinction exists.
      const who = callerIdentity(claims as Record<string, unknown>);
      console.log(
        `authorized ${who.kind}`,
        JSON.stringify({
          subject: who.subject,
          on_behalf_of: who.onBehalfOf,
          org: who.org,
        }),
      );
    } catch (e) {
      const message = e instanceof AuthError ? e.message : "unauthorized";
      const detail = e instanceof AuthError ? e.detail : undefined;
      // The response stays generic; the log names the gate and what the token
      // carried. Never log the token itself.
      console.warn(`auth rejected: ${message}${detail ? ` — ${detail}` : ""}`);
      return unauthorized(resource, message, true);
    }

    if (request.method !== "POST") {
      return json({ error: "method not allowed" }, 405);
    }

    // A2A shares this endpoint's authentication and nothing else. It is not
    // MCP: no protocol-version headers, no era detection, no batch. Handling
    // it here rather than in a second Worker is what lets one WorkOS token,
    // one App installation and one review engine serve both protocols.
    if (isA2A) {
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
      try {
        const response = await handleA2A(payload as A2ARequest, env);
        return json(response ?? {});
      } catch (e) {
        return internalError((payload as A2ARequest)?.id ?? null, e);
      }
    }

    // MCP: the SDK parses the request, picks the protocol era, validates
    // versions and headers, and answers. Everything above (method, Origin,
    // WorkOS token) has already been decided here, and the verified token is
    // handed over as authInfo rather than re-derived from headers.
    try {
      const response = await handleMcp(request, env, authInfo);
      const headers = new Headers(response.headers);
      for (const [k, v] of Object.entries(CORS)) headers.set(k, v);
      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers,
      });
    } catch (e) {
      return internalError(null, e);
    }
  },
};
