// nyuchi-github-mcp — a Cloudflare Worker that exposes GitHub review, pull
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

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
  "Access-Control-Allow-Headers":
    "Authorization, Content-Type, Mcp-Session-Id, Mcp-Protocol-Version",
  "Access-Control-Expose-Headers": "WWW-Authenticate",
} as const;

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
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS });
    }

    if (url.pathname === "/health") {
      return json({ status: "ok", server: "nyuchi-github-mcp" });
    }

    // OAuth 2.0 Protected Resource Metadata — public, so clients can discover
    // WorkOS as the authorization server.
    if (url.pathname === "/.well-known/oauth-protected-resource") {
      return json(protectedResourceMetadata(env));
    }

    if (url.pathname !== "/mcp") {
      return json({ error: "not found" }, 404);
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

    try {
      if (Array.isArray(payload)) {
        const responses = (
          await Promise.all(payload.map((m) => handleRpc(m, env)))
        ).filter((r): r is object => r !== null);
        return json(responses);
      }
      const response = await handleRpc(payload as never, env);
      if (response === null)
        return new Response(null, { status: 202, headers: CORS });
      return json(response);
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      const status = e instanceof GitHubError ? 502 : 500;
      return json(
        { jsonrpc: "2.0", id: null, error: { code: -32603, message } },
        status,
      );
    }
  },
};
