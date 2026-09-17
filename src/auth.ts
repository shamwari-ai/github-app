// WorkOS Connect OAuth for the GitHub MCP worker.
//
// Lifted from nyuchi-fly-mcp unchanged apart from the resource URL and
// advertised scopes: the verification logic is identical and deliberately
// kept that way, so a fix to one is a fix worth copying to the other.
//
// This worker is a *tool/integration*, not a user-facing application, so it
// authenticates callers with WorkOS **Connect** (OAuth) rather than an
// AuthKit login app. It acts as an OAuth 2.0 protected resource (MCP auth
// spec / RFC 9728): it verifies the WorkOS-issued access token on each call
// and advertises WorkOS as its authorization server via resource metadata.
//
// Token verification is done in-worker against the WorkOS JWKS with WebCrypto
// (RS256) — no secret needed for auth, only the public JWKS URL. The only
// secret this worker holds is the Fly token.

import { type Env, splitCsv } from "./env";

export class AuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuthError";
  }
}

interface Jwk {
  kid: string;
  kty: string;
  n: string;
  e: string;
  alg?: string;
}

// Per-isolate JWKS cache (isolates are ephemeral; this just avoids refetching
// on every request within one).
let jwksCache: { url: string; keys: Jwk[]; fetchedAt: number } | null = null;
const JWKS_TTL_MS = 10 * 60 * 1000;

function b64urlToBytes(input: string): Uint8Array {
  let s = input.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4 ? 4 - (s.length % 4) : 0;
  s += "=".repeat(pad);
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64urlToJson<T>(segment: string): T {
  return JSON.parse(new TextDecoder().decode(b64urlToBytes(segment))) as T;
}

async function getJwks(env: Env): Promise<Jwk[]> {
  const url = env.WORKOS_JWKS_URL;
  if (!url) {
    throw new AuthError(
      "WorkOS auth is not configured (WORKOS_JWKS_URL unset)",
    );
  }
  const now = Date.now();
  if (
    jwksCache &&
    jwksCache.url === url &&
    now - jwksCache.fetchedAt < JWKS_TTL_MS
  ) {
    return jwksCache.keys;
  }
  const res = await fetch(url);
  if (!res.ok) throw new AuthError(`JWKS fetch failed: ${res.status}`);
  const body = (await res.json()) as { keys: Jwk[] };
  jwksCache = { url, keys: body.keys || [], fetchedAt: now };
  return jwksCache.keys;
}

/**
 * Verify a WorkOS access token (RS256 JWT) and return its claims.
 * Throws AuthError on any failure — fails closed.
 */
export async function verifyWorkosToken(
  token: string,
  env: Env,
): Promise<Record<string, unknown>> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new AuthError("malformed token");
  const [headerB64, payloadB64, sigB64] = parts;

  const header = b64urlToJson<{ alg: string; kid?: string }>(headerB64);
  if (header.alg !== "RS256")
    throw new AuthError(`unsupported alg: ${header.alg}`);

  const keys = await getJwks(env);
  const jwk = keys.find((k) => k.kid === header.kid) ?? keys[0];
  if (!jwk) throw new AuthError("no matching signing key");

  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const data = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    b64urlToBytes(sigB64),
    data,
  );
  if (!valid) throw new AuthError("invalid token signature");

  const claims = b64urlToJson<Record<string, unknown>>(payloadB64);
  const nowSec = Math.floor(Date.now() / 1000);
  if (typeof claims.exp === "number" && claims.exp < nowSec) {
    throw new AuthError("token expired");
  }
  if (typeof claims.nbf === "number" && claims.nbf > nowSec) {
    throw new AuthError("token not yet valid");
  }
  // Required, not optional. Treating an unset WORKOS_ISSUER as "skip the
  // check" means a misconfigured worker silently accepts tokens from any
  // issuer whose key happens to be in the configured JWKS — fail-open on the
  // one variable an operator is most likely to forget.
  if (!env.WORKOS_ISSUER) {
    throw new AuthError("WorkOS auth is not configured (WORKOS_ISSUER unset)");
  }
  if (claims.iss !== env.WORKOS_ISSUER) {
    throw new AuthError("issuer mismatch");
  }
  // Also required. Without it this worker accepts any token the environment
  // minted for ANY of its resources: an MCP client holding a token for, say,
  // the MongoDB server could spend it here. The audience claim is the only
  // thing that binds a token to THIS resource, which is exactly the
  // confused-deputy case it exists to prevent.
  if (!env.WORKOS_AUDIENCE) {
    throw new AuthError(
      "WorkOS auth is not configured (WORKOS_AUDIENCE unset)",
    );
  }
  {
    // WORKOS_AUDIENCE may list several acceptable audiences (comma-separated) —
    // e.g. the Connect client id AND the resource URL — because WorkOS may
    // stamp `aud` as either depending on the token flow. The token's `aud`
    // may itself be a string or an array. Accept if any accepted value
    // appears in the token's audiences; still rejects tokens minted for
    // other apps.
    const accepted = env.WORKOS_AUDIENCE.split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const audClaim = claims.aud;
    const tokenAuds = Array.isArray(audClaim)
      ? audClaim
      : audClaim
        ? [audClaim]
        : [];
    const ok = accepted.some((a) => tokenAuds.includes(a));
    if (!ok) throw new AuthError("audience mismatch");
  }

  // Org gate — only members of the configured organization (blocks customers).
  if (env.WORKOS_ORG_ID && claims.org_id !== env.WORKOS_ORG_ID) {
    throw new AuthError("organization not permitted");
  }

  // Platform permission gate — the caller must hold the required role OR
  // permission (WorkOS may express the grant as either, and third-party app
  // tokens surface permissions rather than the org role). Satisfying any
  // configured dimension passes; a plain org member with neither is rejected.
  const reqRoles = splitCsv(env.WORKOS_REQUIRED_ROLES);
  const reqPerms = splitCsv(env.WORKOS_REQUIRED_PERMISSIONS);
  if (reqRoles.length || reqPerms.length) {
    const roleClaim = claims.role;
    const rolesClaim = claims.roles;
    const tokenRoles = [
      ...(typeof roleClaim === "string" ? [roleClaim] : []),
      ...(Array.isArray(rolesClaim) ? (rolesClaim as string[]) : []),
    ];
    const permsClaim = claims.permissions;
    const tokenPerms = Array.isArray(permsClaim)
      ? (permsClaim as string[])
      : [];
    const roleOk =
      reqRoles.length > 0 && reqRoles.some((r) => tokenRoles.includes(r));
    const permOk =
      reqPerms.length > 0 && reqPerms.some((p) => tokenPerms.includes(p));
    if (!roleOk && !permOk) {
      throw new AuthError("missing required platform role/permission");
    }
  }

  return claims;
}

export function resourceUrl(env: Env): string {
  return env.MCP_RESOURCE_URL || "https://github.nyuchi.dev/mcp";
}

/** OAuth 2.0 Protected Resource Metadata (RFC 9728) — points clients at WorkOS. */
export function protectedResourceMetadata(env: Env): Record<string, unknown> {
  return {
    resource: resourceUrl(env),
    authorization_servers: [
      env.WORKOS_AUTHORIZATION_SERVER || "https://api.workos.com",
    ],
    bearer_methods_supported: ["header"],
    scopes_supported: ["github:read", "github:review", "github:write"],
  };
}
