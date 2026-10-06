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
  /**
   * Context for the operator, logged but NEVER returned to the caller.
   *
   * The 401 body stays generic while the log says which gate rejected the
   * token and what it actually carried. Without this an auth failure is a
   * bare 401 in the request log and the only way to diagnose it is to guess.
   */
  readonly detail?: string;

  constructor(message: string, detail?: string) {
    super(message);
    this.name = "AuthError";
    this.detail = detail;
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
  resource?: string,
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
    throw new AuthError(
      "issuer mismatch",
      `token iss=${String(claims.iss)} expected=${env.WORKOS_ISSUER}`,
    );
  }
  // Also required. Without it this worker accepts any token the environment
  // minted for ANY of its resources: an MCP client holding a token for, say,
  // the MongoDB server could spend it here. The audience claim is the only
  // thing that binds a token to THIS resource, which is exactly the
  // confused-deputy case it exists to prevent.
  //
  // The accepted audiences are WORKOS_AUDIENCE (comma-separated; the Connect
  // client id and/or resource URI, because WorkOS stamps `aud` as either
  // depending on the token flow) PLUS the resource URI this request was
  // served under. A token minted for the resource the client discovered is
  // therefore always accepted on that host, without an operator having to
  // keep a static list in step with the hostnames: the static list is exactly
  // what a typo broke. Tokens minted for any other resource are still
  // refused. With neither a configured list nor a served resource, fail
  // closed rather than skip the check.
  {
    const accepted = [
      ...(env.WORKOS_AUDIENCE || "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
      ...(resource ? [resource] : []),
    ];
    if (!accepted.length) {
      throw new AuthError(
        "WorkOS auth is not configured (WORKOS_AUDIENCE unset)",
      );
    }
    const audClaim = claims.aud;
    const tokenAuds = Array.isArray(audClaim)
      ? audClaim
      : audClaim
        ? [audClaim]
        : [];
    const ok = accepted.some((a) => tokenAuds.includes(a));
    if (!ok) {
      throw new AuthError(
        "audience mismatch",
        `token aud=${JSON.stringify(tokenAuds)} accepted=${JSON.stringify(accepted)}`,
      );
    }
  }

  // Org gate — only members of the configured organization (blocks customers).
  if (env.WORKOS_ORG_ID && claims.org_id !== env.WORKOS_ORG_ID) {
    // Overwhelmingly the commonest cause: the signer belongs to several
    // organizations and AuthKit issued the token against the wrong one.
    throw new AuthError(
      "organization not permitted",
      `token org_id=${String(claims.org_id)} expected=${env.WORKOS_ORG_ID}`,
    );
  }

  // Platform permission gate — the caller must hold the required role OR
  // permission. WorkOS expresses the same grant three different ways
  // depending on how the token was obtained, and all three are read here:
  //
  //   claims.role / claims.roles   an AuthKit USER signing in
  //   claims.permissions           a third-party Connect app token
  //   claims.scope                 a WorkOS AGENT token (Agent Auth)
  //
  // The third is why an agent could authenticate but never get in: agent
  // tokens are signed by the same issuer and pass every check above, then
  // arrive at this gate carrying `scope` and no role at all. Reading scope
  // is what lets an agent connect without loosening anything for a person.
  const reqRoles = splitCsv(env.WORKOS_REQUIRED_ROLES);
  const reqPerms = splitCsv(env.WORKOS_REQUIRED_PERMISSIONS);
  if (reqRoles.length || reqPerms.length) {
    const roleClaim = claims.role;
    const rolesClaim = claims.roles;
    const tokenRoles = [
      ...(typeof roleClaim === "string" ? [roleClaim] : []),
      ...(Array.isArray(rolesClaim) ? (rolesClaim as string[]) : []),
    ];
    const tokenPerms = [...permissionsOf(claims), ...scopesOf(claims)];
    const roleOk =
      reqRoles.length > 0 && reqRoles.some((r) => tokenRoles.includes(r));
    const permOk =
      reqPerms.length > 0 && reqPerms.some((p) => tokenPerms.includes(p));
    if (!roleOk && !permOk) {
      throw new AuthError(
        "missing required platform role/permission",
        `token roles=${JSON.stringify(tokenRoles)} permissions=${JSON.stringify(tokenPerms)} required_roles=${JSON.stringify(reqRoles)} required_permissions=${JSON.stringify(reqPerms)}`,
      );
    }
  }

  return claims;
}

/** Permissions from a user or Connect-app token, which carry an array. */
function permissionsOf(claims: Record<string, unknown>): string[] {
  const p = claims.permissions;
  return Array.isArray(p) ? (p as string[]) : [];
}

/**
 * Permissions from a WorkOS agent token, which carries OAuth `scope`.
 *
 * Space-separated per RFC 6749, not an array — reading it as one silently
 * yields nothing and the agent is rejected for holding no permission, which
 * is indistinguishable from it genuinely holding none.
 */
function scopesOf(claims: Record<string, unknown>): string[] {
  const s = claims.scope;
  if (typeof s === "string") return s.split(" ").filter(Boolean);
  // Some issuers use the plural array form. Accept it rather than guess.
  if (Array.isArray(s))
    return (s as unknown[]).filter((v): v is string => typeof v === "string");
  return [];
}

/**
 * Who this token says is calling, for logs and audit.
 *
 * An agent token's `sub` is its registration id, and `act` is the RFC 8693
 * delegation claim naming the person who authorised it. Recording both is
 * the difference between "an agent did this" and "an agent did this FOR
 * someone" — which is the question asked after anything goes wrong.
 */
export function callerIdentity(claims: Record<string, unknown>): {
  kind: "agent" | "user";
  subject: string;
  onBehalfOf?: string;
  org?: string;
} {
  const sub = typeof claims.sub === "string" ? claims.sub : "";
  const act = claims.act as { sub?: unknown } | undefined;
  const onBehalfOf = act && typeof act.sub === "string" ? act.sub : undefined;
  return {
    kind: sub.startsWith("agent_") ? "agent" : "user",
    subject: sub,
    ...(onBehalfOf ? { onBehalfOf } : {}),
    ...(typeof claims.org_id === "string" ? { org: claims.org_id } : {}),
  };
}

/** The canonical resource, used when a request arrives on no allowed host. */
export const DEFAULT_RESOURCE_URL = "https://github.shamwari.ai/mcp";

/** The configured canonical resource URL, or the default. */
export function resourceUrl(env: Env): string {
  return env.MCP_RESOURCE_URL || DEFAULT_RESOURCE_URL;
}

/**
 * Hosts this worker may name itself under: MCP_RESOURCE_HOSTS plus the host
 * of the canonical MCP_RESOURCE_URL. Lower-cased; ports kept as given.
 */
export function allowedResourceHosts(env: Env): string[] {
  const hosts = splitCsv(env.MCP_RESOURCE_HOSTS).map((h) => h.toLowerCase());
  try {
    hosts.push(new URL(resourceUrl(env)).host.toLowerCase());
  } catch {
    // An unparseable MCP_RESOURCE_URL contributes nothing.
  }
  return [...new Set(hosts)];
}

/**
 * The resource URI for THIS request: `https://<served host>/mcp`.
 *
 * RFC 9728 requires the `resource` in the metadata to be the URL the client
 * is actually talking to; an MCP client that sees anything else refuses to
 * continue. Deriving it from the request means the metadata can never
 * disagree with the host serving it, which is exactly what the static
 * MCP_RESOURCE_URL on github.nyuchi.dev did (it named "github.shmwari.ai").
 *
 * Only an allowlisted host (or this worker's own *.workers.dev preview host)
 * is reflected. Anything else gets the canonical URL, so the worker never
 * names itself after an arbitrary Host header.
 */
export function resourceUrlFor(request: Request, env: Env): string {
  let url: URL;
  try {
    url = new URL(request.url);
  } catch {
    return resourceUrl(env);
  }
  const host = url.host.toLowerCase();
  const allowed =
    allowedResourceHosts(env).includes(host) || host.endsWith(".workers.dev");
  if (!allowed || url.protocol !== "https:") return resourceUrl(env);
  return `https://${host}/mcp`;
}

export const AUTHORIZATION_SERVER_MISSING =
  "WORKOS_AUTHORIZATION_SERVER is not configured";

/**
 * Parse — never concatenate — a configured AuthKit domain into an https origin.
 *
 * Accepts a bare host or an https origin, in any case. Any path, query or
 * fragment is dropped. A blank value, `http:`, any other scheme, embedded
 * credentials and anything `URL` cannot parse all throw an error whose message
 * starts with `AUTHORIZATION_SERVER_MISSING`. The result is `URL.origin`.
 */
export function normaliseAuthkitDomain(value: string | undefined): string {
  const raw = value?.trim();
  if (!raw) throw new Error(AUTHORIZATION_SERVER_MISSING);
  let url: URL;
  try {
    url = new URL(
      /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`,
    );
  } catch {
    throw new Error(
      `${AUTHORIZATION_SERVER_MISSING} (not a valid host or URL)`,
    );
  }
  if (url.protocol !== "https:" || url.username || url.password) {
    throw new Error(
      `${AUTHORIZATION_SERVER_MISSING} (must be an https origin)`,
    );
  }
  return url.origin;
}

/**
 * The AuthKit issuer to advertise, from configuration only — there is no
 * compiled-in default and no fallback host. Parsed by `normaliseAuthkitDomain`.
 * Null when unset or unusable (http, another scheme, credentials,
 * unparseable): the metadata and agent-card routes then answer 503.
 */
export function authorizationServer(env: Env): string | null {
  try {
    return normaliseAuthkitDomain(env.WORKOS_AUTHORIZATION_SERVER);
  } catch {
    return null;
  }
}

/**
 * OAuth 2.0 Protected Resource Metadata (RFC 9728) — points clients at WorkOS.
 * Null when WORKOS_AUTHORIZATION_SERVER is unset: the caller answers 503
 * rather than advertising a guessed host.
 */
export function protectedResourceMetadata(
  env: Env,
  resource: string = resourceUrl(env),
): Record<string, unknown> | null {
  const issuer = authorizationServer(env);
  if (!issuer) return null;
  return {
    resource,
    authorization_servers: [issuer],
    bearer_methods_supported: ["header"],
    // NO scopes_supported, deliberately.
    //
    // It is optional in RFC 9728, and advertising a scope the authorization
    // server does not define is worse than advertising none: a client reads
    // this document, asks WorkOS for those scopes, and WorkOS answers
    // `error=invalid_scope` straight back to the client's callback — so the
    // user never even reaches a login page, and the failure surfaces nowhere
    // near this file.
    //
    // This worker gates on organization, role and permission claims, not on
    // scopes, so it has nothing to advertise here. Do not add a scope unless
    // it exists in WorkOS and this worker actually checks it.
  };
}
