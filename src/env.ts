// Environment bindings for nyuchi-github-mcp.
//
// Secrets are set with `wrangler secret put <NAME>` and never committed.
// Everything else lives in wrangler.toml [vars] so the authorization policy
// is versioned and auditable alongside the code that enforces it.

export interface Env {
  // ---- GitHub App (the only secret this worker holds) ----------------------
  // The App's private key, PEM. Accepts GitHub's own download format
  // (PKCS#1, "BEGIN RSA PRIVATE KEY") or PKCS#8 ("BEGIN PRIVATE KEY") —
  // see toPkcs8() in github.ts. Taking PKCS#1 directly means the same secret
  // value works here and in RELEASE_APP_PRIVATE_KEY with no conversion step,
  // which is one fewer way to get it wrong.
  GITHUB_APP_PRIVATE_KEY: string;

  // ---- GitHub App identity and policy (public, wrangler.toml [vars]) -------
  GITHUB_APP_ID?: string; // numeric App ID, same value as RELEASE_APP_ID
  GITHUB_API?: string; // default https://api.github.com

  // Repository allowlist, comma-separated "owner/repo". EMPTY MEANS DENY ALL.
  // This is the outer bound: a tool call naming a repo outside this list is
  // refused before any token is minted, so the App's own installation scope
  // is never the only thing standing between the agent and a repository.
  GITHUB_ALLOWED_REPOS?: string;

  // Permissions requested when minting an installation token, as
  // "name:level" pairs. An installation token may request a SUBSET of what
  // the App holds, never a superset — so this narrows a broadly-scoped App
  // down to what an agent actually needs. Omitting `workflows` here is the
  // point: the App can push workflow files, the agent cannot.
  GITHUB_TOKEN_PERMISSIONS?: string;

  // ---- WorkOS Connect OAuth (public config; the worker only verifies) -----
  WORKOS_JWKS_URL?: string; // WorkOS Connect app's JWKS endpoint
  WORKOS_ISSUER?: string; // expected `iss` claim
  WORKOS_AUDIENCE?: string; // accepted `aud` values, comma-separated
  WORKOS_AUTHORIZATION_SERVER?: string; // advertised in resource metadata
  MCP_RESOURCE_URL?: string; // this resource's canonical URL

  // ---- Authorization gates (public policy) --------------------------------
  WORKOS_ORG_ID?: string; // required `org_id` claim — blocks other orgs
  WORKOS_REQUIRED_ROLES?: string; // comma-separated; one must match
  WORKOS_REQUIRED_PERMISSIONS?: string; // comma-separated; one must match
}

export function splitCsv(value: string | undefined): string[] {
  return (value || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}
