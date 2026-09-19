// Environment bindings for shamwari-github-mcp.
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

  // ---- Review agent (Workers AI) ------------------------------------------
  // GitHub webhook shared secret. A SECRET, set with `wrangler secret put`.
  // Unset means /webhook answers 503: an endpoint that runs model calls on
  // unauthenticated input is an endpoint anyone can bill to this account.
  GITHUB_WEBHOOK_SECRET?: string;

  // The inference binding. Declared optional so every existing test can keep
  // constructing an Env without one; reviewPullRequest() checks for it and
  // says what to add rather than throwing on undefined.
  AI?: {
    run(
      model: string,
      input: Record<string, unknown>,
      // The AI Gateway options. A THIRD argument, not a field of `input` —
      // see gatewayOptions() in review.ts for why that distinction bites.
      options?: Record<string, unknown>,
    ): Promise<unknown>;
  };

  // Full Workers AI model id, e.g. "@cf/zai-org/glm-5.3". A var rather than a
  // constant so the model can be changed, and compared, without a deploy of
  // new code — which is the whole point of the bake-off.
  REVIEW_MODEL?: string;

  // Quality and cost ceiling on the annotated diff, in bytes. Not a context
  // limit: every candidate model holds at least 262K tokens.
  REVIEW_MAX_DIFF_BYTES?: string;

  // The handle that summons a review in a comment, e.g. "@shamwari". A var
  // so the agent's public name can change without a code change.
  REVIEW_MENTION?: string;

  // Which author_association values may summon a review, comma-separated.
  // Default OWNER,MEMBER,COLLABORATOR. This is a spending gate as much as an
  // access one: on a public repository anyone can comment, and without it a
  // stranger typing the handle bills model calls to the repository owner.
  REVIEW_TRIGGER_ASSOCIATIONS?: string;

  // AI Gateway to route inference through. Unset means calling Workers AI
  // directly. Set it and you get caching, rate limiting, retries, and a log
  // of every review with metadata attached — which is what turns "what did
  // this cost?" from a guess into a query.
  AI_GATEWAY_ID?: string;

  // KILL SWITCH. Exactly "false" disables the reviewer. Compared against the
  // string "false" rather than treated as a boolean so that an unset or
  // misspelled value leaves the agent ENABLED-but-inert only where that is
  // safe — here the agent cannot act without an explicit call anyway, and a
  // typo silently disabling review would be its own kind of failure.
  REVIEW_ENABLED?: string;

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
