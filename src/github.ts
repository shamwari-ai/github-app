// GitHub App client for the MCP worker.
//
// A Worker cannot use the official Octokit App plumbing wholesale, so this
// does the three things that matter by hand:
//
//   1. Sign an App JWT (RS256) with WebCrypto.
//   2. Exchange it for an INSTALLATION token scoped down to one repository
//      and a reduced permission set.
//   3. Call the REST API with that token.
//
// Step 2 is the security story. The App this worker authenticates as is the
// same one that mints release tokens, and it holds Contents, Pull requests
// and Workflows read/write. An installation token may request a subset of
// what the App holds, so the agent runs with `pull_requests: write`,
// `issues: write`, `contents: read` and NO `workflows` — it can review and
// file, it cannot push a workflow file or cut a release. One App, two very
// different effective capabilities.

import { type Env, splitCsv } from "./env";

export class GitHubError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly detail: unknown,
  ) {
    super(message);
    this.name = "GitHubError";
  }
}

const api = (env: Env) => env.GITHUB_API || "https://api.github.com";

const DEFAULT_PERMISSIONS =
  "pull_requests:write,issues:write,contents:read,metadata:read";

// ---------------------------------------------------------------------------
// Repository allowlist
// ---------------------------------------------------------------------------

/**
 * Resolve "owner/repo" and refuse anything outside GITHUB_ALLOWED_REPOS.
 *
 * Checked before a token is minted, so a repo outside the list never reaches
 * GitHub at all. An unset/empty allowlist denies everything rather than
 * allowing everything — a misconfigured worker should be useless, not open.
 */
export function resolveRepo(
  env: Env,
  repo: string,
): { owner: string; name: string } {
  const allowed = splitCsv(env.GITHUB_ALLOWED_REPOS);
  if (allowed.length === 0) {
    throw new GitHubError(
      "no repositories are allowlisted (GITHUB_ALLOWED_REPOS is unset) — refusing every repo",
      403,
      null,
    );
  }
  const slug = repo.trim();
  if (!allowed.some((a) => a.toLowerCase() === slug.toLowerCase())) {
    throw new GitHubError(
      `repository "${slug}" is not allowlisted; permitted: ${allowed.join(", ")}`,
      403,
      null,
    );
  }
  const [owner, name] = slug.split("/");
  if (!owner || !name)
    throw new GitHubError(
      `malformed repo "${slug}", expected owner/repo`,
      400,
      null,
    );
  return { owner, name };
}

// ---------------------------------------------------------------------------
// App JWT
// ---------------------------------------------------------------------------

function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// derLength, pkcs1ToPkcs8 and pemBody are exported for the test suite only.
// Nothing outside this module should be wrapping keys; they are public so the
// tests exercise the real code rather than a copy that can drift from it.
export function derLength(n: number): number[] {
  if (n < 0x80) return [n];
  const bytes: number[] = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v >>= 8;
  }
  return [0x80 | bytes.length, ...bytes];
}

/**
 * Wrap a PKCS#1 RSA key in the PKCS#8 envelope WebCrypto requires.
 *
 * GitHub hands you "BEGIN RSA PRIVATE KEY" (PKCS#1); crypto.subtle.importKey
 * only takes 'pkcs8'. Rather than make every operator run
 * `openssl pkcs8 -topk8`, wrap it here:
 *
 *   SEQUENCE { INTEGER 0, SEQUENCE { OID rsaEncryption, NULL }, OCTET STRING pkcs1 }
 */
export function pkcs1ToPkcs8(pkcs1: Uint8Array): Uint8Array {
  const version = [0x02, 0x01, 0x00];
  // AlgorithmIdentifier: rsaEncryption (1.2.840.113549.1.1.1) + NULL params
  const algorithm = [
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
    0x01, 0x05, 0x00,
  ];
  const octet = [0x04, ...derLength(pkcs1.length)];
  const bodyLength =
    version.length + algorithm.length + octet.length + pkcs1.length;
  const out = new Uint8Array(1 + derLength(bodyLength).length + bodyLength);
  let i = 0;
  out[i++] = 0x30;
  for (const b of derLength(bodyLength)) out[i++] = b;
  for (const b of version) out[i++] = b;
  for (const b of algorithm) out[i++] = b;
  for (const b of octet) out[i++] = b;
  out.set(pkcs1, i);
  return out;
}

export function pemBody(pem: string): { der: Uint8Array; pkcs1: boolean } {
  const trimmed = (pem || "").trim();
  // Insist on the markers. Without them the replaces below match nothing and
  // any base64-shaped string survives to atob(), producing a junk key that
  // fails much later inside WebCrypto with an opaque error.
  if (!/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(trimmed)) {
    throw new GitHubError(
      "GITHUB_APP_PRIVATE_KEY is empty or not a PEM",
      500,
      null,
    );
  }
  const pkcs1 = trimmed.includes("BEGIN RSA PRIVATE KEY");
  const base64 = trimmed
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----/, "")
    .replace(/-----END [A-Z ]*PRIVATE KEY-----/, "")
    .replace(/\s+/g, "");
  if (!base64)
    throw new GitHubError(
      "GITHUB_APP_PRIVATE_KEY is empty or not a PEM",
      500,
      null,
    );
  const bin = atob(base64);
  const der = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) der[i] = bin.charCodeAt(i);
  return { der, pkcs1 };
}

let signingKey: CryptoKey | null = null;

async function getSigningKey(env: Env): Promise<CryptoKey> {
  if (signingKey) return signingKey;
  if (!env.GITHUB_APP_PRIVATE_KEY) {
    throw new GitHubError("GITHUB_APP_PRIVATE_KEY is not set", 500, null);
  }
  const { der, pkcs1 } = pemBody(env.GITHUB_APP_PRIVATE_KEY);
  const pkcs8 = pkcs1 ? pkcs1ToPkcs8(der) : der;
  signingKey = await crypto.subtle.importKey(
    "pkcs8",
    pkcs8 as unknown as ArrayBuffer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return signingKey;
}

/**
 * Mint an App JWT. `iat` is backdated 60s because GitHub rejects a token
 * whose `iat` is in the future relative to its own clock, and a Worker's
 * clock can be marginally ahead. Ten-minute maximum life; nine is polite.
 */
async function appJwt(env: Env): Promise<string> {
  const appId = (env.GITHUB_APP_ID || "").trim();
  if (!appId) throw new GitHubError("GITHUB_APP_ID is not set", 500, null);
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const payload = { iat: now - 60, exp: now + 540, iss: appId };
  const enc = new TextEncoder();
  const unsigned = `${b64url(enc.encode(JSON.stringify(header)))}.${b64url(
    enc.encode(JSON.stringify(payload)),
  )}`;
  const key = await getSigningKey(env);
  const sig = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    enc.encode(unsigned),
  );
  return `${unsigned}.${b64url(new Uint8Array(sig))}`;
}

// ---------------------------------------------------------------------------
// Installation tokens, scoped down
// ---------------------------------------------------------------------------

interface CachedToken {
  token: string;
  expiresAt: number;
}

// Per-isolate cache keyed by owner/repo. Isolates are ephemeral, so this only
// saves round-trips within one; it is not a durable store.
const tokenCache = new Map<string, CachedToken>();

function requestedPermissions(env: Env): Record<string, string> {
  const spec = env.GITHUB_TOKEN_PERMISSIONS || DEFAULT_PERMISSIONS;
  const out: Record<string, string> = {};
  for (const pair of splitCsv(spec)) {
    const [name, level] = pair.split(":").map((s) => s.trim());
    if (name && level) out[name] = level;
  }
  return out;
}

async function githubJson(
  url: string,
  init: RequestInit,
  context: string,
): Promise<{ status: number; body: unknown }> {
  const res = await fetch(url, {
    ...init,
    headers: {
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "shamwari-github-mcp",
      ...(init.headers || {}),
    },
  });
  const text = await res.text();
  let body: unknown = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }
  if (!res.ok) {
    const message =
      body && typeof body === "object" && "message" in body
        ? String((body as { message: unknown }).message)
        : `HTTP ${res.status}`;
    throw new GitHubError(`${context}: ${message}`, res.status, body);
  }
  return { status: res.status, body };
}

/**
 * Get an installation token scoped to one repository and a reduced
 * permission set.
 *
 * If the App does not hold a permission requested here, GitHub answers 422
 * rather than silently granting less — the error is surfaced verbatim so a
 * missing App permission is diagnosable rather than mysterious. The release
 * App, for instance, holds no Issues permission today, so issue tools fail
 * with a 422 naming it until Issues: read/write is added to the App.
 */
/**
 * Which requested permissions an installation does not satisfy, as
 * "name:level" strings.
 *
 * `write` satisfies a `read` request; `read` does not satisfy `write`. Getting
 * that backwards would either hide a real gap or report a false one, and the
 * whole point of this report is to be trusted when a 422 shows up.
 */
export function missingPermissions(
  requested: Record<string, string>,
  granted: Record<string, string>,
): string[] {
  return Object.entries(requested)
    .filter(([perm, level]) => {
      const held = granted[perm];
      if (!held) return true;
      if (level === "write") return held !== "write";
      return false;
    })
    .map(([perm, level]) => `${perm}:${level}`);
}

interface Installation {
  id?: number;
  /**
   * What the installation ACTUALLY grants — which is not the same as what the
   * App declares. Adding a permission to an App puts the installation into
   * "pending review" until an owner accepts it; until then the App advertises
   * the permission and the installation withholds it. Reading it from here is
   * the only way to tell those two states apart.
   */
  permissions?: Record<string, string>;
  repository_selection?: string;
  account?: { login?: string };
}

async function installationFor(
  env: Env,
  owner: string,
  name: string,
  jwt?: string,
): Promise<Installation> {
  const token = jwt ?? (await appJwt(env));
  const { body } = await githubJson(
    `${api(env)}/repos/${owner}/${name}/installation`,
    { headers: { Authorization: `Bearer ${token}` } },
    `resolving the App installation on ${owner}/${name}`,
  );
  return body as Installation;
}

async function installationToken(
  env: Env,
  owner: string,
  name: string,
): Promise<string> {
  const cacheKey = `${owner}/${name}`.toLowerCase();
  const cached = tokenCache.get(cacheKey);
  if (cached && cached.expiresAt - 60_000 > Date.now()) return cached.token;

  const jwt = await appJwt(env);
  const auth = { Authorization: `Bearer ${jwt}` };

  const install = await installationFor(env, owner, name, jwt);
  const installationId = install.id;
  if (!installationId) {
    throw new GitHubError(
      `no installation id returned for ${owner}/${name}`,
      502,
      install,
    );
  }

  const { body: minted } = await githubJson(
    `${api(env)}/app/installations/${installationId}/access_tokens`,
    {
      method: "POST",
      headers: { ...auth, "Content-Type": "application/json" },
      body: JSON.stringify({
        repositories: [name],
        permissions: requestedPermissions(env),
      }),
    },
    `minting a scoped installation token for ${owner}/${name}`,
  );

  const { token, expires_at } = minted as {
    token?: string;
    expires_at?: string;
  };
  if (!token)
    throw new GitHubError(
      "no token in installation token response",
      502,
      minted,
    );
  tokenCache.set(cacheKey, {
    token,
    expiresAt: expires_at ? Date.parse(expires_at) : Date.now() + 30 * 60_000,
  });
  return token;
}

/** Authenticated REST call against an allowlisted repository. */
async function repoApi(
  env: Env,
  repo: string,
  path: string,
  init: RequestInit = {},
  accept?: string,
): Promise<unknown> {
  const { owner, name } = resolveRepo(env, repo);
  const token = await installationToken(env, owner, name);
  const url = `${api(env)}/repos/${owner}/${name}${path}`;
  const headers: Record<string, string> = {
    Authorization: `Bearer ${token}`,
    ...((init.headers as Record<string, string>) || {}),
  };
  if (accept) headers.Accept = accept;
  if (init.body) headers["Content-Type"] = "application/json";
  const { body } = await githubJson(
    url,
    { ...init, headers },
    `${init.method || "GET"} ${path}`,
  );
  return body;
}

/** Raw-text REST call (diffs and patches are not JSON). */
async function repoText(
  env: Env,
  repo: string,
  path: string,
  accept: string,
): Promise<string> {
  const { owner, name } = resolveRepo(env, repo);
  const token = await installationToken(env, owner, name);
  const res = await fetch(`${api(env)}/repos/${owner}/${name}${path}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: accept,
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "shamwari-github-mcp",
    },
  });
  const text = await res.text();
  if (!res.ok)
    throw new GitHubError(`GET ${path}: HTTP ${res.status}`, res.status, text);
  return text;
}

// ---------------------------------------------------------------------------
// Operations — plain functions, so the webhook-driven layer (M2) calls the
// same code the MCP tools do rather than reimplementing it.
// ---------------------------------------------------------------------------

export async function whoami(env: Env): Promise<unknown> {
  const jwt = await appJwt(env);
  const { body: app } = await githubJson(
    `${api(env)}/app`,
    { headers: { Authorization: `Bearer ${jwt}` } },
    "reading the authenticated App",
  );
  const a = app as {
    slug?: string;
    name?: string;
    permissions?: Record<string, string>;
  };
  const declared = a.permissions || {};
  const requested = requestedPermissions(env);
  const allowed = splitCsv(env.GITHUB_ALLOWED_REPOS);

  // Probe every allowlisted repository rather than reporting the App alone.
  // A token mint asks for the WHOLE permission set in one call, so one missing
  // permission fails every tool, not just the ones that need it — and the App
  // declaring a permission does not mean the installation has accepted it.
  // Checking here turns "everything returns 422" into a named cause.
  const repositories = await Promise.all(
    allowed.map(async (slug) => {
      const [owner, name] = slug.split("/");
      if (!owner || !name) {
        return {
          repo: slug,
          ok: false,
          error: "malformed, expected owner/repo",
        };
      }
      try {
        const install = await installationFor(env, owner, name, jwt);
        const granted = install.permissions || {};
        const missing = missingPermissions(requested, granted);
        return {
          repo: slug,
          installed: true,
          installation_id: install.id,
          repository_selection: install.repository_selection,
          granted,
          missing,
          ok: missing.length === 0,
        };
      } catch (e) {
        const status = e instanceof GitHubError ? e.status : 0;
        return {
          repo: slug,
          installed: false,
          ok: false,
          error:
            status === 404
              ? "the App is not installed on this repository (or the installation does not include it)"
              : e instanceof Error
                ? e.message
                : String(e),
        };
      }
    }),
  );

  const broken = repositories.filter((r) => !r.ok);
  return {
    app: { slug: a.slug, name: a.name },
    app_declared_permissions: declared,
    token_permissions_requested: requested,
    repositories,
    ready: broken.length === 0,
    note:
      broken.length === 0
        ? "Every allowlisted repository has an installation granting the permissions the scoped token asks for."
        : `Not ready: ${broken.map((r) => r.repo).join(", ")}. A token mint requests the whole permission set at once, so any gap here fails EVERY tool on that repository, not only the ones needing the missing permission. Note that adding a permission to the App leaves the installation pending an owner's approval — "granted" above is what the installation actually holds, which is what matters.`,
  };
}

// paginate, slimPull and slimIssue are exported for the test suite only —
// nothing outside this module should be reshaping GitHub payloads.
/**
 * One page of results, with enough metadata to know whether more exist.
 *
 * GitHub signals "more" through a Link header this client does not read, so
 * the page is fetched one item over the requested limit: if the extra item
 * arrives, there is another page. Costs nothing and needs no header parsing.
 */
interface Page<T> {
  items: T[];
  count: number;
  page: number;
  has_more: boolean;
  next_page?: number;
}

export function paginate<T>(rows: T[], limit: number, page: number): Page<T> {
  const has_more = rows.length > limit;
  const items = has_more ? rows.slice(0, limit) : rows;
  return {
    items,
    count: items.length,
    page,
    has_more,
    ...(has_more ? { next_page: page + 1 } : {}),
  };
}

/**
 * Trim a GitHub object down to what a caller reviewing or triaging needs.
 *
 * A raw pull request carries 36 top-level fields, including nested user, head,
 * base, _links and a full repository object on every row. Measured on this
 * repository, thirteen of them serialise to 276,801 bytes against 3,842 for
 * the fields below — 99% of the payload is structure nothing reads. Anything
 * omitted here is one shamwari_get_pull_request away.
 */
export function slimPull(p: Record<string, unknown>) {
  return {
    number: p.number,
    title: p.title,
    state: p.state,
    draft: p.draft,
    author: (p.user as { login?: string } | undefined)?.login,
    base: (p.base as { ref?: string } | undefined)?.ref,
    head: (p.head as { ref?: string } | undefined)?.ref,
    labels: (p.labels as Array<{ name?: string }> | undefined)?.map(
      (l) => l.name,
    ),
    created_at: p.created_at,
    updated_at: p.updated_at,
    url: p.html_url,
  };
}

export function slimIssue(i: Record<string, unknown>) {
  return {
    number: i.number,
    title: i.title,
    state: i.state,
    // GitHub returns pull requests from the issues endpoint too. Flagging it
    // is cheaper than making the caller notice the pull_request field.
    is_pull_request: i.pull_request !== undefined,
    author: (i.user as { login?: string } | undefined)?.login,
    labels: (i.labels as Array<{ name?: string }> | undefined)?.map(
      (l) => l.name,
    ),
    assignees: (i.assignees as Array<{ login?: string }> | undefined)?.map(
      (a) => a.login,
    ),
    comments: i.comments,
    created_at: i.created_at,
    updated_at: i.updated_at,
    url: i.html_url,
  };
}

export async function listPullRequests(
  env: Env,
  repo: string,
  state: string,
  limit: number,
  page = 1,
): Promise<unknown> {
  const q = new URLSearchParams({
    state,
    per_page: String(limit + 1),
    page: String(page),
    sort: "updated",
    direction: "desc",
  });
  const rows = (await repoApi(env, repo, `/pulls?${q}`)) as Array<
    Record<string, unknown>
  >;
  const pageResult = paginate(rows, limit, page);
  return { ...pageResult, items: pageResult.items.map(slimPull) };
}

export async function getPullRequest(
  env: Env,
  repo: string,
  number: number,
): Promise<unknown> {
  const pr = (await repoApi(env, repo, `/pulls/${number}`)) as Record<
    string,
    unknown
  >;
  const head = (pr.head as { sha?: string } | undefined)?.sha;
  const [files, checks] = await Promise.all([
    repoApi(env, repo, `/pulls/${number}/files?per_page=100`),
    head
      ? repoApi(env, repo, `/commits/${head}/check-runs`).catch(() => null)
      : Promise.resolve(null),
  ]);
  const runs =
    (checks as { check_runs?: Array<Record<string, unknown>> } | null)
      ?.check_runs || [];
  return {
    number: pr.number,
    title: pr.title,
    state: pr.state,
    draft: pr.draft,
    author: (pr.user as { login?: string } | undefined)?.login,
    base: (pr.base as { ref?: string } | undefined)?.ref,
    head: (pr.head as { ref?: string } | undefined)?.ref,
    head_sha: head,
    mergeable: pr.mergeable,
    mergeable_state: pr.mergeable_state,
    additions: pr.additions,
    deletions: pr.deletions,
    changed_files: pr.changed_files,
    body: pr.body,
    files: (files as Array<Record<string, unknown>>).map((f) => ({
      filename: f.filename,
      status: f.status,
      additions: f.additions,
      deletions: f.deletions,
    })),
    checks: {
      total: runs.length,
      failing: runs
        .filter(
          (c) =>
            c.status === "completed" &&
            !["success", "skipped", "neutral"].includes(String(c.conclusion)),
        )
        .map((c) => c.name),
      pending: runs.filter((c) => c.status !== "completed").map((c) => c.name),
    },
  };
}

export function getPullRequestDiff(
  env: Env,
  repo: string,
  number: number,
): Promise<string> {
  return repoText(
    env,
    repo,
    `/pulls/${number}`,
    "application/vnd.github.v3.diff",
  );
}

/**
 * Just the head sha and draft flag of a pull request.
 *
 * The issue_comment payload carries neither — it describes a comment on an
 * "issue", and a pull request is an issue with extra URLs hanging off it. So
 * a mention costs one lookup, and this is the cheap one: getPullRequest()
 * also fetches the file list and a check-run rollup, none of which a review
 * needs.
 */
export async function getPullRequestHead(
  env: Env,
  repo: string,
  number: number,
): Promise<{ sha: string; draft: boolean; state: string }> {
  const pr = (await repoApi(env, repo, `/pulls/${number}`)) as Record<
    string,
    unknown
  >;
  const sha = (pr.head as { sha?: string } | undefined)?.sha;
  if (!sha) {
    throw new GitHubError(`${repo}#${number}: no head sha`, 502, null);
  }
  return {
    sha,
    draft: pr.draft === true,
    state: typeof pr.state === "string" ? pr.state : "unknown",
  };
}

/**
 * The diff a push introduced, as a unified diff./**
 * The diff a push introduced, as a unified diff.
 *
 * `base` and `head` are the webhook's `before` and `after`. This is what the
 * reviewer reads after a commit: what just arrived, not the whole pull
 * request, which it has already seen.
 */
export function compareCommits(
  env: Env,
  repo: string,
  base: string,
  head: string,
): Promise<string> {
  return repoText(
    env,
    repo,
    `/compare/${base}...${head}`,
    "application/vnd.github.v3.diff",
  );
}

/**
 * Comment on a commit.
 *
 * Deliberately NOT a pull request review. A commit comment cannot carry a
 * review event, so it cannot request changes, cannot approve, and cannot
 * satisfy or block a branch protection rule — there is no state for a person
 * to dismiss. The reviewer says its piece and changes nothing.
 *
 * `path` and `position` are omitted on purpose. For commit comments GitHub
 * anchors on `position`, the line index counted down from the first `@@`
 * header in that file, continuing across hunks and counting removed and
 * context lines alike — NOT the file line number that pull request review
 * comments take. Getting that arithmetic wrong puts a confident comment on
 * unrelated code, so the review goes in one body with each finding naming its
 * own `path:line` in text. Anyone adding inline anchoring later: that is the
 * rule you have to implement, and `line` is deprecated for this endpoint.
 */
export function createCommitComment(
  env: Env,
  repo: string,
  sha: string,
  body: string,
): Promise<unknown> {
  return repoApi(env, repo, `/commits/${sha}/comments`, {
    method: "POST",
    body: JSON.stringify({ body }),
  });
}

/** Existing comments on a commit — how the reviewer knows it already ran. */
export async function listCommitComments(
  env: Env,
  repo: string,
  sha: string,
): Promise<Array<Record<string, unknown>>> {
  const rows = (await repoApi(
    env,
    repo,
    `/commits/${sha}/comments?per_page=100`,
  )) as Array<Record<string, unknown>>;
  return Array.isArray(rows) ? rows : [];
}

export async function listIssues(
  env: Env,
  repo: string,
  state: string,
  limit: number,
  page = 1,
): Promise<unknown> {
  const q = new URLSearchParams({
    state,
    per_page: String(limit + 1),
    page: String(page),
    sort: "updated",
    direction: "desc",
  });
  const rows = (await repoApi(env, repo, `/issues?${q}`)) as Array<
    Record<string, unknown>
  >;
  const pageResult = paginate(rows, limit, page);
  return { ...pageResult, items: pageResult.items.map(slimIssue) };
}

export function getIssue(
  env: Env,
  repo: string,
  number: number,
): Promise<unknown> {
  return repoApi(env, repo, `/issues/${number}`);
}

export function createPullRequest(
  env: Env,
  repo: string,
  args: {
    title: string;
    head: string;
    base: string;
    body?: string;
    draft?: boolean;
  },
): Promise<unknown> {
  return repoApi(env, repo, "/pulls", {
    method: "POST",
    // Draft unless explicitly told otherwise: a PR this agent opens should
    // not start demanding review attention on its own.
    body: JSON.stringify({ ...args, draft: args.draft !== false }),
  });
}

export function updatePullRequest(
  env: Env,
  repo: string,
  number: number,
  patch: Record<string, unknown>,
): Promise<unknown> {
  return repoApi(env, repo, `/pulls/${number}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
}

/**
 * Submit a review. APPROVE is refused, deliberately and permanently.
 *
 * An agent that can approve can satisfy a repository's own review requirement
 * and let code reach a protected branch with no human having read it. Review
 * is where a person is supposed to stand; an automated approval removes the
 * person while leaving the ritual. COMMENT and REQUEST_CHANGES carry every
 * finding a review needs to carry, and neither one unblocks a merge.
 */
// `async` rather than a plain function returning a promise: the guards below
// throw before any await, and a synchronous throw from a Promise-typed
// function is an uncaught exception for any caller using .catch().
export async function createReview(
  env: Env,
  repo: string,
  number: number,
  args: {
    event: "COMMENT" | "REQUEST_CHANGES";
    body: string;
    comments?: Array<{ path: string; line: number; body: string }>;
  },
): Promise<unknown> {
  const event = String(args.event).toUpperCase();
  if (event === "APPROVE") {
    throw new GitHubError(
      "this server does not approve pull requests; use COMMENT or REQUEST_CHANGES",
      403,
      null,
    );
  }
  if (event !== "COMMENT" && event !== "REQUEST_CHANGES") {
    throw new GitHubError(
      `unsupported review event "${args.event}"`,
      400,
      null,
    );
  }
  return repoApi(env, repo, `/pulls/${number}/reviews`, {
    method: "POST",
    body: JSON.stringify({
      event,
      body: args.body,
      comments: args.comments || [],
    }),
  });
}

export function createComment(
  env: Env,
  repo: string,
  number: number,
  body: string,
): Promise<unknown> {
  // Issues and PRs share the issue-comments endpoint.
  return repoApi(env, repo, `/issues/${number}/comments`, {
    method: "POST",
    body: JSON.stringify({ body }),
  });
}

export function createIssue(
  env: Env,
  repo: string,
  args: {
    title: string;
    body?: string;
    labels?: string[];
    assignees?: string[];
  },
): Promise<unknown> {
  return repoApi(env, repo, "/issues", {
    method: "POST",
    body: JSON.stringify(args),
  });
}

export function updateIssue(
  env: Env,
  repo: string,
  number: number,
  patch: Record<string, unknown>,
): Promise<unknown> {
  return repoApi(env, repo, `/issues/${number}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
}
