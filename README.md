# nyuchi-github-mcp

> A Cloudflare Worker that exposes GitHub review, pull request and issue
> operations as an MCP server, so Claude can work the repositories directly.

Sibling of [`nyuchi-fly-mcp`](https://github.com/nyuchi/mukoko-platform/tree/main/fly-mcp):
same transport (MCP Streamable HTTP / JSON-RPC 2.0), same WorkOS Connect auth,
same shape. If you have a client pointed at `fly.nyuchi.dev`, this is the same
config with a different URL.

## What it does

| Tool                           | What it does                                                     |
| ------------------------------ | ---------------------------------------------------------------- |
| `github_whoami`                | Verify credentials; report App permissions vs token permissions  |
| `github_list_pull_requests`    | PRs, most recently updated first                                 |
| `github_get_pull_request`      | One PR: metadata, mergeability, files, check rollup              |
| `github_get_pull_request_diff` | The unified diff — the text you actually review                  |
| `github_create_review`         | Submit a review, `COMMENT` or `REQUEST_CHANGES`, inline comments |
| `github_create_pull_request`   | Open a PR (draft unless told otherwise)                          |
| `github_update_pull_request`   | Title, body, base, open/close                                    |
| `github_list_issues`           | Issues, most recently updated first                              |
| `github_get_issue`             | One issue                                                        |
| `github_create_issue`          | File an issue                                                    |
| `github_update_issue`          | Retitle, relabel, reassign, open/close                           |
| `github_comment`               | Comment on an issue or PR                                        |

## What it deliberately cannot do

**It does not approve pull requests.** `github_create_review` accepts
`COMMENT` and `REQUEST_CHANGES` and refuses `APPROVE` in any casing, before
the repository allowlist is even consulted. An agent that can approve can
satisfy a branch protection review requirement by itself, letting code reach a
protected branch with nobody having read it — that removes the person while
leaving the ritual. Every finding a review needs to carry fits in a comment.

**It does not merge, and could not.** Merging needs `contents: write`; the
token asks for `contents: read`.

**It does not touch workflows.** The App holds `workflows: read/write`; the
token does not request it. So this worker cannot modify a `.github/workflows/`
file or cut a release, even though the credential it authenticates with can.

## How the permissions actually work

This worker authenticates as the **same GitHub App that mints release tokens**.
That was a deliberate decision, and the blast radius is managed with two
independent bounds rather than by trusting the App's scope:

**Outer bound — `GITHUB_ALLOWED_REPOS`.** A comma-separated `owner/repo` list,
checked before a token is minted, so a repository outside it never reaches
GitHub at all. **Empty or unset denies everything**: a misconfigured worker
should be useless, not open. There is a test for exactly that.

**Inner bound — `GITHUB_TOKEN_PERMISSIONS`.** Every call runs on an
installation token minted per-repository via
`POST /app/installations/{id}/access_tokens` with an explicit `repositories`
and `permissions` narrowing. A token may request a **subset** of what the App
holds and never a superset, which is what turns a release-capable App into a
review-capable agent.

```
App holds:     contents:write  pull_requests:write  workflows:write
Token asks:    contents:read   pull_requests:write  issues:write  metadata:read
                    ^ read            ^ same              ^ new        ^
               cannot push      can review        needs App change
               cannot merge                       (see below)
```

> **Known gap.** The release App does **not** currently hold an Issues
> permission, so every issue tool fails with GitHub's `422` naming it until
> **Issues: read/write** is added to the App and the installation
> re-authorised. `github_whoami` reports this directly under
> `permissions_missing_from_app`, so it is visible in one call rather than as
> a surprise mid-task.

## Auth

Callers authenticate with a **WorkOS Connect** access token, verified in-worker
against the WorkOS JWKS with WebCrypto (RS256). The worker advertises WorkOS as
its authorization server at `/.well-known/oauth-protected-resource` (RFC 9728),
so an MCP client discovers it and runs PKCE without configuration.

Two gates beyond a valid signature, both in `wrangler.toml` so a change to who
may call this shows up in a diff:

- **Org gate** — `org_id` must equal `WORKOS_ORG_ID`. Blocks every other org.
- **Role/permission gate** — the caller must hold `WORKOS_REQUIRED_ROLES` or
  `WORKOS_REQUIRED_PERMISSIONS`. A plain org member with neither is refused.

Verification fails closed: any error is a 401.

## Setup

```bash
cd worker
npm install
npm run build     # tsc --noEmit
npm test          # DER wrapper + policy guards
npm run dev       # wrangler dev
```

`GITHUB_APP_ID` is committed in `wrangler.toml` — an App ID is an identifier,
not a credential, and `wrangler deploy` replaces the deployed `[vars]` block,
so a value set only in the dashboard is overwritten by the next deploy. The
private key is the secret:

```bash
wrangler secret put GITHUB_APP_PRIVATE_KEY   # the whole .pem, BEGIN/END included
wrangler secret put WORKOS_JWKS_URL          # https://accounts.mukoko.com/oauth2/jwks
wrangler secret put WORKOS_ISSUER            # https://accounts.mukoko.com
wrangler secret put WORKOS_AUDIENCE          # https://github.nyuchi.dev/mcp
```

The three WorkOS values are not guesses. `issuer` and `jwks_uri` are what
`https://accounts.mukoko.com/.well-known/oauth-authorization-server` serves;
the audience is this worker's resource URI.

**Do not use `https://api.workos.com/sso/jwks/<client_id>`.** That is the older
SSO-profile JWKS. AuthKit access tokens here are signed by the authorization
server above, so that endpoint holds no matching key and every call fails
verification with `no matching signing key`. `auth.mukoko.com` is the WorkOS
auth API and serves no authorization-server metadata at all — it 404s.

`WORKOS_AUDIENCE` only carries the resource URI once that URI is registered as
an **AuthKit OAuth resource** in the WorkOS environment
(`environment_01KQBBSMDHMT9Y5GVD8S1A3C0W`, the Production environment that
holds the Nyuchi Africa org, `org_01KRDAB894DJF5V38PT5617TV1`). Until it is,
WorkOS will not mint a token scoped to this resource and verification fails on
`audience mismatch`.

The two authorization gates are checked against that same environment:
`platform-team` is the slug of the **Platform Team** role, and `mongodb:access`
is a permission it holds.

`GITHUB_APP_PRIVATE_KEY` takes GitHub's own download format — PKCS#1,
`BEGIN RSA PRIVATE KEY` — as well as PKCS#8. WebCrypto only imports PKCS#8, so
the worker wraps PKCS#1 in the PKCS#8 envelope itself. That means this secret
is **byte-identical to `RELEASE_APP_PRIVATE_KEY`** with no `openssl pkcs8`
step, which is one fewer thing to get wrong. `test/der.test.ts` checks the
wrapper against OpenSSL's own output at 2048, 3072 and 4096 bits.

Until `WORKOS_ISSUER` is set, `/mcp` stays locked.

## Endpoints

```
POST /mcp                                    MCP, requires a WorkOS bearer token
GET  /.well-known/oauth-protected-resource   OAuth resource metadata (public)
GET  /health                                 liveness (public)
```

## Layout

```
src/env.ts      bindings and the csv helper
src/auth.ts     WorkOS token verification (shared logic with nyuchi-fly-mcp)
src/github.ts   App JWT, scoped installation tokens, REST operations
src/mcp.ts      tool definitions and JSON-RPC dispatch
src/index.ts    routing, CORS, auth enforcement
```

`src/github.ts` exposes each operation as a plain function. The MCP layer is a
thin wrapper over them, so the webhook-driven autonomous layer calls the same
code rather than reimplementing it.

## Status

**Milestone 1 — MCP server.** Claude is the brain; this worker is the hands.
Nothing here acts on its own.

**Milestone 2 — autonomous agent**, not yet built. Webhook ingest, an LLM call
in the worker, and its own review loop, reusing these operations. It needs
things this milestone does not: an Anthropic key as a Worker secret, a queue,
rate limiting, loop guards against reviewing its own output, and a kill switch.
