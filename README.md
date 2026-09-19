# Shamwari for GitHub

> A Cloudflare Worker that reviews pull requests and exposes GitHub review,
> pull request and issue operations as an MCP server.

Served at **`https://github.shamwari.ai`**. The GitHub App is **Shamwari for
GitHub**; comment `@shamwari` on a pull request to summon a review.

Sibling of [`nyuchi-fly-mcp`](https://github.com/nyuchi/mukoko-platform/tree/main/fly-mcp):
same transport (MCP Streamable HTTP / JSON-RPC 2.0), same WorkOS Connect auth,
same shape. If you have a client pointed at `fly.nyuchi.dev`, this is the same
config with a different URL.

## What it does

| Tool                             | What it does                                                     |
| -------------------------------- | ---------------------------------------------------------------- |
| `shamwari_whoami`                | Per-repo installation and permission readiness — start here      |
| `shamwari_list_pull_requests`    | PRs, most recently updated first                                 |
| `shamwari_get_pull_request`      | One PR: metadata, mergeability, files, check rollup              |
| `shamwari_get_pull_request_diff` | The unified diff — the text you actually review                  |
| `shamwari_create_review`         | Submit a review, `COMMENT` or `REQUEST_CHANGES`, inline comments |
| `shamwari_create_pull_request`   | Open a PR (draft unless told otherwise)                          |
| `shamwari_update_pull_request`   | Title, body, base, open/close                                    |
| `shamwari_list_issues`           | Issues, most recently updated first                              |
| `shamwari_get_issue`             | One issue                                                        |
| `shamwari_create_issue`          | File an issue                                                    |
| `shamwari_update_issue`          | Retitle, relabel, reassign, open/close                           |
| `shamwari_comment`               | Comment on an issue or PR                                        |
| `shamwari_review_pull_request`   | Review a PR with a model on Workers AI — dry run by default      |

## What it deliberately cannot do

**It does not approve pull requests.** `shamwari_create_review` accepts
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

> **A missing permission breaks everything, not just the tool that needs it.**
> The token mint requests the whole set in one call, so if the installation
> does not grant `issues: write`, GitHub rejects the mint with `422` and no
> token is produced — reading a PR diff fails too.
>
> Two states look alike and are not: an App can _declare_ a permission while
> the installation has not _accepted_ it. Adding one puts the installation
> into pending review until an owner approves. `shamwari_whoami` reports what
> the installation actually grants, per repository, so the difference shows up
> in one call rather than as a 422 mid-task.

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

Verification fails closed: any error is a 401, and a missing setting is an
error rather than a skipped check.

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
wrangler secret put WORKOS_AUDIENCE          # https://github.shamwari.ai/mcp
```

The three WorkOS values are not guesses. `issuer` and `jwks_uri` are what
`https://accounts.mukoko.com/.well-known/oauth-authorization-server` serves;
the audience is this worker's resource URI.

**Do not use `https://api.workos.com/sso/jwks/<client_id>`.** That is the older
SSO-profile JWKS. AuthKit access tokens here are signed by the authorization
server above, so that endpoint holds no matching key and every call fails
verification with `no matching signing key`. `auth.mukoko.com` is the WorkOS
auth API and serves no authorization-server metadata at all — it 404s.

### Two ways a client gets a token, and what `aud` is in each

`WORKOS_AUDIENCE` accepts a comma-separated list, because the audience depends
on how the client authenticated:

| How the client got its token                          | `aud` carries                                          |
| ----------------------------------------------------- | ------------------------------------------------------ |
| Dynamic client registration (Claude registers itself) | the **resource URI**, `https://github.shamwari.ai/mcp` |
| The **Nyuchi Internal Tools** Connect app             | its **client id**, `client_01KVTX0V2K1VM3PSC0DJ9VZWTV` |

Listing both accepts either and still rejects a token minted for anything else,
so set:

```
WORKOS_AUDIENCE = https://github.shamwari.ai/mcp,client_01KVTX0V2K1VM3PSC0DJ9VZWTV
```

The Connect app route is worth preferring: it is **org-restricted to Nyuchi
Africa**, so a signer who belongs to several organizations cannot accidentally
present a token issued against the wrong one — the commonest way a valid token
gets refused here. It is a public PKCE client, so a client id alone is enough,
no secret, and `https://claude.ai/api/mcp/auth_callback` plus its `.com` twin
are already registered on it. It grants `mongodb:access`, which satisfies this
worker's permission gate; third-party app tokens surface permissions rather
than the organization role, which is why that gate accepts either.

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

All three are required. `verifyWorkosToken` refuses outright when any of
`WORKOS_JWKS_URL`, `WORKOS_ISSUER` or `WORKOS_AUDIENCE` is unset, rather than
treating a missing value as "skip that check" — an unset audience would
otherwise let a token minted for any other MCP resource in the same WorkOS
environment be spent here. `test/auth.test.ts` pins that.

## Protocol: dual-era

This server speaks two MCP revisions on one endpoint, which the spec
explicitly allows ("a dual-era server MAY serve both eras concurrently on the
same endpoint or process").

| Revision     | Era    | How a client selects it                                                  |
| ------------ | ------ | ------------------------------------------------------------------------ |
| `2026-07-28` | modern | every request carries `_meta["io.modelcontextprotocol/protocolVersion"]` |
| `2025-06-18` | legacy | an `initialize` handshake                                                |

`2026-07-28` removed the `initialize` handshake, protocol-level sessions and
the standalone GET stream. Serving only it would break every client that has
already connected, so era is chosen by the shape of the request rather than by
configuration: an `initialize` request is legacy by definition, anything
declaring a version is modern, anything else is legacy.

On the modern path the transport rules are enforced:

| Condition                                                                               |  Status | JSON-RPC code                                               |
| --------------------------------------------------------------------------------------- | ------: | ----------------------------------------------------------- |
| `MCP-Protocol-Version` / `Mcp-Method` / `Mcp-Name` missing or disagreeing with the body |     400 | `-32020` HeaderMismatch                                     |
| Version not supported                                                                   |     400 | `-32022` UnsupportedProtocolVersion (with `data.supported`) |
| Unknown method                                                                          | **404** | `-32601`                                                    |
| `GET` or `DELETE` on the endpoint                                                       |     405 | —                                                           |
| `Origin` present and not this resource's                                                |     403 | —                                                           |

Those statuses are not cosmetic: a client uses them to decide whether the
server is modern at all, and a wrong one sends it down the legacy fallback
path. `Mcp-Name` values may arrive in the Base64 sentinel form
`=?base64?...?=` and are decoded before comparison, so a non-ASCII tool name
or resource URI is not mistaken for a mismatch.

Legacy requests are not version-validated and keep returning 200 for a
JSON-RPC error, as their revision expects.

`server/discover` is implemented (the modern spec requires it) and returns the
supported versions, capabilities and server identity in one call.

## What the list tools return

`shamwari_list_pull_requests` and `shamwari_list_issues` return a page, not a raw
GitHub array:

```json
{
  "items": [ ... ],
  "count": 20,
  "page": 1,
  "has_more": true,
  "next_page": 2
}
```

`has_more` is not guessed from a full page and it does not parse GitHub's
`Link` header: the fetch asks for `limit + 1` rows and the extra row, if it
arrives, is the proof. `next_page` is present only when there is one, so a
caller that stops when the field is absent cannot loop forever.

Each row is shaped, not passed through. A raw pull request carries 36
top-level fields — a nested user, head, base, `_links` and a **full repository
object on every row**. Measured against this repository, thirteen raw PRs
serialise to 276,801 bytes; the same thirteen shaped are 3,842. That is 99% of
a tool result spent on structure nothing reads, and it is charged to the
model's context on every call. The fields kept are the ones you triage on —
number, title, state, draft, author, base, head, labels, timestamps, URL —
and anything dropped is one `shamwari_get_pull_request` away.

`shamwari_list_issues` adds `is_pull_request`, because GitHub's issues endpoint
returns pull requests too and a caller that does not notice will file a review
comment on the wrong kind of thing.

## Tool annotations

Every tool advertises the four hints from the spec, so a client can decide
what needs confirming without reading a description:

| Hint              | Meaning here                                                   |
| ----------------- | -------------------------------------------------------------- |
| `readOnlyHint`    | true for the six read tools; they touch nothing                |
| `destructiveHint` | true for the two update tools — they overwrite fields in place |
| `idempotentHint`  | true for reads and updates; false for the four create tools    |
| `openWorldHint`   | true everywhere: the subject is github.com, not local state    |

The hints are advisory and a client may ignore them. They are not the
safeguard — the approve refusal and the read-only token scope are, and those
are enforced server-side regardless of what any client believes.

## The review agent

`shamwari_review_pull_request` reads a diff, asks a model on **Workers AI** what
is wrong with it, and returns findings anchored to specific lines. Inference
runs on the same platform as the worker, so there is no third-party API key to
hold and no egress to allow — it is billed to the Cloudflare account.

### It is a dry run unless you say otherwise

`post` defaults to `false`. Two reasons: the first thing anyone should do with
a new reviewer is read what it _would_ have said, and a dry run lets the same
tool run two models over one pull request without either of them writing to
it.

When it does post, it posts through `createReview()` — which refuses `APPROVE`
before the allowlist is consulted. The agent inherits that guarantee rather
than restating it. It also defaults to `COMMENT` even when findings are
blocking: `REQUEST_CHANGES` leaves a mark a person has to dismiss, so it is
something this reviewer should earn on evidence, not assume on its first day.

### Line numbers are computed, not asked for

A unified diff carries hunk headers (`@@ -a,b +c,d @@`) and leaves the
arithmetic to the reader. Asking a language model to do that arithmetic gets
you comments on unrelated lines — a review that looks careful and points at
the wrong code, which is worse than no review.

So `annotateDiff()` does the arithmetic and writes the answer into the text
the model reads:

```
@@ -10,6 +10,7 @@ function f() {
    10|const a = 1;
    11|const b = 2;
-     |const c = 3;
+   12|const c = 4;
+   13|const d = 5;
    14|const e = 6;
```

Only `+` lines are valid targets, and the set of them is kept. A finding aimed
at anything else is collected under `unanchored` and folded into the comment
separately, so a model pointing at code it cannot see stays visible instead of
being silently dropped.

> **If you ever add inline anchoring**, note that commit comments anchor on
> `position` — the line index counted down from the _first_ `@@` header in
> that file, continuing across hunks, counting context and removed lines
> alike. That is **not** the file line number pull request review comments
> take, and `line` is deprecated on that endpoint. One comment per review
> sidesteps that arithmetic entirely, which is part of why it is one comment.

### The model output is not trusted

Cloudflare's own JSON-mode documentation says it "can't guarantee that the
model responds according to the requested JSON Schema". So the schema is a
request and `parseFindings()` is the enforcement: malformed findings are
dropped one at a time, an unknown severity degrades to `note`, and prose
instead of JSON fails loudly rather than posting an empty review.

### Choosing a model

`REVIEW_MODEL` is a var, not a constant, so the model changes — and two models
are compared — without shipping code.

| Model                           | Context | $/Mtok in / out | Per review¹ |
| ------------------------------- | ------: | --------------: | ----------: |
| `@cf/zai-org/glm-5.3`           |   1.31M |     1.40 / 4.40 |     ~$0.027 |
| `@cf/zai-org/glm-5.3-flash`     |   1.31M |     0.15 / 0.50 |     ~$0.003 |
| `@cf/moonshotai/kimi-k2.7-code` |    262K |     0.95 / 4.00 |     ~$0.023 |

¹ Measured against this repository: the median pull request diff is 4,757
tokens and the largest 8,988, so a review is roughly 7K in and 4K out
including GLM's reasoning tokens, which bill as output.

**At this repository's volume that is a few dollars a year either way**, so
choose on whether the review is worth reading, not on price. GLM 5.3 requires
a Workers Paid plan. The honest way to decide is to run candidates over pull
requests whose defects are already known and see which one finds them.

### What it will not tell you

The system prompt excludes formatting, naming, "consider extracting this",
praise, and summaries of what the diff does. Prettier and markdownlint already
gate every pull request in this org, so a comment about them is a comment
about a check that already runs. It is also told that **returning zero
findings is a correct outcome** — the failure mode of an automated reviewer is
not being wrong, it is being voluminous, and a bot that posts nine nits and
one real bug has buried the bug.

### Not reviewing the same commit twice

GitHub retries a delivery it believes failed, and re-requesting one is a single
click. So before posting, the agent reads the commit's existing comments and
stops if one already carries its marker.

That state lives where the output lives. No KV namespace to provision, and no
second record that can drift out of step with the thing it describes.

### Routing through an AI Gateway

`AI_GATEWAY_ID` is unset by default, which calls Workers AI directly. Set it
and every review is logged with `{ repo, trigger }` metadata attached, where
`trigger` is `push`, `pull_request` or `mention:<login>`.

That turns "what did this repository cost this month" from an estimate into a
query — and it is the mechanism per-customer billing would be built on, since
the same metadata field can carry a customer id.

`skipCache` is set to `true` deliberately. A cached review is a wrong review:
the same diff reviewed twice is a person asking for a second opinion, and
handing back the first one verbatim answers a question nobody asked.

> The `gateway` object is the **third argument** to `env.AI.run`, not a field
> of the input. Putting it in the input silently does nothing and the call
> still succeeds — the mistake shows up as a gateway with no traffic rather
> than as an error.

### Kill switch

`REVIEW_ENABLED = "false"` fails every review closed, before any model call and
before any diff is fetched, with no code deploy.

`GITHUB_WEBHOOK_SECRET` unset makes `/webhook` answer `503`. An endpoint that
runs model calls on unauthenticated input is an endpoint anyone can bill to
your Cloudflare account.

### What is still missing

`ctx.waitUntil()` runs the review after the webhook has been answered, because
a model call over a diff takes far longer than the ten seconds GitHub allows.
It has **no retry and no backpressure**: if the worker is evicted mid-review,
that review is lost. The failure is visible — the commit simply has no comment
— and re-requesting the delivery re-runs it. Cloudflare Queues is the upgrade
once review volume justifies provisioning one.

## Endpoints

```
POST /mcp                                    MCP, requires a WorkOS bearer token
POST /webhook                                GitHub webhook, HMAC-signed (no bearer)
GET  /.well-known/oauth-protected-resource   OAuth resource metadata (public)
GET  /health                                 liveness (public)
GET|DELETE /mcp                              405 (sessions and GET streams are gone)
```

## Layout

```
src/env.ts      bindings and the csv helper
src/protocol.ts era detection, mirrored-header validation, version constants
src/auth.ts     WorkOS token verification (shared logic with nyuchi-fly-mcp)
src/github.ts   App JWT, scoped installation tokens, REST operations
src/review.ts   the review engine: diff annotation, the model call, anchoring
src/webhook.ts  GitHub webhook ingest, signature check, the draft rule
src/mcp.ts      tool definitions and JSON-RPC dispatch
src/index.ts    routing, CORS, auth enforcement
```

`src/github.ts` exposes each operation as a plain function. The MCP layer is a
thin wrapper over them, so the webhook-driven autonomous layer calls the same
code rather than reimplementing it.

## Status

**Milestone 1 — MCP server.** Claude is the brain; this worker is the hands.
Nothing here acts on its own.

**Milestone 2 — autonomous agent**, partly built. The _brain_ exists:
`src/review.ts` reviews a pull request on demand through
`shamwari_review_pull_request`, and Workers AI removed the third-party API key
that milestone was going to need.

What is still missing is the _autonomy_: webhook ingest with signature
verification, a queue so a slow review does not hold a webhook response open,
per-repository rate limiting, dedup on head SHA, and loop guards so the agent
does not review its own output. Deliberately sequenced this way — the review
engine carries all the risk (is the output worth reading?) and none of it
needs a webhook to answer, and the autonomous layer is then a caller of
`reviewPullRequest()` rather than a second implementation of it.
