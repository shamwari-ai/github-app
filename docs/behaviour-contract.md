# Behaviour contract

What `shamwari-github-mcp` does and must keep doing, written down from the
TypeScript implementation before it was rewritten in Rust. Each rule names the
Rust module that now enforces it and the tests that pin it. If a change makes
a line here untrue, change this file in the same pull request and say why.

Everything is served on `github.shamwari.ai` (and `github.nyuchi.dev`, see
[Resource URL](#resource-url)).

## HTTP routes

| Route                                                 | Auth        | Answer                                                                     |
| ----------------------------------------------------- | ----------- | -------------------------------------------------------------------------- |
| `OPTIONS *`                                           | none        | `204` with the CORS headers                                                |
| `GET /health`                                         | none        | `{"status":"ok","server":"shamwari-github-mcp"}`                           |
| `POST /webhook`                                       | HMAC        | GitHub deliveries (below). Other methods: `405`                            |
| `GET /.well-known/agent-card.json` and `/agent.json`  | none        | A2A agent card; `503` while `WORKOS_AUTHORIZATION_SERVER` is unset         |
| `GET /.well-known/oauth-protected-resource[/mcp]`     | none        | RFC 9728 metadata; `503` while `WORKOS_AUTHORIZATION_SERVER` is unset      |
| `GET /github-app/new`, `/created?code=`, `/installed` | none        | App setup pages. Inert: they hold and exchange nothing                     |
| `POST /mcp`                                           | WorkOS JWT  | MCP over Streamable HTTP, stateless JSON-RPC 2.0                           |
| `POST /a2a`                                           | WorkOS JWT  | A2A 1.0, one method: `SendMessage`                                         |
| `GET`/`DELETE` on `/mcp` or `/a2a`                    | none needed | `405` (checked before auth: sessions and the GET stream do not exist)      |
| anything else                                         | none        | `404 {"error":"not found"}`                                                |

Order matters and is kept: `OPTIONS`, `/health`, `/webhook`, agent card,
resource metadata, setup pages, then `/mcp` and `/a2a` (405 for GET/DELETE,
Origin check, bearer verification, then the method check).

CORS: `Access-Control-Allow-Origin: *`, methods `POST, GET, OPTIONS`, allowed
headers include `Mcp-Method` and `Mcp-Name` (the 2026-07-28 mirrored headers),
`WWW-Authenticate` exposed. Applied to everything except the webhook and the
setup pages.

## Authentication (WorkOS AuthKit)

The Worker only verifies; it holds no WorkOS secret. Every `/mcp` and `/a2a`
request needs `Authorization: Bearer <RS256 JWT>`.

- **Origin**: an `Origin` header, when present, must equal the origin of the
  resource URL; absent is allowed (non-browser clients). Refused with `403`.
- **No token**: `401`, `WWW-Authenticate: Bearer resource_metadata="<served
  host>/.well-known/oauth-protected-resource"`.
- **Rejected token**: `401` with `error="invalid_token"` and an
  `error_description` that names the gate (never the token or its claims). The
  log records the gate and what the token carried.
- **Checks, in order**: three dot-separated parts; `alg == RS256`; JWKS fetched
  from `WORKOS_JWKS_URL` (10-minute per-isolate cache; unset URL refuses); key
  chosen by `kid`, else the first key; RS256 signature; `exp` / `nbf`;
  `WORKOS_ISSUER` required and equal to `iss` (unset **refuses**); audience:
  `aud` must contain one of `WORKOS_AUDIENCE` (comma list) or the resource URL
  this request was served under (no accepted audience at all **refuses**);
  `org_id == WORKOS_ORG_ID` when set; then the platform gate.
- **Platform gate**: when `WORKOS_REQUIRED_ROLES` / `WORKOS_REQUIRED_PERMISSIONS`
  are set the caller needs one required role (`role` string or `roles` array)
  **or** one required permission, read from `permissions` (array, Connect apps)
  and `scope` (space-separated string, or an array, for WorkOS agents). Live
  policy: role `platform-team` or permission `github:access`, org
  `org_01KRDAB894DJF5V38PT5617TV1`.
- Accepted calls log the caller kind (`agent` if `sub` starts `agent_`), the
  subject, the delegating user (`act.sub`) and the org.
- The resource metadata advertises **no** `scopes_supported` (an undefined scope
  makes WorkOS answer `invalid_scope` before any login page).

Rust: `src/auth.rs`, `src/router.rs`. Tests: `src/tests/auth.rs`,
`resource.rs`, `transport.rs`, `origin.rs`.

### Resource URL

`resource` in the metadata is `https://<served host>/mcp`, derived from the
request. Only hosts in `MCP_RESOURCE_HOSTS`, the host of `MCP_RESOURCE_URL`,
or `*.workers.dev` over https are reflected; anything else gets the canonical
`MCP_RESOURCE_URL` (default `https://github.shamwari.ai/mcp`). A mistyped
`MCP_RESOURCE_URL` can therefore never leak into an allowed host's metadata.
Every host listed must also be registered as an AuthKit resource.

## The GitHub App

The only identity the Worker uses is the App: no PAT exists anywhere.

- **App JWT**: RS256, `iss = GITHUB_APP_ID`, `iat = now - 60s`,
  `exp = now + 540s`. The key is `GITHUB_APP_PRIVATE_KEY` (a Worker secret),
  PKCS#1 ("BEGIN RSA PRIVATE KEY", as GitHub issues it) or PKCS#8; PKCS#1 is
  wrapped into PKCS#8 in code. Unset id or key fail with a message naming it.
- **Installation token**: resolve `GET /repos/{o}/{r}/installation` with the
  JWT, then `POST /app/installations/{id}/access_tokens` with
  `{"repositories":[<repo>],"permissions":<GITHUB_TOKEN_PERMISSIONS>}`: one
  repository, a reduced permission set. Cached per `owner/repo` (lower-cased)
  until 60 s before `expires_at`.
- **Permission policy**: outer bound `GITHUB_ALLOWED_REPOS` (comma list, matched
  case-insensitively; **empty or unset denies every repository**), checked
  before any token is minted and again at the webhook. Inner bound
  `GITHUB_TOKEN_PERMISSIONS` (default
  `pull_requests:write,issues:write,contents:read,metadata:read`).
  `workflows` is never requested, and `contents` is read-only, which is what
  makes a merge or push tool impossible rather than merely absent.
- **No approval**: `createReview` refuses `APPROVE` (any casing) before the
  allowlist is consulted, and refuses unknown events. The reviewer posts
  commit comments, which carry no review event at all.
- **Errors**: GitHub failures become `"<context>: <GitHub's message>"` with
  GitHub's status. These (and argument errors) are the only messages shown to
  callers; any other failure is logged and answered `internal error`.

Rust: `src/github.rs`. Tests: `src/tests/policy.rs`, `der.rs`, `review.rs`.

## MCP

Stateless: each POST is served on its own. Two eras from one tool table.

- **Modern (2026-07-28)**: a request is modern when `params._meta` carries
  `io.modelcontextprotocol/protocolVersion` (and `clientCapabilities`), or the
  `MCP-Protocol-Version` header names a version `>= 2026-07-28`. It must
  carry `MCP-Protocol-Version` and `Mcp-Method` headers agreeing with the body
  (and `Mcp-Name` for `tools/call`). Answers carry `resultType: "complete"`
  and the server identity in `_meta`. Statuses: unknown method `404`
  (`-32601`); header/body disagreement `400` (`-32020`); unsupported version
  `400` (`-32022`, `data.supported`); bad envelope `400` (`-32602`).
  `server/discover`, `tools/list`, `tools/call`, `ping`.
- **Legacy**: no claim, no required headers. `initialize` answers the
  requested version if supported (`2025-11-25`, `2025-06-18`, `2025-03-26`,
  `2024-11-05`, `2024-10-07`), else `2025-11-25`; `tools/list`, `tools/call`,
  `ping`; an unknown method is a JSON-RPC error on HTTP `200`.
- Server identity: name `shamwari-github-mcp`, title `Shamwari for GitHub`,
  version `0.1.0`.

### Tools

13 tools, `repo` is `owner/repo` and must pass the allowlist.

| Tool                              | Hints                    | Arguments (besides `repo`)                                        |
| --------------------------------- | ------------------------ | ----------------------------------------------------------------- |
| `shamwari_whoami`                 | read                     | none (probes every allowlisted repository)                        |
| `shamwari_list_pull_requests`     | read                     | `state` (open), `limit` 1-100 (20), `page`                        |
| `shamwari_get_pull_request`       | read                     | `number`                                                          |
| `shamwari_get_pull_request_diff`  | read                     | `number`                                                          |
| `shamwari_list_issues`            | read                     | `state` (open), `limit` 1-100 (20), `page`                        |
| `shamwari_get_issue`              | read                     | `number`                                                          |
| `shamwari_create_review`          | create                   | `number`, `event` COMMENT or REQUEST_CHANGES, `body`, `comments`  |
| `shamwari_create_pull_request`    | create                   | `title`, `head`, `base`, `body`, `draft` (**true**)               |
| `shamwari_create_issue`           | create                   | `title`, `body`, `labels`, `assignees`                            |
| `shamwari_comment`                | create                   | `number`, `body`                                                  |
| `shamwari_review_pull_request`    | create (can post)        | `number`, `model`, `post` (false), `head_sha`, `max_findings`, `force` |
| `shamwari_update_pull_request`    | update (destructive)     | `number`, one of `title`/`body`/`base`/`state`                    |
| `shamwari_update_issue`           | update (destructive)     | `number`, one of `title`/`body`/`state`/`labels`/`assignees`      |

Every tool carries `readOnlyHint`, `destructiveHint`, `idempotentHint` and
`openWorldHint`. There is no approve tool and no merge tool. List results are
trimmed (`slim_pull`, `slim_issue`) and paginated by fetching one row over the
limit. A failed call is a `tools/call` result with `isError: true`, never a
transport error.

Rust: `src/mcp.rs`. Tests: `src/tests/transport.rs`, `policy.rs`.

## Webhook and the review agent

`POST /webhook`, authenticated by `X-Hub-Signature-256` (HMAC-SHA256 over the
raw body with `GITHUB_WEBHOOK_SECRET`, constant-time; `sha256=` plus exactly 64
hex digits). Unset secret: `503`. Bad or missing signature: `401`. Non-JSON:
`400`. Answered at once; the review runs after the response (`waitUntil`),
never retried.

| Event / action                                       | Result                                                        |
| ---------------------------------------------------- | ------------------------------------------------------------- |
| `ping`                                               | skip                                                          |
| `pull_request` `synchronize` (before and after, not all zeros) | review **that push** (`compare` diff)               |
| `pull_request` `opened`, `ready_for_review`, first push | review the **whole** pull request                          |
| any `pull_request` action on a **draft**             | skip (the draft rule, checked on the payload)                 |
| closed or merged pull request                        | skip                                                          |
| `issue_comment` `created` mentioning `REVIEW_MENTION` (default `@shamwari`), on a pull request, by a human whose `author_association` is in `REVIEW_TRIGGER_ASSOCIATIONS` (default OWNER, MEMBER, COLLABORATOR) | review, **forced**, drafts allowed |
| a Bot's comment, an edited or deleted comment, a comment on an issue, a mention inside another word (`@shamwari-docs`, `me@shamwari.com`) | skip |
| anything else                                        | skip                                                          |

A repository outside `GITHUB_ALLOWED_REPOS` is skipped before anything is
spent.

The review: fetch the diff, annotate every line with its new-file number
(removed lines get none), cap at `REVIEW_MAX_DIFF_BYTES` (200,000) on a line
boundary, call Workers AI with the fixed system prompt and JSON-schema response
format through AI Gateway `AI_GATEWAY_ID` (`fundi`, passed as the **third**
argument of `AI.run`, `skipCache: true`, metadata `worker`, `job`, `repo`,
`trigger` kind only), validate the answer (dropping malformed findings,
degrading unknown severity to `note`), keep findings that land on a line the
diff **adds** (the rest are reported as unanchored, not dropped), rank by
severity, cap at 10, render **one commit comment** carrying
`<!-- nyuchi-review -->`. A commit that already carries the marker is skipped
**before** the model is called, unless forced. `REVIEW_ENABLED=false` makes
every review fail closed. Model: `REVIEW_MODEL` (default `@cf/zai-org/glm-5.3`,
or a `dynamic/<route>` on the gateway).

Rust: `src/webhook.rs`, `src/review.rs`. Tests: `src/tests/webhook.rs`,
`review.rs`.

## A2A

`GET /.well-known/agent-card.json`: protocol `1.0`, `streaming`,
`pushNotifications` and `extendedAgentCard` all `false`, an OpenID Connect
security scheme built from the parsed authorization-server origin, one skill.
`POST /a2a` `SendMessage` finds `owner/repo#N` (a data part first, then text;
a bare number is refused), runs a **dry-run** review and returns a COMPLETED
task with the result as a data part. An unusable message is `REJECTED`, a
failing review `FAILED`; no `kind` members anywhere (A2A 1.0). Any other
method is a JSON-RPC `-32601`.

Rust: `src/a2a.rs`. Tests: `src/tests/a2a.rs`.

## Tracing

Each review is an `invoke_agent` span with a nested `chat` span, carrying
`gen_ai.operation.name`, `gen_ai.agent.name`, `gen_ai.agent.id` and
`gen_ai.conversation.id`, plus the model, diff size, truncation, token counts
and outcome. **Metadata only**: no prompt, diff or response is ever an
attribute. Rust: `src/tracing.rs`, spans opened by `Platform::in_span`.

## Secrets and configuration

Secrets (never committed, never printed): `GITHUB_APP_PRIVATE_KEY`,
`GITHUB_WEBHOOK_SECRET`, and the WorkOS values the repository treats as
secrets (`WORKOS_AUTHORIZATION_SERVER`, `WORKOS_JWKS_URL`, `WORKOS_ISSUER`,
`WORKOS_AUDIENCE`). Everything else is a public `[vars]` entry in
`wrangler.toml`, which `wrangler deploy` replaces wholesale, so nothing public
lives only in the dashboard.
