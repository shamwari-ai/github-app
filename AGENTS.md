# AGENTS.md

Shamwari for GitHub: a Cloudflare Worker (`shamwari-github-mcp`), written in
Rust, serving an MCP server, an A2A endpoint and a GitHub webhook at
**github.shamwari.ai**, acting on GitHub only as the **Shamwari for GitHub**
App, owned by the bundu-labs enterprise. Moved here from
`nyuchi/web-services/worker` with its history.

## Rules

- **Big work lives in GitHub issues** in this repo: plan, decisions and
  status, so another session can pick it up. Open or update the issue before
  starting, and link it from the PR.
- Branches: trunk-based. Pull requests target `main`, and a merge to `main`
  deploys and releases (the version is the next tag, bumped from the PR
  title). There is **no `staging` branch** and it is never re-added. Go
  through the merge queue (`gh pr merge <n>`, no strategy flag), no bypassing
  rulesets, no `--no-verify`.
- Checks: the org-required "Org lint" workflow runs the `vite-plus` jobs (fmt,
  check, test, build: only `fmt` does work here, on Markdown and JSON, as
  there is no root `package.json`) and the `lint` jobs (actionlint,
  markdownlint, yamllint). The repository's own workflow runs rustfmt,
  clippy, `cargo test` and a wrangler dry-run build. Locally:
  `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`.
- Secrets: never print, commit or pass in argv. They live in 1Password
  (`shamwari-ai/github-app`) and reach the Worker via
  `scripts/github-app-convert.sh secrets`. `GITHUB_APP_ID` is a public var;
  the key and webhook secret are secrets. `wrangler deploy` replaces
  `[vars]`, so every non-secret setting lives in `wrangler.toml`, never only in
  the dashboard. A dashboard edit is how `github.shmwari.ai` happened.
- The OAuth resource URL is derived from the request host
  (`resource_url_for`, `MCP_RESOURCE_HOSTS`). Never hardcode a host in code
  paths, and never hardcode the AuthKit domain (`WORKOS_AUTHORIZATION_SERVER`
  is config only).
- Every host in `MCP_RESOURCE_HOSTS` must also be registered as an AuthKit
  OAuth resource (`https://<host>/mcp`) in WorkOS. Otherwise OAuth fails for
  that host.
- Names: Shamwari is the consumer AI and Nyuchi AI is internal. Never use
  "Ubuntu AI". British spelling: licence (noun), license (verb).
- Security reports: see SECURITY.md (<security@nyuchi.com>).

## Dev skills and progress reports

Load the Mzizi **dev skills** before starting work:
`mzizi_get_skills category=dev` on the Mzizi MCP (`mcp.mzizi.dev`), or
`@nyuchi/mzizi-skills` from npm. They are `digital-hygiene` and
`progress-report`.

- **Digital hygiene.** Check free disk before starting, clone only under
  `$TMPDIR`, share build caches, and audit, then delete, your clones once the
  work merges (`digital-hygiene` skill).
- **Clone isolation.** Clone only into a directory unique to you; never touch
  another agent's.
- **Progress reports.** All dev work runs on a 10-minute progress-report loop
  (`progress-report` skill): measured bars, what changed, and a final "Needs
  you:" line. Report ticks never publish, release, merge or deploy without the
  owner's approval.

## Layout

- `src/`: the Worker (`router.rs` routes, `auth.rs` WorkOS + resource metadata,
  `github.rs` App JWT and installation tokens, `mcp.rs` tools and protocol,
  `review.rs` the reviewer, `webhook.rs`, `a2a.rs`, `setup.rs` App setup pages,
  `worker_entry.rs` the only module that touches the Workers runtime)
- `src/tests/`: `cargo test` suite; `scripts/smoke-local.sh` runs the built wasm
- `app-manifest.json`: the GitHub App definition (see docs/github-app.md)
- `docs/`: `behaviour-contract.md`, `rust-port.md` (parity with the TypeScript
  Worker), `github-app.md`, `enterprise-app-setup.md` (owner runbook)
- `scripts/github-app-convert.sh`: owner-only credential plumbing
