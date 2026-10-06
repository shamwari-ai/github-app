# AGENTS.md

Shamwari for GitHub: a Cloudflare Worker (`shamwari-github-mcp`) serving an
MCP server, an A2A endpoint and a GitHub webhook at **github.shamwari.ai**,
acting on GitHub only as the **Shamwari for GitHub** App (shamwari-ai org).
Moved here from `nyuchi/web-services/worker` with its history.

## Rules

- **Big work lives in GitHub issues** in this repo: plan, decisions and
  status, so another session can pick it up. Open or update the issue before
  starting, and link it from the PR.
- Branches: feature PRs target `staging`. `staging` to `main` is a release.
  Squash or rebase only, linear history, no bypassing rulesets, no
  `--no-verify`. A staging merge is a patch release. Main gets a minor.
- Checks: the org-required "Org lint" workflow runs `vite-plus / fmt, check,
test, build` and `lint / actionlint, markdownlint, yamllint`. Locally:
  `npm run check && npm test && npm run build`.
- Secrets: never print, commit or pass in argv. They live in 1Password
  (`shamwari-ai/github-app`) and reach the Worker via
  `scripts/github-app-convert.sh secrets`. `wrangler deploy` replaces
  `[vars]`, so every non-secret setting lives in `wrangler.toml`, never only in
  the dashboard. A dashboard edit is how `github.shmwari.ai` happened.
- The OAuth resource URL is derived from the request host
  (`resourceUrlFor`, `MCP_RESOURCE_HOSTS`). Never hardcode a host in code
  paths, and never hardcode the AuthKit domain (`WORKOS_AUTHORIZATION_SERVER`
  is config only).
- Every host in `MCP_RESOURCE_HOSTS` must also be registered as an AuthKit
  OAuth resource (`https://<host>/mcp`) in WorkOS. Otherwise OAuth fails for
  that host.
- Names: Shamwari is the consumer AI and Nyuchi AI is internal. Never use
  "Ubuntu AI". British spelling: licence (noun), license (verb).
- Security reports: see SECURITY.md (<security@nyuchi.com>).

## Dev skills, progress reports and the merge gate

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
- **Merge gate.** Merge only when the work is complete, CI is green, it's
  verified at runtime, and `/code-review` has run with findings resolved.

## Layout

- `src/`: Worker (`index.ts` routes, `auth.ts` WorkOS + resource metadata,
  `github.ts` App JWT and installation tokens, `mcp.ts` tools, `review.ts` the
  reviewer, `webhook.ts`, `a2a.ts`, `setup.ts` App setup pages)
- `test/`: `node:test` via tsx
- `app-manifest.json`: the GitHub App definition (see docs/github-app.md)
- `scripts/github-app-convert.sh`: owner-only credential plumbing
