# The GitHub App

**Shamwari for GitHub** is a GitHub App owned by the **shamwari-ai**
organisation. This Worker authenticates to GitHub only as that App. It signs a
short-lived JWT with the App's private key and exchanges it for an
installation access token per repository (`src/github.ts`), scoped down to
`GITHUB_TOKEN_PERMISSIONS`. There is no personal access token anywhere.

`app-manifest.json` is the App's definition, reviewed like code. A test
(`test/setup.test.ts`) pins its permissions and URLs.

## Permissions (least privilege)

| Permission      | Level | Why                                                                                  |
| --------------- | ----- | ------------------------------------------------------------------------------------ |
| `metadata`      | read  | Mandatory for every App                                                              |
| `contents`      | read  | Diffs, files and commit comments (GitHub lists commit comments under Contents: read) |
| `checks`        | read  | The check-run rollup in `shamwari_get_pull_request`                                  |
| `pull_requests` | write | Read PRs and diffs, post reviews, open and update PRs                                |
| `issues`        | write | List, file and update issues, and comment on issues and PRs                          |

It has no `workflows`, `administration` or `contents: write`. It cannot merge
or push, and the Worker refuses `APPROVE`.

Events: `pull_request` (review on open, ready and new commits) and
`issue_comment` (the `@shamwari` mention). Webhook:
`https://github.shamwari.ai/webhook`, verified with `GITHUB_WEBHOOK_SECRET`.

There is no user OAuth (`request_oauth_on_install: false`, no callback URLs).
The App never acts as a person. People reach the MCP server through WorkOS,
not through the App.

## One-click creation (owner)

GitHub's manifest flow is a form POST, so the one click is a page on the
Worker:

1. Open **<https://github.shamwari.ai/github-app/new>** and press **Create the
   App on GitHub**. It POSTs the bundled `app-manifest.json` to
   `https://github.com/organizations/shamwari-ai/settings/apps/new?state=<random>`.
   Confirm the name on GitHub. You need to be an owner of shamwari-ai.
2. GitHub redirects to `https://github.shamwari.ai/github-app/created?code=…`,
   which shows one command. Within the hour, from a clone of this repo, signed
   in to `gh` and `op`:

   ```sh
   scripts/github-app-convert.sh <code>
   ```

   This exchanges the code (`POST /app-manifests/{code}/conversions`) and
   pipes the result into the 1Password item **`shamwari-ai/github-app`**
   (vault `$OP_VAULT`, default "Bundu Infrastructure"). Nothing is printed. The
   item gets these fields:

   | Field                      | Secret | Goes to                                   |
   | -------------------------- | ------ | ----------------------------------------- |
   | `GITHUB_APP_ID`            | no     | `wrangler.toml` `[vars]`, by pull request |
   | `GITHUB_APP_SLUG`          | no     | install URL                               |
   | `GITHUB_APP_CLIENT_ID`     | no     | 1Password only (no user OAuth)            |
   | `GITHUB_APP_CLIENT_SECRET` | yes    | 1Password only                            |
   | `GITHUB_WEBHOOK_SECRET`    | yes    | Worker secret                             |
   | `GITHUB_APP_PRIVATE_KEY`   | yes    | Worker secret                             |

3. Set the Worker secrets from 1Password (piped, never on screen):

   ```sh
   scripts/github-app-convert.sh secrets
   ```

4. Open a pull request that changes `GITHUB_APP_ID` in `wrangler.toml` to the
   new id, and adds `checks:read` to `GITHUB_TOKEN_PERMISSIONS`. The old
   release App does not hold Checks, so that addition must land together with
   the switch, or token minting returns 422.
5. Install the App on each organisation whose repositories it should serve
   (`https://github.com/apps/<slug>/installations/new`), selecting only those
   repositories. Then add each one to `GITHUB_ALLOWED_REPOS` by pull request.
   The allowlist is the outer bound, so installing alone switches nothing on.
6. Once reviews arrive from the new App, uninstall the old release App from
   this Worker's repositories, or leave it if release tooling still uses it.
   Remove its key from this Worker. It has already been overwritten in step 3.

## Enterprise install (owner)

All three organisations the App serves, `nyuchi`, `shamwari-ai` and
`mukoko-dev`, are inside the **bundu-labs** enterprise
(<https://github.com/enterprises/bundu-labs>; owner, 2026-10-28). Install the App
once at that level, then add it to each organisation, rather than managing
three separate installs by hand.

1. An **enterprise owner** (an app manager cannot) opens the enterprise's
   GitHub Apps settings and installs **Shamwari for GitHub** on the enterprise.
   GitHub's steps:
   <https://docs.github.com/en/enterprise-cloud@latest/apps/using-github-apps/installing-a-github-app-on-your-enterprise>.
2. Install it on each organisation, choosing **selected repositories** only.
   GitHub also has an API for installing an App on the organisations an
   enterprise owns; it can only be called by an App installed on that
   enterprise.
3. Add every repository it should serve to `GITHUB_ALLOWED_REPOS` by pull
   request. The allowlist stays the outer bound: an enterprise install alone
   switches nothing on, and it is listed repository by repository, never by
   wildcard.

Two limits to check against GitHub's current documentation before relying on
them (this section was written from the docs, not from a live install):

- An App installed at the enterprise level does not receive webhooks for
  enterprise-level events. This Worker only needs `pull_request` and
  `issue_comment`, which are repository events.
- Not every API supports enterprise-installed Apps. Installation access tokens
  for repositories are still minted per organisation installation
  (`src/github.ts`), so confirm that the per-organisation install exists for each
  organisation, not just the enterprise one.

The Worker needs no code change for this: it already mints a token per
repository installation. The one change that does need code is switching
`GITHUB_APP_ID` to the new App (step 4 above).

## Rotating

- Private key: generate a new key in the App settings, put it in 1Password,
  run `scripts/github-app-convert.sh secrets`, then delete the old key on
  GitHub.
- Webhook secret: set a new one in the App settings and in 1Password, then
  run the same command.
