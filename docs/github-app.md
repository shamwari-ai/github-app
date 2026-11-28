# The GitHub App

**Shamwari for GitHub** is a GitHub App owned by the **bundu-labs
enterprise** (an _enterprise-owned_ App), installed on the organisations in
that enterprise that it serves. This Worker authenticates to GitHub only as
that App: it signs a short-lived JWT with the App's private key and exchanges
it for an installation access token per repository (`src/github.rs`), scoped
down to `GITHUB_TOKEN_PERMISSIONS`. There is no personal access token
anywhere.

`app-manifest.json` is the App's definition, reviewed like code. A test
(`src/tests/setup.rs`) pins its permissions, events and URLs. Ownership is not
part of a manifest: it is decided by where the manifest is registered (the
enterprise's "new GitHub App" page, see
[enterprise-app-setup.md](enterprise-app-setup.md)).

## What the Worker needs from the App

| What           | Where                       | Kind   | Notes                                           |
| -------------- | --------------------------- | ------ | ----------------------------------------------- |
| App ID         | `GITHUB_APP_ID` in `[vars]` | public | An identifier, not a credential                 |
| Private key    | `GITHUB_APP_PRIVATE_KEY`    | secret | The `.pem` as GitHub issues it (PKCS#1 is fine) |
| Webhook secret | `GITHUB_WEBHOOK_SECRET`     | secret | Unset means `/webhook` answers 503              |

Pointing the Worker at a different App is therefore one `[vars]` edit plus two
secrets, in one release. Nothing else in the code names an App.

## Permissions (least privilege)

| Permission      | Level | Why                                                                                  |
| --------------- | ----- | ------------------------------------------------------------------------------------ |
| `metadata`      | read  | Mandatory for every App                                                              |
| `contents`      | read  | Diffs, files and commit comments (GitHub lists commit comments under Contents: read) |
| `checks`        | read  | The check-run rollup in `shamwari_get_pull_request`                                  |
| `pull_requests` | write | Read PRs and diffs, post reviews, open and update PRs                                |
| `issues`        | write | List, file and update issues, and comment on issues and PRs                          |

It has no `workflows`, `administration` or `contents: write`, no organisation
or enterprise permissions. It cannot merge or push, and the Worker refuses
`APPROVE`. `issues: write` is requested for the issue tools and for comments
on issues and pull requests; the review agent itself needs only
`pull_requests`, `contents: read` and `metadata`, because it posts a commit
comment (verified against GitHub's "Permissions required for GitHub Apps":
creating a commit comment needs Contents: read).

`GITHUB_TOKEN_PERMISSIONS` in `wrangler.toml` is the inner bound: a token may
request a subset of what the App holds, never a superset. Add a permission to
the App and to that list together, then have each organisation accept the
update (an enterprise owner's own change is accepted automatically; an app
manager's is not).

Events: `pull_request` (review on open, ready and new commits) and
`issue_comment` (the `@shamwari` mention). Webhook:
`https://github.shamwari.ai/webhook`, verified with `GITHUB_WEBHOOK_SECRET`.

There is no user OAuth (`request_oauth_on_install: false`, no callback URLs).
The App never acts as a person. People reach the MCP server through WorkOS,
not through the App.

## Who owns it, and what that changes

An enterprise-owned App can be installed on the enterprise's organisations (and
on the enterprise itself, which this App does not need: it has no enterprise
permissions) and cannot be installed on user accounts. Enterprise owners can
manage it; they can add _app managers_, who may change its settings and
credentials but cannot install it at enterprise level.

Moving from the old App (`shamwari-for-github`, ID 5579098, owned by the
`bundu-labs` _organisation_) is a new registration, not a transfer: the new App
has a new ID, key and webhook secret. The Worker is switched over with the
runbook in [enterprise-app-setup.md](enterprise-app-setup.md).

## Installations

The App is public: anyone may install it on their organisation. Installing
it grants exactly what the installer selects — GitHub's own repository
choice is the outer bound; there is no worker-side repository list. Each
token the Worker mints is narrowed further, per repository and per
permission, by `GITHUB_TOKEN_PERMISSIONS`.

## Rotating

- Private key: generate a new key in the App settings, put it in 1Password, run
  `scripts/github-app-convert.sh secrets`, then delete the old key on GitHub.
- Webhook secret: set a new one in the App settings and in 1Password, then run
  the same command.
