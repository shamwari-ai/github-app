# Runbook: move the GitHub App to the bundu-labs enterprise

For the **owner** (an enterprise owner of `bundu-labs`). It registers the App
under the enterprise, installs it on the organisations it serves, puts its
credentials on the Worker and verifies the result. About 30 minutes.

You will handle a private key. Nothing in this repository, in CI or in a chat
session ever sees it: it goes from GitHub to 1Password, and from 1Password to
the Worker through `scripts/github-app-convert.sh`, which prints nothing.

Why: the App `shamwari-for-github` (ID `5579098`) is owned by the
`bundu-labs` _organisation_. It must be owned by the _enterprise_, so the
enterprise can manage it and install it across its organisations. An App cannot
change owner type, so this is a new App with a new ID, key and webhook secret.
Background: [github-app.md](github-app.md).

## 0. Before you start

- You are an **enterprise owner** of `bundu-labs`
  (<https://github.com/enterprises/bundu-labs/people>). An app manager cannot
  do step 3.
- Tools on your machine: `gh` (signed in), `op` (signed in, with access to the
  vault `Bundu Infrastructure`), `jq`, Node (for `npx wrangler`).
- Deploys from CI need two repository secrets that are **missing today**, which
  is why every deploy since 2 November has failed. Add them once, with the value
  read from stdin so it is never on a command line:

  ```bash
  gh secret set CLOUDFLARE_ACCOUNT_ID --repo shamwari-ai/github-app --body 125a2dfbc21f76a25c980609609e8218
  gh secret set CLOUDFLARE_API_TOKEN --repo shamwari-ai/github-app
  ```

  The second prompts for the token. Create it at
  <https://dash.cloudflare.com/profile/api-tokens> from the **Edit Cloudflare
  Workers** template, restricted to the _Nyuchi Web Services_ account. It needs
  Workers Scripts: Edit and nothing else.

## 1. Free the name

GitHub App names are unique across GitHub, and the old App holds
**Shamwari for GitHub**. Rename it at
<https://github.com/organizations/bundu-labs/settings/apps/shamwari-for-github>
to `Shamwari for GitHub (legacy)`. **Do not delete it yet**: it is the rollback.
(If you would rather keep that name, register the new App under another one:
the Worker never uses the name or slug, only the ID.)

## 2. Register the App under the enterprise

### Option A: one click

Open <https://github.shamwari.ai/github-app/new> and press **Create the App on
GitHub**. It posts `app-manifest.json` to
`https://github.com/enterprises/bundu-labs/settings/apps/new`. Confirm the name.
GitHub then redirects to `/github-app/created?code=...`, which shows one
command; run it **within the hour** from a clone of this repository:

```bash
scripts/github-app-convert.sh <code>
```

It exchanges the single-use code and stores the App's ID, slug, client id,
client secret, webhook secret and private key in the 1Password item
`bundu-labs/shamwari-for-github` (vault `Bundu Infrastructure`), printing none
of them. Go to step 4.

GitHub documents the manifest flow for personal and organisation accounts only.
If it refuses the enterprise URL, use Option B.

### Option B: manual registration

1. <https://github.com/enterprises/bundu-labs/settings/apps> then **New GitHub
   App** (on github.com: your profile menu, **Your enterprises**, `bundu-labs`,
   **Settings**, **GitHub Apps**).
2. Fill the form exactly as below. Anything not mentioned stays at its default
   or empty.

   | Field                                                  | Value                                             |
   | ------------------------------------------------------ | ------------------------------------------------- |
   | GitHub App name                                        | `Shamwari for GitHub`                             |
   | Description                                            | from `app-manifest.json`                          |
   | Homepage URL                                           | `https://github.shamwari.ai`                      |
   | Callback URL                                           | **empty**                                         |
   | Request user authorization (OAuth) during installation | **unticked**                                      |
   | Expire user authorization tokens                       | ticked (irrelevant: no user OAuth)                |
   | Setup URL                                              | `https://github.shamwari.ai/github-app/installed` |
   | Redirect on update                                     | **unticked**                                      |
   | Webhook > Active                                       | ticked                                            |
   | Webhook URL                                            | `https://github.shamwari.ai/webhook`              |
   | Webhook secret                                         | a fresh random value (below)                      |
   | SSL verification                                       | Enable                                            |

   Generate the webhook secret without displaying it, straight into the
   clipboard, and paste it into the form and then into 1Password:

   ```bash
   openssl rand -hex 32 | pbcopy
   ```

3. **Repository permissions**, and only these:

   | Permission    | Access                |
   | ------------- | --------------------- |
   | Metadata      | Read-only (automatic) |
   | Contents      | Read-only             |
   | Checks        | Read-only             |
   | Pull requests | Read and write        |
   | Issues        | Read and write        |

   Leave **every** other repository permission, all organisation and account
   permissions and all enterprise permissions at _No access_. In particular
   never **Workflows**, **Administration** or **Contents: write**: the Worker
   cannot merge or push by construction, and the App should not be able to
   either.

4. **Subscribe to events**: **Pull request** and **Issue comment** only (they
   appear once the permissions above are set).
5. **Where can this GitHub App be installed?** Whatever GitHub offers for an
   enterprise-owned App; it can only ever be installed inside the enterprise.
6. **Create GitHub App.** Note the **App ID** shown at the top of the App's
   settings page (a number), and the slug in the URL.
7. On the same page, **Private keys** then **Generate a private key**. A `.pem`
   downloads. In the 1Password app create (or open) the item
   `bundu-labs/shamwari-for-github` in the vault `Bundu Infrastructure` and
   give it these fields:

   | Field                    | Value                                                      |
   | ------------------------ | ---------------------------------------------------------- |
   | `GITHUB_APP_ID`          | the App ID                                                 |
   | `GITHUB_APP_SLUG`        | the slug                                                   |
   | `GITHUB_WEBHOOK_SECRET`  | the webhook secret from step 2                             |
   | `GITHUB_APP_PRIVATE_KEY` | the whole `.pem` (BEGIN and END lines included), concealed |

   Then **delete the downloaded `.pem`** (and empty the clipboard). One key at a
   time: if you ever suspect it leaked, generate a new one and delete the old
   on the same page.

## 3. Install it on the organisations

For each organisation the App serves (`nyuchi`, `shamwari-ai`, `mukoko-dev`;
the ones whose repositories are in `GITHUB_ALLOWED_REPOS`):

1. Open `https://github.com/apps/<slug>/installations/new` (or the App's
   settings page, **Install App**).
2. Choose the organisation, then **Only select repositories**, and tick exactly
   the repositories listed for that organisation in `GITHUB_ALLOWED_REPOS` in
   `wrangler.toml`. Install.

Installing on the _enterprise_ itself is not needed: the App has no enterprise
permissions. If you later add a repository, add it here **and** to
`GITHUB_ALLOWED_REPOS` by pull request; the allowlist is the outer bound.

## 4. Put the credentials on the Worker

From a clone of this repository, signed in to `op` and `wrangler`:

```bash
scripts/github-app-convert.sh secrets
```

It reads `GITHUB_APP_PRIVATE_KEY` and `GITHUB_WEBHOOK_SECRET` from the
1Password item and pipes each into `wrangler secret put ... --name
shamwari-github-mcp`. Nothing is printed except `set <NAME> on
shamwari-github-mcp`, and then the App ID to use in step 5. If your item has
another name, set `OP_ITEM`.

The live Worker has **no** `GITHUB_APP_PRIVATE_KEY` today, so setting these
cannot break anything that works now.

## 5. Switch the Worker to the new App

Open a pull request that changes, in `wrangler.toml`:

- `GITHUB_APP_ID` to the new App ID (replacing `5579098` and the `TODO(owner)`
  comment above it);
- `GITHUB_TOKEN_PERMISSIONS` to
  `pull_requests:write,issues:write,contents:read,checks:read,metadata:read`
  (adds `checks:read`, which the new App holds).

Get it through the merge queue (`gh pr merge <n>`, no strategy flag). The merge
to `main` deploys (the Deploy workflow, using the secrets from step 0). The
deployed `[vars]` block is replaced by the committed one, so this edit is the
only place the ID lives.

To deploy by hand instead: `npx wrangler@4 deploy` from a clean checkout of
`main`, with `CLOUDFLARE_ACCOUNT_ID` set.

## 6. Verify

1. `curl -fsS https://github.shamwari.ai/health` answers `{"status":"ok",...}`.
2. In an MCP client signed in through WorkOS (the "Nyuchi Internal Tools"
   connection), call `shamwari_whoami`. The client sends:

   ```json
   {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shamwari_whoami","arguments":{}}}
   ```

   A healthy result has `"ready": true`, the new App's `slug` and `name`, and for
   **every** allowlisted repository `"installed": true` and `"missing": []`. If
   `ready` is false the `note` and the per-repository `error` say which
   repository lacks an installation or which permission the installation has not
   accepted (an organisation owner must accept a pending permission request).

3. In the App's settings, **Advanced**, **Recent Deliveries**: the `ping`
   from creation (or **Redeliver**) shows `200` and
   `{"ok":true,"skipped":"ping"}`. A `401` is a webhook-secret mismatch; a
   `503` means `GITHUB_WEBHOOK_SECRET` is not set on the Worker.
4. On a pull request in an allowlisted repository, comment `@shamwari` (as an
   owner, member or collaborator). A comment from the App headed "Automated
   review" appears on the head commit within about a minute.

## 7. Clean up

Once step 6 passes and a day of normal use looks right:

- Uninstall the old App from the repositories it served, then delete it (the
  legacy `Shamwari for GitHub (legacy)` App), unless release tooling elsewhere
  still depends on it.
- Delete the old 1Password item `shamwari-ai/github-app`.

## Rolling back

Revert the pull request from step 5 (the `GITHUB_APP_ID` goes back to
`5579098`), and set the old App's private key and webhook secret on the Worker
(`OP_ITEM=shamwari-ai/github-app scripts/github-app-convert.sh secrets`). The
old App is untouched until step 7.
