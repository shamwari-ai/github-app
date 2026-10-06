#!/usr/bin/env bash
# Owner-only. Turns the GitHub App manifest code into credentials, straight
# into 1Password, and from 1Password into the Worker's secrets. Nothing is
# printed, written to disk or passed in argv except the single-use code.
#
#   scripts/github-app-convert.sh <code>     exchange the manifest code (within 1 hour)
#   scripts/github-app-convert.sh secrets    pipe the Worker secrets from 1Password to wrangler
#
# Needs: gh (signed in as a shamwari-ai owner), op (signed in), jq, npx.
# Vault: $OP_VAULT, default "Bundu Infrastructure". Item: "shamwari-ai/github-app".
set -euo pipefail

VAULT="${OP_VAULT:-Bundu Infrastructure}"
ITEM="shamwari-ai/github-app"
WORKER="shamwari-github-mcp"

need() { command -v "$1" >/dev/null || { echo "missing: $1" >&2; exit 1; }; }

field() { op read "op://$VAULT/$ITEM/$1"; }

case "${1:-}" in
  "" | -h | --help)
    sed -n '2,11p' "$0"
    ;;
  secrets)
    need op; need npx
    # The two values the Worker needs. Client id/secret stay in 1Password:
    # the App does no user OAuth, so the Worker never holds them.
    for name in GITHUB_APP_PRIVATE_KEY GITHUB_WEBHOOK_SECRET; do
      field "$name" | npx wrangler secret put "$name" --name "$WORKER" >/dev/null
      echo "set $name on $WORKER"
    done
    echo "GITHUB_APP_ID is public: put $(field GITHUB_APP_ID) in wrangler.toml by pull request."
    ;;
  *)
    need gh; need op; need jq
    code="$1"
    [[ "$code" =~ ^[A-Za-z0-9_-]{1,100}$ ]] || { echo "not a manifest code" >&2; exit 1; }
    if op item get "$ITEM" --vault "$VAULT" >/dev/null 2>&1; then
      echo "1Password item '$ITEM' already exists in '$VAULT'; rename or remove it first." >&2
      exit 1
    fi
    # The response holds pem, webhook_secret and client_secret. It goes from
    # gh to jq to op through pipes only.
    gh api -X POST "/app-manifests/$code/conversions" |
      jq --arg title "$ITEM" '{
        title: $title,
        category: "API_CREDENTIAL",
        fields: [
          {id: "GITHUB_APP_ID", label: "GITHUB_APP_ID", type: "STRING", value: (.id | tostring)},
          {id: "GITHUB_APP_SLUG", label: "GITHUB_APP_SLUG", type: "STRING", value: .slug},
          {id: "GITHUB_APP_CLIENT_ID", label: "GITHUB_APP_CLIENT_ID", type: "STRING", value: .client_id},
          {id: "GITHUB_APP_CLIENT_SECRET", label: "GITHUB_APP_CLIENT_SECRET", type: "CONCEALED", value: .client_secret},
          {id: "GITHUB_WEBHOOK_SECRET", label: "GITHUB_WEBHOOK_SECRET", type: "CONCEALED", value: .webhook_secret},
          {id: "GITHUB_APP_PRIVATE_KEY", label: "GITHUB_APP_PRIVATE_KEY", type: "CONCEALED", value: .pem}
        ]
      }' |
      op item create --vault "$VAULT" >/dev/null
    echo "saved to 1Password: $VAULT / $ITEM"
    echo "App: https://github.com/organizations/shamwari-ai/settings/apps/$(field GITHUB_APP_SLUG)"
    echo "next: scripts/github-app-convert.sh secrets"
    ;;
esac
