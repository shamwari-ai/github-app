#!/usr/bin/env bash
# Local end-to-end smoke test of the BUILT Worker under `wrangler dev`, using
# throwaway keys and dummy non-secret values. Nothing here touches production,
# GitHub, WorkOS or 1Password, and no real credential is read or written.
#
#   scripts/smoke-local.sh
#
# What it proves that `cargo test` cannot: the wasm build itself, on workerd.
#   * the MCP round trip (legacy initialize, tools/list, modern server/discover)
#   * WorkOS RS256 token verification against a JWKS (fixture served locally)
#   * the webhook HMAC-SHA256 signature path (good, bad, unsigned)
#   * the GitHub App JWT: signed in wasm with a throwaway key, checked here
#     with openssl, against a stand-in GitHub API (shamwari_whoami)
#
# Needs: openssl, python3, curl, jq, node (for npx wrangler@4; the Worker uses
# the Workers custom-spans API, which needs a current wrangler), a Rust
# toolchain with the wasm32-unknown-unknown target. No Cloudflare login is
# needed: the run uses a copy of wrangler.toml WITHOUT the `[ai]` binding, which
# would otherwise force wrangler dev to open a remote session. The checks below
# never call the model.
set -euo pipefail

cd "$(dirname "$0")/.."
WORK="$(mktemp -d)"
PORT_DEV="${PORT_DEV:-8788}"
PORT_STUB="${PORT_STUB:-8799}"
pids=()
cleanup() {
  for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done
  rm -rf "$WORK" .dev.vars.smoke wrangler.smoke.toml
}
trap cleanup EXIT

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok   $*"; }

# --- throwaway fixtures ------------------------------------------------------
openssl genrsa -out "$WORK/app.pem" 2048 2>/dev/null          # the "GitHub App" key (PKCS#1 or PKCS#8)
openssl genrsa -out "$WORK/idp.pem" 2048 2>/dev/null          # the "WorkOS" signing key
openssl rsa -in "$WORK/idp.pem" -pubout -out "$WORK/idp.pub" 2>/dev/null
python3 - "$WORK" <<'PY'
import base64, json, subprocess, sys
w = sys.argv[1]
txt = subprocess.check_output(["openssl", "rsa", "-pubin", "-in", f"{w}/idp.pub", "-noout", "-modulus"]).decode()
n = bytes.fromhex(txt.strip().split("=")[1])
b = lambda x: base64.urlsafe_b64encode(x).rstrip(b"=").decode()
json.dump({"keys": [{"kty": "RSA", "kid": "smoke", "alg": "RS256", "use": "sig", "n": b(n), "e": b(b"\x01\x00\x01")}]}, open(f"{w}/jwks.json", "w"))
PY

ISSUER="https://idp.smoke.test"
AUD="http://127.0.0.1:${PORT_DEV}/mcp"
mint() { # mint <claims-json-fragment>
  local now exp h p sig
  now=$(date +%s); exp=$((now + 600))
  h=$(printf '{"alg":"RS256","typ":"JWT","kid":"smoke"}' | b64url)
  p=$(printf '{"iss":"%s","aud":"%s","iat":%s,"exp":%s,%s}' "$ISSUER" "$AUD" "$now" "$exp" "$1" | b64url)
  sig=$(printf '%s.%s' "$h" "$p" | openssl dgst -sha256 -sign "$WORK/idp.pem" | b64url)
  printf '%s.%s.%s' "$h" "$p" "$sig"
}
GOOD=$(mint '"org_id":"org_smoke","role":"platform-team"')
WRONG_ORG=$(mint '"org_id":"org_other","role":"platform-team"')

# --- a stand-in GitHub API and JWKS host -------------------------------------
cat > "$WORK/stub.py" <<'PY'
import http.server, json, os, sys
work, port = sys.argv[1], int(sys.argv[2])
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        if self.path == "/jwks.json":
            return self.send(200, json.load(open(f"{work}/jwks.json")))
        auth = self.headers.get("Authorization", "")
        if self.path == "/app":
            open(f"{work}/app-jwt.txt", "w").write(auth.removeprefix("Bearer "))
            return self.send(200, {"slug": "smoke-app", "name": "Smoke App", "permissions": {"issues": "write"}})
        if self.path.startswith("/repos/") and self.path.endswith("/installation"):
            return self.send(200, {"id": 7, "repository_selection": "selected",
                                   "permissions": {"pull_requests": "write", "issues": "write", "contents": "read", "metadata": "read"}})
        self.send(404, {"message": "Not Found"})
http.server.HTTPServer(("127.0.0.1", port), H).serve_forever()
PY
python3 "$WORK/stub.py" "$WORK" "$PORT_STUB" & pids+=($!)

# --- the Worker under wrangler dev ---------------------------------------------
sed '/^\[ai\]/,/^$/d' wrangler.toml >wrangler.smoke.toml
cat > .dev.vars.smoke <<VARS
GITHUB_APP_PRIVATE_KEY="$(cat "$WORK/app.pem")"
GITHUB_WEBHOOK_SECRET=smoke-webhook-secret
WORKOS_AUTHORIZATION_SERVER=$ISSUER
VARS
${WRANGLER:-npx --yes wrangler@4} dev -c wrangler.smoke.toml --port "$PORT_DEV" --env-file .dev.vars.smoke \
  --var "GITHUB_API:http://127.0.0.1:${PORT_STUB}" \
  --var "GITHUB_APP_ID:424242" \
  --var "WORKOS_JWKS_URL:http://127.0.0.1:${PORT_STUB}/jwks.json" \
  --var "WORKOS_ISSUER:$ISSUER" \
  --var "WORKOS_AUDIENCE:$AUD" \
  --var "WORKOS_ORG_ID:org_smoke" \
  --var "MCP_RESOURCE_URL:$AUD" \
  --var "MCP_RESOURCE_HOSTS:127.0.0.1:${PORT_DEV}" \
  >"$WORK/dev.log" 2>&1 & pids+=($!)

BASE="http://127.0.0.1:${PORT_DEV}"
for _ in $(seq 1 120); do
  curl -fsS "$BASE/health" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS "$BASE/health" >/dev/null 2>&1 || { tail -40 "$WORK/dev.log" >&2; fail "wrangler dev did not come up"; }

# --- checks ---------------------------------------------------------------------
[[ "$(curl -fsS "$BASE/health" | jq -r .status)" == ok ]] && pass "GET /health"

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/mcp" -H 'Content-Type: application/json' -d '{}')
[[ "$code" == 401 ]] && pass "POST /mcp without a token is 401" || fail "no token gave $code"

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/mcp" -H "Authorization: Bearer $WRONG_ORG" -H 'Content-Type: application/json' -d '{}')
[[ "$code" == 401 ]] && pass "a token from another organisation is 401" || fail "wrong org gave $code"

meta=$(curl -fsS "$BASE/.well-known/oauth-protected-resource")
[[ "$(jq -r .resource <<<"$meta")" == "$AUD" ]] && pass "resource metadata names the served host" || fail "metadata: $meta"
[[ "$(jq -r '.authorization_servers[0]' <<<"$meta")" == "$ISSUER" ]] && pass "metadata advertises the configured authorization server"

rpc() { curl -fsS -X POST "$BASE/mcp" -H "Authorization: Bearer $GOOD" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' "$@"; }

init=$(rpc -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"1"}}}')
[[ "$(jq -r .result.protocolVersion <<<"$init")" == 2025-06-18 ]] && pass "MCP initialize (legacy era)" || fail "initialize: $init"

tools=$(rpc -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}')
n=$(jq '.result.tools | length' <<<"$tools")
[[ "$n" == 13 ]] && pass "MCP tools/list returns 13 tools" || fail "tools/list: $tools"
jq -e '.result.tools | map(.name) | (index("shamwari_whoami") != null) and (index("shamwari_merge") == null)' <<<"$tools" >/dev/null && pass "whoami present, no merge tool"

disc=$(rpc -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: server/discover' \
  -d '{"jsonrpc":"2.0","id":3,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}')
[[ "$(jq -r '.result.supportedVersions[0]' <<<"$disc")" == 2026-07-28 ]] && pass "MCP server/discover (modern era)" || fail "discover: $disc"

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/mcp" -H "Authorization: Bearer $GOOD" -H 'Content-Type: application/json' -H 'MCP-Protocol-Version: 2026-07-28' \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}')
[[ "$code" == 400 ]] && pass "modern request without Mcp-Method is 400" || fail "missing Mcp-Method gave $code"

# whoami: the Worker signs an App JWT in wasm, calls the stand-in GitHub API.
started=$(python3 -c 'import time; print(time.time())')
who=$(rpc -d '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"shamwari_whoami","arguments":{}}}')
elapsed=$(python3 -c "import time; print(round((time.time() - $started) * 1000))")
echo "info whoami (parse key, sign in wasm, 4 stub calls): ${elapsed} ms wall clock"
text=$(jq -r '.result.content[0].text' <<<"$who")
[[ "$(jq -r .ready <<<"$text" 2>/dev/null)" == true ]] && pass "shamwari_whoami reports ready" || { echo "$who" >&2; fail "whoami not ready"; }
jwt=$(cat "$WORK/app-jwt.txt")
IFS=. read -r jh jp js <<<"$jwt"
printf '%s.%s' "$jh" "$jp" > "$WORK/signed.txt"
printf '%s' "$js" | tr '_-' '/+' | { cat; printf '=='; } | openssl base64 -d -A > "$WORK/sig.bin" 2>/dev/null
openssl rsa -in "$WORK/app.pem" -pubout -out "$WORK/app.pub" 2>/dev/null
openssl dgst -sha256 -verify "$WORK/app.pub" -signature "$WORK/sig.bin" "$WORK/signed.txt" >/dev/null \
  && pass "the App JWT signed in wasm verifies with the matching public key (openssl)" || fail "App JWT signature invalid"
[[ "$(printf '%s' "$jp" | tr '_-' '/+' | { cat; printf '=='; } | openssl base64 -d -A 2>/dev/null | jq -r .iss)" == 424242 ]] && pass "the JWT iss is GITHUB_APP_ID from vars"

# public pages
card=$(curl -fsS "$BASE/.well-known/agent-card.json")
[[ "$(jq -r .protocolVersion <<<"$card")" == 1.0 ]] && pass "A2A agent card (protocol 1.0)" || fail "agent card: $card"
curl -fsS "$BASE/github-app/new" | grep -q 'enterprises/bundu-labs/settings/apps/new' && pass "/github-app/new posts to the bundu-labs enterprise" || fail "setup page"

# webhook: HMAC-SHA256 over the raw body.
body='{"zen":"smoke"}'
sig="sha256=$(printf '%s' "$body" | openssl dgst -sha256 -hmac smoke-webhook-secret | sed 's/^.* //')"
hook() { curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/webhook" -H 'Content-Type: application/json' -H 'X-GitHub-Event: ping' "$@" -d "$body"; }
[[ "$(hook -H "X-Hub-Signature-256: $sig")" == 200 ]] && pass "webhook: a correctly signed ping is accepted" || fail "good signature rejected"
[[ "$(hook -H "X-Hub-Signature-256: sha256=$(printf 'f%.0s' $(seq 64))")" == 401 ]] && pass "webhook: a wrong signature is 401" || fail "bad signature accepted"
[[ "$(hook)" == 401 ]] && pass "webhook: an unsigned delivery is 401" || fail "unsigned accepted"

echo "all smoke checks passed"
