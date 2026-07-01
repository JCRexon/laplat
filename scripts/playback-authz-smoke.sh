#!/usr/bin/env bash
#
# playback-authz-smoke.sh — exercise the recording playback serving-authz
# (ADR-011) without a browser or real media.
#
# Recording playback is authorised per byte-fetch: nginx auth_request's each
# request to authd's GET /v1/recordings/authz, forwarding the original request
# line in X-Original-URI (the file path + ?t=<playback token>). authd verifies
# the per-viewer, per-recording HMAC token, confirms it is for the requested
# file, re-checks entitlement live, audits the access, and answers 204/401/403.
#
# This script forges playback tokens the same way authd mints them
# (HMAC-SHA256 over the base64url payload "<subject>|<recordingID>|<expUnix>",
# key = LAPLAT_RECORDINGS_SECRET) and asserts the authz decisions. It requires
# only a running authd; the --with-db mode additionally seeds a recording so the
# allow (204) path and the nginx wiring can be checked.
#
# Usage:
#   scripts/playback-authz-smoke.sh              # token-rejection checks (no DB)
#   scripts/playback-authz-smoke.sh --with-db    # + allow path + nginx wiring
#
# Config (env, with compose defaults):
#   API_BASE            authd base URL       (default http://localhost:8080)
#   NGINX_BASE          recordings server    (default http://localhost:9090)
#   RECORDINGS_SECRET   token HMAC key        (default devrecordingssecret)
#   DB_EXEC             psql command for --with-db (default: docker compose db)
#
# Requires: bash, curl, openssl. (--with-db additionally: docker compose.)
set -euo pipefail

API_BASE=${API_BASE:-http://localhost:8080}
NGINX_BASE=${NGINX_BASE:-http://localhost:9090}
RECORDINGS_SECRET=${RECORDINGS_SECRET:-devrecordingssecret}
AUTHZ_URL="$API_BASE/v1/recordings/authz"
DB_EXEC=${DB_EXEC:-docker compose exec -e PGPASSWORD=laplat -T db psql -U laplat -d laplat -v ON_ERROR_STOP=1 -tA}

# Seed fixtures (a direct/classless session is on the free floor, so a valid
# token alone should be authorised). Paths mirror the compose file prefix /out.
VIEWER=smoke-viewer
REC_ID=smoke-authz-rec
SESS_ID=smoke-authz-sess
OUTPUT_URI=/out/smoke.mp4
REL_PATH=/smoke.mp4   # output_uri with the /out prefix stripped (what nginx serves)

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m%s\033[0m\n' "$*"; }
fail()  { red "[FAIL] $*"; exit 1; }

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

# mint_token <secret> <subject> <recordingID> <expUnix> — matches playtoken.go.
mint_token() {
  local secret="$1" payload p sig
  payload="$2|$3|$4"
  p=$(printf '%s' "$payload" | b64url)
  sig=$(printf '%s' "$p" | openssl dgst -sha256 -hmac "$secret" -binary | b64url)
  printf '%s.%s' "$p" "$sig"
}

# authz_code <path> <token> — the HTTP status authd returns for the auth_request.
authz_code() {
  curl -sS -o /dev/null -w '%{http_code}' \
    -H "X-Original-URI: $1?t=$2" "$AUTHZ_URL"
}

expect() { # <label> <got> <want>
  if [ "$2" = "$3" ]; then green "[ok] $1 -> HTTP $2"; else fail "$1 -> HTTP $2 (want $3)"; fi
}

now=$(date +%s)
info "authz endpoint: $AUTHZ_URL"

# ---- Token-rejection ladder (no DB needed: rejected before any lookup) ------
expect "missing token" "$(authz_code "$REL_PATH" "")" 401

valid_unknown=$(mint_token "$RECORDINGS_SECRET" "$VIEWER" "$REC_ID" "$((now + 300))")
# Prepending a byte changes the MAC input but not the signature -> guaranteed mismatch.
expect "tampered token" "$(authz_code "$REL_PATH" "X${valid_unknown}")" 401

expired=$(mint_token "$RECORDINGS_SECRET" "$VIEWER" "$REC_ID" "$((now - 60))")
expect "expired token" "$(authz_code "$REL_PATH" "$expired")" 401

wrong_key=$(mint_token "not-the-secret" "$VIEWER" "$REC_ID" "$((now + 300))")
expect "wrong-key token" "$(authz_code "$REL_PATH" "$wrong_key")" 401

# A correctly-signed token for a recording that does not exist: the token
# verifies, but the recording lookup fails -> 403 (no DB row yet).
if [ "${1:-}" != "--with-db" ]; then
  expect "valid token, unknown recording" "$(authz_code "$REL_PATH" "$valid_unknown")" 403
  green "token-rejection smoke passed. Re-run with --with-db for the allow path + nginx wiring."
  exit 0
fi

# ---- Allow path + nginx wiring (--with-db) ----------------------------------
info "seeding viewer + direct session + completed recording ($REC_ID -> $OUTPUT_URI)"
$DB_EXEC >/dev/null <<SQL
INSERT INTO users (id, handle, display_name)
VALUES ('$VIEWER', '$VIEWER', 'Smoke Viewer') ON CONFLICT (id) DO NOTHING;
INSERT INTO sessions (id, kind, livekit_room)
VALUES ('$SESS_ID', 'direct', 'smoke-authz-room') ON CONFLICT (id) DO NOTHING;
INSERT INTO recordings (id, session_id, status, output_uri)
VALUES ('$REC_ID', '$SESS_ID', 'completed', '$OUTPUT_URI') ON CONFLICT (id) DO NOTHING;
SQL

valid=$(mint_token "$RECORDINGS_SECRET" "$VIEWER" "$REC_ID" "$((now + 300))")
expect "valid token, correct file (free/direct)" "$(authz_code "$REL_PATH" "$valid")" 204
# Same valid token pointed at a different file must be refused.
expect "valid token, wrong file" "$(authz_code "/someone-elses.mp4" "$valid")" 403

# nginx wiring: a tokenless request must be rejected by auth_request (401),
# proving the subrequest is active — no recording file needs to exist for this.
if curl -sS -o /dev/null -w '%{http_code}' "$NGINX_BASE/$REC_ID-probe.mp4" >/tmp/authz_nginx 2>/dev/null; then
  code=$(cat /tmp/authz_nginx); rm -f /tmp/authz_nginx
  expect "nginx tokenless fetch (auth_request active)" "$code" 401
else
  info "nginx not reachable at $NGINX_BASE — skipping the wiring check"
fi

green "playback-authz smoke passed."
