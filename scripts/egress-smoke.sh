#!/usr/bin/env bash
#
# egress-smoke.sh — exercise the recording webhook ingest path WITHOUT a live
# media session.
#
# Recording capture needs LiveKit + headless Chrome compositing a real
# participant's media — which you can't produce in a plain dev container. But the
# part that is ours to verify is the control plane: that authd accepts a
# correctly-signed LiveKit webhook, rejects a forged one, and drives a recording
# row starting -> active -> completed with the output file recorded. This script
# forges the LiveKit HS256 webhook JWT (signing input + hex body-sha256 claim,
# exactly as internal/livekit/webhook.go verifies it) and fires the lifecycle.
#
# Two modes:
#   (default)     verify-only — POST a valid webhook (expect 200) and a forged
#                 one (expect 401). Proves ingest + signature verification. Needs
#                 only a reachable authd; no DB.
#   --with-db     full lifecycle — seed a session + recording row via psql, then
#                 fire started/ended webhooks and read the row back, showing the
#                 real starting -> active -> completed transition and output_uri.
#
# Usage:
#   scripts/egress-smoke.sh                 # verify-only against http://localhost:8080
#   scripts/egress-smoke.sh --with-db       # full lifecycle (uses docker compose db)
#
# Config (env, with compose defaults):
#   API_BASE    authd base URL                  (default http://localhost:8080)
#   LK_KEY      LiveKit API key  (= webhook iss) (default devkey)
#   LK_SECRET   LiveKit API secret (HMAC key)    (default devsecret)
#   DB_EXEC     psql command for --with-db       (default: docker compose exec ... db psql ...)
#
# Requires: bash, curl, openssl. (--with-db additionally: docker compose, or a
# custom DB_EXEC.)
set -euo pipefail

API_BASE=${API_BASE:-http://localhost:8080}
LK_KEY=${LK_KEY:-devkey}
LK_SECRET=${LK_SECRET:-devsecret}
WEBHOOK_URL="$API_BASE/v1/webhooks/livekit"
DB_EXEC=${DB_EXEC:-docker compose exec -e PGPASSWORD=laplat -T db psql -U laplat -d laplat -v ON_ERROR_STOP=1 -tA}

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m%s\033[0m\n' "$*"; }

# base64url (no padding), reading stdin.
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

# mint_jwt <body-file> <secret> -> prints a LiveKit-style HS256 JWT whose sha256
# claim is the hex SHA-256 of the body file (matching verifyWebhookJWT).
mint_jwt() {
  local body_file="$1" secret="$2"
  local body_sha now exp nbf header claims h_b64 c_b64 signing sig
  body_sha=$(openssl dgst -sha256 "$body_file" | awk '{print $NF}')
  now=$(date +%s); exp=$((now + 300)); nbf=$((now - 30))
  header='{"alg":"HS256","typ":"JWT"}'
  claims=$(printf '{"iss":"%s","sha256":"%s","exp":%s,"nbf":%s}' "$LK_KEY" "$body_sha" "$exp" "$nbf")
  h_b64=$(printf '%s' "$header" | b64url)
  c_b64=$(printf '%s' "$claims" | b64url)
  signing="$h_b64.$c_b64"
  sig=$(printf '%s' "$signing" | openssl dgst -sha256 -hmac "$secret" -binary | b64url)
  printf '%s.%s' "$signing" "$sig"
}

# post_webhook <body-file> <secret> -> prints the HTTP status code.
post_webhook() {
  local body_file="$1" secret="$2" token
  token=$(mint_jwt "$body_file" "$secret")
  curl -sS -o /dev/null -w '%{http_code}' \
    -X POST "$WEBHOOK_URL" \
    -H "Authorization: Bearer $token" \
    -H 'Content-Type: application/webhook+json' \
    --data-binary @"$body_file"
}

# event_body <event> <egress-id> <status> [output-location] -> writes JSON to a
# temp file and prints its path.
event_body() {
  local event="$1" egress_id="$2" status="$3" out="${4:-}" f
  f=$(mktemp)
  if [ -n "$out" ]; then
    printf '{"event":"%s","egressInfo":{"egressId":"%s","roomName":"smoke-room","status":"%s","file":{"filename":"smoke.mp4","location":"%s"}}}' \
      "$event" "$egress_id" "$status" "$out" > "$f"
  else
    printf '{"event":"%s","egressInfo":{"egressId":"%s","roomName":"smoke-room","status":"%s"}}' \
      "$event" "$egress_id" "$status" > "$f"
  fi
  printf '%s' "$f"
}

EGRESS_ID="smoke-eg-$(date +%s)"

info "authd webhook endpoint: $WEBHOOK_URL  (iss=$LK_KEY)"

# ---- Step 1: a correctly-signed webhook is accepted (200) -------------------
body=$(event_body egress_ended "$EGRESS_ID" EGRESS_COMPLETE "/out/smoke.mp4")
code=$(post_webhook "$body" "$LK_SECRET")
rm -f "$body"
if [ "$code" = "200" ]; then
  green "[ok] valid webhook accepted (HTTP $code)"
else
  red   "[FAIL] valid webhook returned HTTP $code (expected 200) — is authd up at $API_BASE?"
  exit 1
fi

# ---- Step 2: a webhook signed with the wrong secret is rejected (401) -------
body=$(event_body egress_ended "$EGRESS_ID" EGRESS_COMPLETE "/out/smoke.mp4")
code=$(post_webhook "$body" "wrong-secret")
rm -f "$body"
if [ "$code" = "401" ]; then
  green "[ok] forged webhook rejected (HTTP $code)"
else
  red   "[FAIL] forged webhook returned HTTP $code (expected 401) — signature gate not enforced!"
  exit 1
fi

if [ "${1:-}" != "--with-db" ]; then
  green "verify-only smoke passed. Re-run with --with-db to drive a recording row end-to-end."
  exit 0
fi

# ---- Step 3 (--with-db): full lifecycle against a seeded recording row ------
info "seeding a direct session + recording row (egress_id=$EGRESS_ID)"
REC_ID="smoke-rec-$(date +%s)"
$DB_EXEC >/dev/null <<SQL
INSERT INTO sessions (id, kind, livekit_room)
VALUES ('smoke-sess', 'direct', 'smoke-room-lk')
ON CONFLICT (id) DO NOTHING;
INSERT INTO recordings (id, session_id, egress_id, status)
VALUES ('$REC_ID', 'smoke-sess', '$EGRESS_ID', 'starting');
SQL

show_status() {
  $DB_EXEC -c "SELECT status || '  output_uri=' || COALESCE(output_uri, '<null>') FROM recordings WHERE id = '$REC_ID';"
}
info "seeded:        $(show_status)"

body=$(event_body egress_started "$EGRESS_ID" EGRESS_ACTIVE)
post_webhook "$body" "$LK_SECRET" >/dev/null; rm -f "$body"
info "after started: $(show_status)"

body=$(event_body egress_ended "$EGRESS_ID" EGRESS_COMPLETE "/out/smoke.mp4")
post_webhook "$body" "$LK_SECRET" >/dev/null; rm -f "$body"
final=$(show_status)
info "after ended:   $final"

if printf '%s' "$final" | grep -q "completed  output_uri=/out/smoke.mp4"; then
  green "lifecycle smoke passed: row reached completed with the output file recorded."
  green "authd would now serve a signed playback URL for this recording from /out/smoke.mp4."
else
  red "[FAIL] expected completed with output_uri=/out/smoke.mp4, got: $final"
  exit 1
fi
