#!/usr/bin/env bash
# End-to-end smoke harness: boots Postgres + authd (dev console OTP sender) + the
# SvelteKit dev server, then runs the Playwright funnel test against the real
# stack. Self-contained and self-cleaning. Local/CI use only.
#
#   web/e2e/run.sh
#
# Requires: PostgreSQL 16 binaries, Node, and a Chromium for Playwright. The dev
# server is used (not a production build) so SvelteKit runs with dev=true and its
# session cookies are not Secure — required over plain http://localhost.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WEB="$REPO/web"
PGBIN=/usr/lib/postgresql/16/bin
ROOT=/tmp/lpe2e
AUTHD_PORT=8089
WEB_PORT=5173
AUTHD_LOG="$ROOT/authd.log"

cleanup() {
  # Kill the dev-server tree (npm spawns vite as a child that orphans on a plain
  # kill) and authd, by their distinctive command lines.
  pkill -9 -f "vite dev --port $WEB_PORT" 2>/dev/null || true
  pkill -9 -f "$ROOT/authd" 2>/dev/null || true
  runuser -u postgres -- "$PGBIN/pg_ctl" -D "$ROOT/data" -m immediate stop >/dev/null 2>&1 || true
}
trap cleanup EXIT
# Clear anything a previous run leaked before we start.
cleanup

echo "==> postgres"
rm -rf "$ROOT"; mkdir -p "$ROOT/sock"; chown -R postgres "$ROOT"; chmod -R 755 "$ROOT"
runuser -u postgres -- "$PGBIN/initdb" -D "$ROOT/data" -U postgres -A trust --no-locale -E UTF8 >/dev/null
runuser -u postgres -- "$PGBIN/pg_ctl" -D "$ROOT/data" -l "$ROOT/pg.log" -w -o "-k $ROOT/sock -h ''" start >/dev/null
runuser -u postgres -- psql -h "$ROOT/sock" -U postgres -d postgres -c "CREATE DATABASE app;" >/dev/null

echo "==> migrations"
for f in "$REPO"/migrations/0*.sql; do
  awk '/-- \+goose Up/{u=1;next} /-- \+goose Down/{u=0} u' "$f" | grep -v '^-- +goose' \
    | runuser -u postgres -- psql -h "$ROOT/sock" -U postgres -d app -v ON_ERROR_STOP=1 -q >/dev/null
done

echo "==> authd"
go build -o "$ROOT/authd" "$REPO/cmd/authd"
LAPLAT_DB_DSN="host=$ROOT/sock user=postgres dbname=app" \
LAPLAT_TOKEN_KID="dev-1" \
LAPLAT_TOKEN_SIGNING_KEY="$(head -c32 /dev/urandom | base64 -w0)" \
LAPLAT_DEV_OTP_CONSOLE=1 \
LAPLAT_HTTP_ADDR="127.0.0.1:$AUTHD_PORT" \
  "$ROOT/authd" >"$AUTHD_LOG" 2>&1 &
AUTHD_PID=$!
for i in $(seq 1 30); do
  curl -fsS "http://127.0.0.1:$AUTHD_PORT/healthz" >/dev/null 2>&1 && break
  sleep 0.5
done
curl -fsS "http://127.0.0.1:$AUTHD_PORT/healthz" >/dev/null

echo "==> sveltekit dev server"
# --strictPort: fail rather than silently drift to another port (which would let
# a stale server answer the test on the expected port).
( cd "$WEB" && API_BASE="http://127.0.0.1:$AUTHD_PORT" npm run dev -- --port "$WEB_PORT" --strictPort --host 127.0.0.1 >"$ROOT/web.log" 2>&1 ) &
for i in $(seq 1 60); do
  curl -fsS "http://127.0.0.1:$WEB_PORT/signin" >/dev/null 2>&1 && break
  sleep 0.5
done
curl -fsS "http://127.0.0.1:$WEB_PORT/signin" >/dev/null 2>&1 || { echo "sveltekit dev server did not come up on $WEB_PORT"; tail -5 "$ROOT/web.log"; exit 1; }

echo "==> playwright"
CHROMIUM="$(find /opt/pw-browsers -type f -name chrome -path '*chrome-linux*' 2>/dev/null | head -1)"
cd "$WEB"
E2E_BASE_URL="http://127.0.0.1:$WEB_PORT" \
E2E_AUTHD_LOG="$AUTHD_LOG" \
E2E_CHROMIUM="$CHROMIUM" \
PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
  npx playwright test "$@"
