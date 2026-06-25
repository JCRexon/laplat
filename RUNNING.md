# Running laplat locally

Two ways to bring up the whole stack — Postgres, `authd`, and the web client —
on your own machine. Both use the **dev console OTP sender**: login codes are
written to `authd`'s logs instead of being emailed/SMSed, so no vendor is needed.
Both are **DEV ONLY**.

## Option A — Docker Compose (no toolchain on the host)

Requires only Docker (Docker Desktop on a Mac).

```sh
docker compose up --build
```

Then open **http://localhost:5173**:

1. Sign in with any email.
2. Find the code in the compose logs — the `authd` service prints
   `"msg":"DEV OTP issued…","code":"NNNNNN"`.
3. Enter it, then climb the assurance ladder on **My identity** and browse the
   **Catalog**. Phone OTP works the same way.

What the compose runs: `db` (Postgres 16) → `migrate` (applies the migrations
with `psql`, then exits) → `authd` (`:8080`, dev OTP sender) → `web` (a
production SvelteKit build served by `adapter-node`, with `COOKIE_SECURE=false`
so its httpOnly cookies work over plain `http://localhost`). The web BFF reaches
`authd` over the internal network; the browser only ever talks to `web`.

Tear down with `docker compose down` (add `-v` to also drop the database).

## Option B — Native (Go + Node + Postgres on the host)

Useful for active development (hot reload). On macOS with Homebrew:

```sh
brew install go node postgresql@16 goose
brew services start postgresql@16
createdb laplat
goose -dir migrations postgres "postgres://localhost/laplat?sslmode=disable" up
```

Terminal 1 — `authd`:

```sh
export LAPLAT_DB_DSN="postgres://localhost:5432/laplat?sslmode=disable"
export LAPLAT_TOKEN_KID="dev-1"
export LAPLAT_TOKEN_SIGNING_KEY="$(head -c 32 /dev/urandom | base64)"
export LAPLAT_DEV_OTP_CONSOLE=1
go run ./cmd/authd     # :8080
```

Terminal 2 — web:

```sh
cd web
npm install
API_BASE=http://localhost:8080 npm run dev   # http://localhost:5173
```

## Limits of the local stack

- **Live room** needs a LiveKit server (`LAPLAT_LIVEKIT_*`); without it
  `/v1/sessions` 404s and the room won't connect.
- **`verified` tier** needs the eKYC vendor (not wired); reach it via `adminctl`
  to test instructor flows.

See `web/README.md` for the frontend's design and the `npm run e2e` smoke test.
