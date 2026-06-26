# Handoff

A running snapshot of where the project is and what's next, so a fresh session
(or a returning human) can get up to speed without re-reading the whole chat
history. Update the "Current state" and "Next tasks" sections as work lands.

_Last updated: 2026-06-26 — after social sign-in, admin/class/session UI, and nginx secure_link (PRs #36–#37)._

## What laplat is

A Vietnamese live-learning platform: a Go backend (`authd`) plus a SvelteKit
frontend (`web/`). The differentiated bet is a **Decree 147 / PDPL
identity-assurance ladder** — access to features is gated by how strongly a
user's identity is assured, and sensitive actions (recording, payments) are
backed by tamper-evident, legally-defensible records.

## How to get oriented fast

Read these in order — the "why" is written down, not just in commit history:

1. `ACCESS-MODEL.md` — the assurance tiers, what each unlocks, owned-vs-tier
   gating, and a **Built vs. planned** list (keep this current).
2. `AUTH-EXTENSIBILITY.md` — the "snap-in like Lego bricks" auth architecture
   (Principal/resolver registry, assurance policy, provider table).
3. `AUDIT.md` — the append-only hash-chained, signed audit log. The consent
   ledger uses the same discipline; understand one and you understand both.
4. `RUNNING.md` — how to run the stack locally (Docker Compose via
   Lima/`nerdctl compose` on a Mac).
5. `TESTING.md` — the verification story (`make check`, integration tests).
6. Package doc-comments: `internal/consent`, `internal/recording`,
   `internal/store`, `internal/session`, `internal/livekit`.

## Architecture conventions (follow these)

- **Stdlib-first.** Crypto, HTTP, JWTs are hand-rolled with the standard
  library (see `internal/livekit/token.go`, `pkg/token`). No heavyweight SDKs.
- **Two kinds of tables.** *Ledgers* (`audit_log`, `consent_records`) are
  append-only, hash-chained, ed25519-signed, and protected by DB triggers that
  block `UPDATE`/`DELETE` — they are legal evidence. *Operational state*
  (`recordings`, `sessions`) is normal mutable data.
- **Ledger store methods are hand-written SQL**, not sqlc — mirror
  `internal/store/consent.go` and `internal/store/audit.go` (advisory lock →
  read tail hash → build → sign → insert). sqlc covers the plainer queries.
- **Services depend on interfaces, not `*store.Store`**, so they can be faked
  in unit tests (see `internal/recording` `Repo`/`Egress` interfaces).
- **HTTP handlers self-authenticate** via `token.Validator` and take the acting
  subject from the token claims, never the request body. Mirror
  `internal/moderation/http.go` / `internal/consent/http.go`.
- **Decoupling via hooks.** Cross-feature reactions are wired in `main.go`, not
  by packages importing each other (e.g. consent fires `OnChange`; `main` wires
  it to `recording.ReconcileForSession`).
- **Optional features are config-gated.** LiveKit/recording only switch on when
  the relevant env vars are present; absent config = feature cleanly disabled.

## The assurance ladder (one-liner)

`none < declared < phone_verified < verified` (+ orthogonal `pending`).
Capabilities `can_instruct`, `platform_moderator`. Tiers gate the discovery
funnel; owned/paid content is entitlement-gated, not tier-gated.

## Current state (built + merged)

- Auth: token mint/rotate, email/phone OTP (with a dev-console sender), identity
  tiers + eKYC hook.
- **Social sign-in** (PR #36): Google and Apple via OIDC; SvelteKit BFF proxy
  routes at `/v1/auth/oidc/[provider]/start` and `/v1/auth/oidc/[provider]/callback`
  re-set cookies with the correct `Secure` flag for the serving environment
  (authd hardcodes `Secure: true`, which breaks plain HTTP dev). Zalo omitted
  until the provider review clears.
  - **To enable**: set `LAPLAT_OIDC_*` env vars and `LAPLAT_OIDC_REDIRECT_BASE`
    to the SvelteKit origin (e.g. `http://localhost:5173` in dev).
- Class catalog, live sessions (LiveKit room grants), instructor onboarding
  (self-apply + moderator grant/revoke), platform moderation.
- Append-only **audit log** (`internal/audit`, `internal/store/audit.go`).
- **Recording-consent ledger** (`internal/consent`, PR #29/#30): append-only,
  signed, chained; effective-consent = latest-wins; `RecordingAllowed` gate
  (every *present* participant must have a current "yes"); `VerifyChain`;
  HTTP at `/v1/consent/sessions/{id}` (POST grant / DELETE withdraw / GET).
- **Recording control plane** (`internal/recording`, PR #30): starts/stops
  LiveKit egress **only behind the consent gate** (D-2); host-triggered;
  `ReconcileForSession` auto-stops an in-flight recording on withdrawal (not
  host-gated — it's the system obeying the law). HTTP at
  `/v1/recordings/sessions/{id}`. Egress client in `internal/livekit/egress.go`
  (stdlib Twirp/JSON, roomRecord JWT). Output: local-file behind a pluggable
  client (S3/GCS snap in later).
- **LiveKit media-infra slice** (PR #37):
  - `compose.yaml` runs `redis` + `livekit/livekit-server` + `livekit/egress`
    alongside authd; all `LAPLAT_LIVEKIT_*` env vars are wired so live sessions
    and recording work end-to-end with `docker compose up --build`.
  - Dev configs: `dev/livekit.yaml` and `dev/egress.yaml` (DEV-only keys; egress
    writes to the named Docker volume `recordings`).
  - **Webhook ingest**: `internal/livekit/webhook.go` verifies the LiveKit HS256
    JWT (signing input + body SHA-256 claim); `POST /v1/webhooks/livekit` applies
    `egress_started`/`egress_updated`/`egress_ended` → `store.UpdateRecordingStatus`.
  - **Playback**: `GET /v1/recordings/sessions/{id}/playback` returns completed
    recordings for any authenticated user (free-recording floor, `none` tier).
  - **Catalog UI polish**: class cards in a responsive grid, session list with
    live/scheduled/ended status badges, recording count shown inline per session.
- **Playback serving** (PR #33): nginx:alpine on port 9090 serves completed
  recordings from the shared `recordings` named volume.
- **nginx secure_link** (current branch): playback URLs are now HMAC-MD5 signed
  with a 1-hour expiry. `authd` computes `md5("$expires$path $secret")` (base64url)
  and appends `?md5=HASH&expires=UNIX`. nginx validates in-process via its
  `secure_link` module — zero subrequests per range request (critical for video
  scrubbing). Shared secret in `LAPLAT_RECORDINGS_SECRET` / compose env var
  `RECORDINGS_SECRET` (dev value: `devrecordingssecret`).
  - `NGINX_ENVSUBST_TEMPLATE_VARS: RECORDINGS_SECRET` limits envsubst so nginx's
    own `$uri`, `$arg_*`, `$secure_link*` variables survive template processing.
- **Class enrollment** (PR #33): `class_members` table (migration 00015); store
  methods; declared-tier gate; HTTP at `POST/DELETE /v1/classes/{id}/enroll`.
  Catalog shows Enroll/Unenroll buttons.
- **Security hardening** (PRs #34–#35):
  - `buildPlaybackURL` rejects `outputUri` containing `..`
  - `ParseWebhook` enforces JWT `exp`/`nbf` (30s clock-skew) and `iss` == `apiKey`.
- **Moderation dashboard** (`web/src/routes/admin/`) — `platform_moderator` gated:
  - User list from `GET /v1/moderation/users` (new endpoint in `internal/moderation`).
  - Per-row: Suspend/Reinstate, Grant instructor / Revoke instructor.
  - Nav link "Moderation" shown only to moderators.
- **Instructor class management** (`web/src/routes/classes/`) — `can_instruct` gated:
  - Create draft, publish/unpublish/archive transitions.
  - **Session management** (current branch): per-class session list fetched from
    `GET /v1/sessions?classId=X`; "Schedule session" form (kind=class, optional
    `scheduledStart`); Start / Enter room / End session controls per session status.
  - Session statuses: `scheduled` → `live` → `ended`. Start and End buttons POST
    to `?/startSession` and `?/endSession` actions via `use:enhance` (no reload).
  - Nav link "My classes" shown only to instructors.
- Frontend: SvelteKit + adapter-node BFF (tokens in httpOnly cookies,
  server-side load/actions) — chosen to minimise client-side data storage.
- Local stack: Docker Compose (`compose.yaml`) — db → migrate → seed → authd →
  web + **redis + livekit + egress + nginx**. Runs on a Mac via Lima/`nerdctl compose`.

### Decisions worth remembering

- Recording is **host-triggered** (not auto-on-session-start) and writes to a
  **local file behind the pluggable egress client**. Both reversible.
- Migrations use goose *markers* (`-- +goose Up/Down/...`) but the goose
  *binary* was removed; the compose `migrate` step applies Up sections via
  `awk` + `psql`. Don't reintroduce the goose binary.
- Feature branches per PR (e.g. `claude/consent-ledger`), not one long-lived
  branch. Commit-message trailers: `Co-Authored-By` + `Claude-Session`.

## Next tasks (pick one)

1. **Payments / entitlements**. The free-recording floor is live; paid content
   is the next tier. Needs: payment-provider integration (Stripe / VNPay), an
   `entitlements` table, a purchase flow, and an entitlement check in the
   playback endpoint (replacing the free-only stub). The enrollment service
   already has a stub comment for the entitlement gate.

2. **Zalo OIDC**. Wire the Zalo sign-in flow end-to-end once the provider review
   clears. The Go backend already has a `providers["VN"]` slot; the SvelteKit
   proxy routes support any `[provider]` slug.

3. **Learner session UI**. The instructor can now start/end sessions from
   `/classes`. Learners see live sessions in the catalog (`/catalog`) with a
   Join button that POSTs to `POST /v1/sessions/{id}/join` and redirects to
   `/room/{id}`. The room page exists but the catalog doesn't surface join links
   dynamically based on live status — add a polling or SSE refresh so "Live now"
   appears without a manual reload.

4. **Recording playback in the room page**. After a session ends, the instructor
   (and enrolled learners) should be able to play back recordings from the room
   page or the class detail view. `GET /v1/recordings/sessions/{id}/playback`
   is already implemented; just needs a UI surface.

## Verification commands

- `make check` — gofmt + vet + unit tests + security-acceptance threat suite
  (the pre-push gate).
- `go test -tags=integration ./...` — boots an ephemeral Postgres via
  `internal/dbtest` (needs local Postgres server binaries: `initdb`, `pg_ctl`,
  `psql`).
- `make vuln` — `govulncheck` (needs the tool installed).
