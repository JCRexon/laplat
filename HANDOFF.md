# Handoff

A running snapshot of where the project is and what's next, so a fresh session
(or a returning human) can get up to speed without re-reading the whole chat
history. Update the "Current state" and "Next tasks" sections as work lands.

_Last updated: 2026-06-26 — after playback serving, class enrollment, and security hardening (PRs #33–#35)._

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

- Auth: token mint/rotate, OIDC federation (Google/Apple; Zalo in review),
  email/phone OTP (with a dev-console sender), identity tiers + eKYC hook.
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
- **LiveKit media-infra slice** (this PR):
  - `compose.yaml` now runs `redis` + `livekit/livekit-server` + `livekit/egress`
    alongside authd; `LAPLAT_LIVEKIT_*` env vars are wired so live sessions and
    recording work end-to-end with `docker compose up --build`.
  - Dev configs live in `dev/livekit.yaml` and `dev/egress.yaml` (DEV-only keys;
    egress writes to a named Docker volume `recordings`).
  - **Webhook ingest**: `internal/livekit/webhook.go` verifies the LiveKit HS256
    JWT (signing input + body SHA-256 claim); `POST /v1/webhooks/livekit` applies
    `egress_started`/`egress_updated`/`egress_ended` events to the recording row
    via `recording.Service.HandleWebhookEvent` → `store.UpdateRecordingStatus`,
    landing the async `completed`/`failed` status and `output_uri`.
  - **Playback**: `GET /v1/recordings/sessions/{id}/playback` returns completed
    recordings for any authenticated user (free-recording floor, `none` tier).
  - **Catalog UI polish**: class cards in a responsive grid, session list with
    live/scheduled/ended status badges, recording count shown inline per session.
- **Playback serving** (PR #33): nginx:alpine on port 9090 serves completed
  recordings from the shared `recordings` named volume. `authd` builds a
  `playbackUrl` by stripping `LAPLAT_LIVEKIT_FILE_PREFIX` from `outputUri` and
  prepending `LAPLAT_RECORDINGS_BASE_URL`. Catalog shows Watch links.
  DEV ONLY: nginx has no auth; production needs `auth_request` → authd or
  signed/expiring URLs.
- **Class enrollment** (PR #33): `class_members` table (migration 00015); store
  methods `EnrollClass`/`UnenrollClass`/`IsEnrolled`/etc.; service layer with
  declared-tier gate (Decree 147 adult self-attestation); HTTP at
  `POST/DELETE /v1/classes/{id}/enroll` and `GET /v1/classes/enrolled`.
  Catalog shows Enroll/Unenroll buttons (progressive enhancement via `use:enhance`).
- **Security hardening** (PRs #34–#35):
  - `buildPlaybackURL` rejects `outputUri` containing `..`
  - Enroll/unenroll actions validate `classId` non-empty (400 otherwise)
  - `ParseWebhook` now enforces JWT `exp`/`nbf` (30s clock-skew) and verifies
    `iss` == `apiKey`; takes `apiKey` as an explicit parameter.
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

1. **Payments / entitlements** (last priority). The free-recording floor is live;
   paid content is the next tier. Needs: payment-provider integration
   (Stripe / VNPay), an `entitlements` table, a purchase flow, and an
   entitlement check in the playback endpoint (replacing the free-only stub).
   The enrollment service already has a stub comment for the entitlement gate.

2. **Zalo OIDC** (in review). Wire the Zalo sign-in flow end-to-end once
   the provider review clears.

## Verification commands

- `make check` — gofmt + vet + unit tests + security-acceptance threat suite
  (the pre-push gate).
- `go test -tags=integration ./...` — boots an ephemeral Postgres via
  `internal/dbtest` (needs local Postgres server binaries: `initdb`, `pg_ctl`,
  `psql`).
- `make vuln` — `govulncheck` (needs the tool installed).
