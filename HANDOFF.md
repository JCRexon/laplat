# Handoff

A running snapshot of where the project is and what's next, so a fresh session
(or a returning human) can get up to speed without re-reading the whole chat
history. Update the "Current state" and "Next tasks" sections as work lands.

_Last updated: 2026-07-02 — after the learner UI polish pass: live-status polling, inline recording playback, and the wide-layout redesign (branch `claude/onboarding-docs-review-2bl1c7`)._

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
- **Presence auditing** (`internal/presence`, ADR-010): append-only
  `presence_events` on the join/leave hot path (stage 1), folded into the global
  audit chain by a periodic Vault-signed **Merkle checkpoint** worker with an
  inclusion-proof verifier (stage 2). `LAPLAT_PRESENCE_CHECKPOINT_INTERVAL`
  (default 30s).
- **Entitlements** (`internal/entitlement`, migration 00020, PR #52): durable
  per-account ownership gate for paid content. `classes.price_cents` marks paid
  classes (0 = free floor); enrollment and recording playback consult the gate
  (free unchanged; paid without ownership → 402). Moderator grant/revoke via
  `POST/DELETE /v1/entitlements`, `GET /v1/entitlements/me`. Durable across a
  tier downgrade. Grant/revoke are **audited atomically** (`entitlement.granted`
  / `entitlement.revoked`, ADR-013, PR #61). The purchase/charge step still needs
  a provider (Blocked #1).
- **Recording playback authz** (`internal/recording`, ADR-011, PRs #56/#57):
  playback is identity-bound, not a bearer link. The playback URL carries a
  per-viewer, per-recording short-lived HMAC token; nginx `auth_request`s every
  byte fetch to `GET /v1/recordings/authz`, which verifies the token, re-checks
  entitlement live, and audits the access (`recording.played`, deduped per
  grant). `LAPLAT_PLAYBACK_TTL` (default 5m). Smoke: `scripts/playback-authz-smoke.sh`.
- **Recording start quotas** (`internal/recording`, ADR-008/012, PRs #60/#62):
  a global concurrent-recording cap (`LAPLAT_RECORDING_MAX_CONCURRENT`, 0 =
  unlimited → 503) and a per-host start rate limit (`LAPLAT_RECORDING_START_RPS`
  / `_BURST`, 0 = disabled → 429) bound egress load and abuse.
- **Rate-limit exemption** (`internal/httpx`, PR #59): the server-to-server
  endpoints (`/v1/recordings/authz`, `/v1/webhooks/`) skip the per-IP limiter —
  they share one source IP (nginx/LiveKit) and carry their own auth.
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
- **nginx secure_link** (PR #37) — **superseded by the ADR-011 auth_request
  playback authz above** (#57). The static HMAC-MD5 `secure_link` bearer URL was
  replaced by nginx `auth_request` to authd; nginx no longer holds a secret
  (`LAPLAT_RECORDINGS_SECRET` is now the token-signing key on authd only).
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
- **Learner session + playback UI** (current branch): the catalog session list
  shows the owning class's title per row, sorts live sessions first, highlights
  the live row, and shows a Join button; catalog and dashboard **poll-refresh**
  (`web/src/lib/poll.ts` — `invalidateAll()` every 20s while the tab is visible,
  and on tab-refocus), so "Live now" appears without a manual reload and the
  short-TTL playback URLs stay fresh. Recordings play in an **inline expandable
  video player** (`web/src/lib/components/RecordingPlayback.svelte`, shared by
  catalog + dashboard) instead of opening the raw file in a new tab; the player
  snapshots its URL at click time so a poll tick doesn't restart playback.
- **Wide layout** (current branch): the content column is now 1400px max with
  responsive padding (was 720px), so the catalog class grid and the dashboard /
  instructor course cards flow left-to-right across the page. Document-like
  pages (onboarding, account, my-data, certificate) keep a readable 720px
  measure via a `page-narrow` utility.
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

## Next tasks

Split by whether they can be built **now** (self-contained, no third party) or
are **blocked** on an external provider/credential/approval. Prefer the
unblocked list — these close loops on features already half-built.

### Unblocked — buildable now (no external dependency)

1. ~~**Learner session UI**.~~ **Done** (current branch): the catalog surfaces
   live sessions with the owning class's title, live-first ordering, and a Join
   button; catalog and dashboard poll-refresh (20s, visibility-aware) so "Live
   now" appears without a manual reload. The create→join session loop is closed.

2. ~~**Recording playback surface**.~~ **Done** (current branch): completed
   recordings play in an inline expandable player on the catalog and dashboard
   (shared `RecordingPlayback.svelte`), fed by the identity-bound signed URLs
   from `GET /v1/recordings/sessions/{id}/playback` (ADR-011). Poll-refresh
   keeps the 5-minute-TTL URLs fresh while a page stays open.

3. ~~**Entitlements scaffolding** (the non-provider half of payments).~~ **Done**
   ([`internal/entitlement`](internal/entitlement), migration 00020): durable
   per-account `entitlements` table; `classes.price_cents` marks paid content; the
   gate is wired into class enrollment and recording playback (free content
   unchanged); a moderator can grant/revoke today via `POST/DELETE
   /v1/entitlements` and read their library at `GET /v1/entitlements/me`. Only the
   purchase/charge step remains (Blocked #1) — it calls `entitlement.Service.Grant`.

### Blocked — needs an external provider, credential, or approval

1. **Payments**. The purchase/charge flow needs a Stripe or VNPay merchant
   account + API credentials. The entitlements model + gate are now built
   (Unblocked #3, done), so this is purely the last mile: on a completed charge,
   call `entitlement.Service.Grant(subject, "class", classID, "purchase", cents, …)`.

2. **Zalo OIDC**. Waiting on Zalo's provider/app review. The Go backend already
   has a `providers["VN"]` slot and the SvelteKit proxy routes accept any
   `[provider]` slug — just needs approved client credentials.

3. **eKYC `verified` tier**. The hook is in (`internal/ekyc`, `providers["VN"]`);
   needs the VN vendor's URL/token and a real contract to switch on.

4. **Production wiring of dev stubs**. Real Google/Apple OIDC client secrets,
   SMTP/SMS providers (OTP is dev-console today), S3/GCS-backed egress instead of
   the local-file client, and real secrets replacing the `dev*` defaults
   (`LAPLAT_TOKEN_SIGNING_KEY`, `LAPLAT_RECORDINGS_SECRET`, LiveKit keys).

## Verification commands

- `make check` — gofmt + vet + unit tests + security-acceptance threat suite
  (the pre-push gate).
- `go test -tags=integration ./...` — boots an ephemeral Postgres via
  `internal/dbtest` (needs local Postgres server binaries: `initdb`, `pg_ctl`,
  `psql`).
- `make vuln` — `govulncheck` (needs the tool installed).
