# Decision log

A running record of architecture/structure questions raised about this project,
the decisions taken, and — most importantly — the **reasoning**, so the choices
can be reviewed and learned from later.

Format: each entry is a lightweight ADR — Context (the question), Decision,
Reasoning, Consequences, and links. Newest at the bottom; never edit a past
entry's decision — supersede it with a new one.

**Status legend:** `Accepted` (decided + implemented) · `Proposed` (recommended,
awaiting a call) · `Pending` (decided in principle, not yet built) ·
`Superseded` (replaced by a later entry).

---

## ADR-001 — Frontend uses npm; deliberate supply-chain stance
**Date:** 2026-06 · **Status:** Accepted

**Context.** Is npm a supply-chain liability for this project? Where is it even used?

**Decision.** Keep npm, scoped to the `web/` SvelteKit frontend only (the Go
backend has none). Keep the dependency surface minimal; use `npm ci` + committed
lockfile and review dependency bumps deliberately. Consider Bun later for a
smaller trust surface; not now.

**Reasoning.** The risk is real but the surface here is as thin as SvelteKit
gets (framework + adapter + Vite + Playwright; no UI kit, no utility belt). `npm
ci` enforces the lockfile exactly; that plus review is the right cost/benefit at
this stage. A runtime swap (Bun) is a bigger change to make only when the dev
stack stabilises.

---

## ADR-002 — Coalesce concurrent token refresh (single-flight)
**Date:** 2026-06 · **Status:** Accepted

**Context.** Parallel `api()` calls in a load that all hit 401 each tried to
refresh; the refresh token is single-use and rotates on first use, so the
others failed and logged the user out.

**Decision.** Single-flight the refresh via a `WeakMap<Cookies, Promise>` keyed
by the per-request cookies object; concurrent callers in one request share one
refresh; entries drop on settle.

**Reasoning.** A module-global map would cross-contaminate requests; sequential
warm-up is fragile. Keying by the request's `cookies` isolates requests while
coalescing within one, spending the rotating token exactly once. No manual
cleanup (WeakMap + `finally`).

---

## ADR-003 — Class completion is derived, not stored; reminders deferred
**Date:** 2026-06-27 · **Status:** Accepted (completion) / Pending (reminders)

**Context.** Group 3 "completion + certificates." What counts as completing a
session, and do we build session reminders now?

**Decision.** A class is complete when **all its sessions have ended and the
learner attended every one** — computed from `sessions.status` +
`session_participants`, with **no new table** and no instructor action.
**Reminders deferred** (they need a background scheduler — new infra).

**Reasoning.** The derivable rule ships fastest, needs no schema, and avoids a
product decision about instructor-driven completion. Reminders are the heaviest
Group 3 item (a long-running process); not worth coupling to the completion work.

**Consequences.** Certificates (`/certificate/[classId]`) render only for a fully
completed class. Instructor-confirmed completion can be layered later if needed.

---

## ADR-004 — Sensitive data export sits behind step-up re-auth
**Date:** 2026-06-27 · **Status:** Accepted

**Context.** The consolidated "My data" (PDPL right-of-access) page aggregates
everything held on a user. Should viewing it require more than an active session?

**Decision.** Gate it behind **step-up re-authentication**: a fresh OTP to the
user's registered phone (preferred) or email mints a short-lived (5 min) grant
(hash stored, raw token in an httpOnly cookie) that the export endpoint requires.

**Reasoning.** A consolidated export is more sensitive than the same facts
scattered across pages, so it warrants a fresh identity check even when signed in.
OTP re-verification is the natural step-up for a passwordless platform (reuses the
existing OTP challenge tables + senders); the grant is hashed like refresh tokens.

**Finding (important).** While building this we confirmed there is **no
encryption/decryption layer** — the `*_enc` vault columns (name, DOB, email) are
never written and can't be read. So the export shows them as "on file / not yet
collected," never decrypted. Real PII display depends on the eKYC ingestion +
crypto work landing first.

---

## ADR-005 — Signing key behind a seam; self-hosted Vault, not cloud
**Date:** 2026-06-27 · **Status:** Accepted

**Context.** The Ed25519 token+audit signing key is a plaintext env var
(`LAPLAT_TOKEN_SIGNING_KEY`) — fine for dev, wrong for production. The codebase
comments say "use KMS/HSM." Does that force a cloud dependency? Can it be
off-cloud (VPS)?

**Decision.** Introduce a backend-agnostic `signing.KeySigner` seam (stdlib-only,
so `pkg/token` stays dependency-free). Default = in-process env key. Add a
**self-hosted HashiCorp Vault Transit** backend (`internal/vaultsign`) where the
key never enters the process; `authd` fetches its own public key from Vault at
startup. Ship a persistent-Vault **pre-prod compose overlay**. A hardware HSM
isn't guaranteed on a VPS, so Vault (software, self-hostable) is the target.

**Reasoning.** "KMS" was shorthand for "hold the key and sign elsewhere," not
"cloud." Vault Transit runs on your own infra; data-residency (Decree 147/PDPL)
also favours in-country/self-hosted. The seam means the eventual backend
(Vault now, HSM/cloud KMS later) is a one-file swap. Self-fetching the public key
removes the brittle, format-fragile manual pubkey-publishing step.

**Consequences.** `audit.Signer.Sign` now returns an error (a remote signer can
fail), which aborts the enclosing transaction — see ADR-006. Per-event signing is
now a network call — see ADR-010.

---

## ADR-006 — Audit integrity is preserved (and strengthened) by the signing seam
**Date:** 2026-06-27 · **Status:** Accepted

**Context.** Does delegating signing (ADR-005) weaken the tamper-evident audit /
consent ledgers?

**Decision/Finding.** No regression. Same canonical payload, same Ed25519, same
`VerifyChain`, same `kid`. The new failure mode (signing can error) aborts the
whole transaction, so an audited action can never commit without a valid signed
entry — **fail-closed**, slightly stronger than before. Key custody improves
under Vault (key never in process). Trade-off: if Vault is unreachable, audited
mutations block (correct for a tamper-evident log). Asserted by a test that
verifies a Vault-signed audit entry in `VerifyChain`.

**Reasoning.** Tamper-evidence is a property of the payload + algorithm +
verifier, none of which changed; only *where* the bytes get signed moved.

---

## ADR-007 — Keep the pragmatic modular monolith; reject two of Gemini's critiques
**Date:** 2026-06-27 · **Status:** Accepted

**Context.** Is this a modular monolith? An external review (Gemini) argued it
isn't, citing (1) a shared `internal/store`, (2) `pkg/contracts` as an anti-
pattern, (3) domain logic in `cmd/`, (4) global migrations.

**Decision.** It **is** a pragmatic modular monolith — single deployable, strong
interface-driven module boundaries (Service + Handler per domain), a composition
root in `cmd/authd/main.go`, a shared kernel in `pkg/`, low inter-domain coupling
(only `auth` is a hub). Keep this shape. Accept critiques **#1 and #4**; **reject
#2 and #3** as Go-specific misreads.

**Reasoning.**
- **#1 shared store — valid deviation,** but it's what lets an audited mutation
  write the action + its signed audit append in **one transaction**; per-domain
  stores would fragment those. Conscious trade-off.
- **#2 `pkg/contracts` — reject.** Verified: it contains **zero interfaces** —
  it's structs + consts + canonical `SignedPayload()` byte layouts that *must* be
  shared (token/audit/consent verifiers need identical bytes). Interfaces are
  already defined at consumers (`SessionRepo`, `ProfileReader`, `AuditSigner`…).
  Deleting it would break cross-cutting crypto guarantees.
- **#3 logic in `cmd/` — reject.** `ekyc.go`/`oidc.go`/`sms.go` are adapters/
  factories (`ekycBridge`, `buildFederation`, `buildSMSSender`) — composition-root
  wiring, exactly what `cmd/` is for. Domain logic lives in `internal/*`.
- **#4 global migrations — valid, but a consequence of #1:** cross-domain FKs
  (`session_participants → users + sessions`) mean the schema isn't cleanly
  separable until data ownership is split.

**Future direction.** If moving toward *strict* modularity (e.g. to extract a
domain), split **data ownership first** (#1 → #4 follow); leave `pkg/contracts`
and `cmd/` wiring alone.

---

## ADR-008 — Security review: dev-vs-prod triage of 5 findings
**Date:** 2026-06-27 · **Status:** Accepted (triage) — see ADR-009/010 for fixes

**Context.** An external review listed 5 issues. Which are genuine prod gaps vs
dev artifacts?

**Decision/Findings.**
- **Webhook replay + non-monotonic recording state** — **real, env-independent.**
  Fixed (ADR-009).
- **Un-audited session presence** — **real, env-independent.** Pending (ADR-010 /
  issue #45 item 2).
- **Local-disk recordings / storage DoS** — mostly **dev artifact** (compose
  volume; prod uses S3/GCS). The "shares the DB volume" claim is inaccurate (they
  are separate volumes). A start-rate/quota limit is a separate, backend-independent
  hardening.
- **MD5 `secure_link`** — **overstated.** Used as a keyed MAC with the secret as a
  *suffix* (not length-extension-vulnerable); the weak `devrecordingssecret` is the
  only dev artifact.
- **BFF CSRF** — **already mitigated**: `SameSite=Lax` cookies + SvelteKit
  `csrf.checkOrigin` (default on). Only `secure:false` is a dev artifact;
  `SameSite=Lax` (not Strict) is deliberate so OAuth redirects work.

**Reasoning.** "In dev" framing matters: don't spend effort hardening compose-only
artifacts or theoretical crypto-aging; fix the two that exist identically in prod.

---

## ADR-009 — Recording status is monotonic (webhook replay defence)
**Date:** 2026-06-27 · **Status:** Accepted · **Links:** issue #45 (item 1), PR #47

**Context.** LiveKit egress webhooks are verified (iss/exp/nbf/body-hash) but not
`jti`-deduped, and `UpdateRecordingStatus` blindly set status — so a replayed/out-
of-order earlier event could regress a finished recording to a live state.

**Decision.** Make recording status **monotonic**: the SQL `UPDATE` skips rows
already in `completed`/`failed`/`aborted` (race-safe single predicate); the
service also early-returns on an already-terminal recording.

**Reasoning.** A terminal-state guard fixes **both** malicious replay *and*
legitimate out-of-order delivery at the data layer, in one cheap change. Cheaper
and more complete than a `jti` cache (which stops only replay and adds state);
`jti` dedupe remains optional defence-in-depth.

---

## ADR-010 — Presence auditing: decouple ingest from anchoring (Merkle checkpoints)
**Date:** 2026-06-27 · **Status:** Proposed · **Links:** issue #45 (item 2)

**Context.** Session join/leave (the Decree-147 "presence" signal) isn't in the
tamper-evident log. How to add it: a single chain, or sharded chains? The
existing chains use a global advisory lock and sign per append — and signing is
now a **Vault network call** (ADR-005), held across the lock.

**Decision (proposed).** Don't put presence on a per-event synchronously-signed
chain. **Decouple ingestion from anchoring:** `join`/`leave` cheaply `INSERT` a
presence row (no lock, no per-event signature); a periodic job builds a Merkle
root over new rows and appends **one** signed checkpoint to the existing
`audit_log`. Tamper-evidence = an inclusion proof against a signed root. If a
smaller first step is wanted: a dedicated presence chain (like `consent_records`)
with a checkpoint-ready schema.

**Reasoning.** Presence is high-volume and on the join hot path. Per-event signing
under a shared lock — now a Vault RTT per append — is a hard throughput ceiling
and adds join latency. Checkpointing amortises signing (one Vault call per
interval), keeps a single global anchor (no whole-shard-deletion gap), and makes
"per-session" just a query index rather than many chains to manage. The cost is a
short un-anchored window (mitigated by a short checkpoint interval) — the standard
transparency-log trade-off.

**Rejected.** (a) Reusing the admin chain — couples low-volume admin with high-
volume presence. (b) Per-event signing for presence given the Vault call. (c)
Deriving access control from the audit trail — see ADR-011.

---

## ADR-011 — Recording playback binds to identity, not the audit trail
**Date:** 2026-06-27 · **Status:** Pending · **Links:** issue #46

**Context.** Playback `secure_link` URLs are bearer tokens (possession = access,
1h window), leak-prone. Could we bind access using the audit trail / user
activity?

**Decision.** Bind playback to the **authenticated identity** (session +
entitlement), e.g. via an nginx `auth_request` subrequest to authd — **not** to
the audit trail. Separately, **audit** playback access (a `recording.played`
entry). Interim: shorten the URL expiry and make it configurable.

**Reasoning.** The audit log is **evidentiary, not an authorization source** —
gating on it is circular (you'd audit the authz read of the audit), it lags
current state, and behavioural binding causes false lockouts. Authorization binds
to a stable, unforgeable identity (the session); the audit log *records* the
access. Value rises once recordings are entitlement-gated, so this pairs with the
payments/entitlements work; the expiry shortening + playback-audit entry are worth
doing independently.
