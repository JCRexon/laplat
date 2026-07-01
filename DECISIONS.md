# Decision log

A running record of architecture/structure questions raised about this project,
the decisions taken, the **reasoning**, the **trade-offs accepted**, why anything
was **deferred**, and the **conditions that should reopen** each call — so the
choices can be reviewed and learned from later.

**Entry template (an ADR).** Include the fields that carry signal; not all apply
to every entry:
- **Context** — the question / forcing situation.
- **Decision** — what was chosen.
- **Reasoning** — why, including the higher-level judgement.
- **Trade-offs** — what we *knowingly gave up*; the accepted downside.
- **Alternatives** — options weighed and why not chosen (when there were real ones).
- **Deferred / sequencing** — what's pushed out, why now-vs-later, what it's gated on.
- **Assumptions** — things the decision rests on that could later prove false.
- **Revisit when** — the trigger(s) that should reopen the decision.
- **Confidence / review** — how settled it is, and where human *specialist* review
  (crypto / security / legal) is warranted before production.
- **Consequences / Links** — what it causes; issues/PRs.

Newest at the bottom. **Decisions are never rewritten** — supersede with a new
entry. An entry *may* be enriched with trade-offs / revisit-triggers / context
without changing its decision.

**Status legend:** `Accepted` (decided + implemented) · `Proposed` (recommended,
awaiting a call) · `Pending` (decided in principle, not yet built) ·
`Superseded` (replaced by a later entry).

---

## ADR-000 — How we make and record decisions (meta)
**Date:** 2026-06-27 · **Status:** Accepted

**Context.** This is a regulated platform (Decree 147 / PDPL, national-ID eKYC,
tamper-evident audit) being built by a very small team. The number of cross-domain
considerations — auth, applied cryptography, distributed systems, DB design,
infra/DR, compliance, frontend security — exceeds what anyone reliably holds in
their head. How do we make good decisions and not lose the *why*?

**Decision / approach.**
1. **Externalise every non-trivial structural decision** here as an ADR — with
   reasoning, trade-offs, and a "revisit when" trigger. The log, not memory, is the
   source of truth for *why*.
2. **Prefer reversible, seam-based choices.** Put interfaces/adapters at the points
   most likely to change (signing backend, blob store, OTP senders) so a decision
   can be swapped cheaply rather than bet on.
3. **Make "good enough" calls and defer depth — but record the deferral** (what,
   why now-vs-later, what it's gated on), so deferral is a logged choice, not drift.
4. **Buy human specialist review before production where stakes are highest** — in
   particular applied **crypto/security** (token + audit signing, Merkle
   checkpoints, key custody) and **Decree 147 / PDPL legal/privacy**. The reasoning
   here is careful, but accountability and edge-cases warrant a specialist.
5. **AI assists breadth and recall; the human owns judgement and accountability.**
   The AI lowers the cost of considering many angles and can be confidently wrong;
   decisions and their consequences remain the team's.

**Reasoning.** Solo/small-team breadth is only tractable if it's written down and
made reversible. The discipline above is what lets one person *steer* a team's
worth of considerations without holding them all in-head.

**Revisit when.** The team grows (add real review gates / ownership), or a decision
here proves repeatedly wrong (tighten the process).

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

**Trade-offs.** Accept the npm ecosystem's exposure in exchange for a mainstream
framework's velocity and docs; the thin dep list bounds the blast radius.
**Deferred.** Bun — gated on the dev stack settling. **Revisit when.** A
supply-chain incident touches one of our deps, the dep count grows materially, or
the dev stack stabilises (then re-evaluate Bun). **Confidence/review.** High; low
stakes.

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

**Trade-offs.** Coalescing is per-request only; two *separate* requests still
refresh independently — fine, they carry different cookies/tokens.
**Assumptions.** One process holds the request's cookies object (true for the
SvelteKit BFF). **Revisit when.** Moving to multi-instance with a shared session
store, or if refresh-token semantics change. **Confidence/review.** High.

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

**Trade-offs.** The derived rule can't express *partial* completion or
instructor-confirmed completion, and "attended every session" is strict (one
missed session = not complete). Accepted for speed/simplicity. **Deferred.**
Reminders — gated on the background-process infra also needed by ADR-010; build
once that exists. **Revisit when.** Product wants partial/instructor-confirmed
completion, or reminders get prioritised. **Confidence/review.** Medium — product
semantics may evolve.

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

**Trade-offs.** Adds friction (an OTP) to viewing one's own data; reuses OTP, so a
**federated-only** account with no phone/email can't step up. **Assumptions.** The
user has a phone or email factor. **Deferred / gated.** Actual PII display gated on
the crypto layer + eKYC ingestion. **Revisit when.** The crypto layer lands (then
revisit "reveal vs full re-auth"), or federated-only step-up is needed.
**Confidence/review.** Medium; **security review of the grant flow before prod.**

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

**Trade-offs.** Signing becomes a network call (forced ADR-010's checkpoint
design); Vault is a new operational dependency and an **availability coupling**
(audited writes block if Vault is down — see ADR-006); the pre-prod overlay stores
unseal material on a volume (pre-prod only). **Assumptions.** In-country
self-hosting is viable; the team has Vault ops capacity. **Deferred.** Production
auto-unseal (KMS/HSM seal) and least-privilege tokens; HSM/cloud KMS backends (seam
ready). **Revisit when.** A hosting/KMS platform is chosen, or an HSM becomes
available. **Confidence/review.** Design medium-high; **needs a crypto/security
reviewer before prod** (key custody, rotation, unseal).

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

**Trade-offs.** Availability for integrity: a Vault outage blocks audited
mutations (suspend, grant, consent) — a deliberate fail-closed choice.
**Revisit when.** Audited-write latency/availability becomes a real problem (then
consider a separate fast local key for some chains, weighed against custody).
**Confidence/review.** High that integrity is preserved; the availability trade is
a conscious ops choice to confirm with whoever owns uptime.

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

**Trade-offs.** The shared store eases cross-domain transactions (a real benefit)
at the cost of clean extraction boundaries. **Assumptions.** No near-term need to
extract a domain into a separate service. **Revisit when.** A domain needs
independent scaling or extraction → then do the data-ownership split first.
**Confidence/review.** High (it's an assessment, not a build).

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
  volume; prod uses S3-compatible object storage per ADR-012). The "shares the DB
  volume" claim is inaccurate (they are separate volumes). A start-rate/quota limit
  is a separate, backend-independent hardening.
- **MD5 `secure_link`** — **overstated.** Used as a keyed MAC with the secret as a
  *suffix* (not length-extension-vulnerable); the weak `devrecordingssecret` is the
  only dev artifact.
- **BFF CSRF** — **already mitigated**: `SameSite=Lax` cookies + SvelteKit
  `csrf.checkOrigin` (default on). Only `secure:false` is a dev artifact;
  `SameSite=Lax` (not Strict) is deliberate so OAuth redirects work.

**Reasoning.** "In dev" framing matters: don't spend effort hardening compose-only
artifacts or theoretical crypto-aging; fix the two that exist identically in prod.

**Trade-offs.** We deliberately leave the dev-only weaknesses in place in dev
(they vanish in prod) rather than spend effort now. **Revisit when.** An
"out-of-scope" item's context changes — e.g. recordings become *paid*, which
raises the stakes on `secure_link` leakage (→ ADR-011) and on CSRF for purchase
flows. **Confidence/review.** Triage high; an independent **security review before
prod** is still worth it (this triage was AI-led).

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

**Trade-offs.** A terminal recording can't be legitimately re-opened/corrected via
a later webhook (acceptable — terminal is terminal). **Deferred.** `jti` dedupe
(defence-in-depth). **Revisit when.** A real need to amend a terminal recording
arises, or replay defence-in-depth is wanted (add `jti`). **Confidence/review.**
High; shipped with unit + integration tests.

---

## ADR-010 — Presence auditing: Merkle-checkpointed, Vault-signed, hot-path events in the DB
**Date:** 2026-06-27 · **Status:** Accepted · **Links:** issue #45 (item 2), ADR-005, ADR-006, ADR-011

**Context.** Session join/leave — the Decree-147 "presence" signal (proof of who
was in a room and when) — is recorded only operationally in `session_participants`,
not in the tamper-evident log. Adding it raises a design question: a single chain,
sharded chains, or something else? Two forces shape the answer: presence is
**high-volume and on the join hot path**, and the existing chains **sign per append
under a global advisory lock held across that sign** — which is now a **Vault
network round-trip** (ADR-005).

**Decision.** Decouple **ingestion** from **anchoring**:
1. **Hot path writes cheaply to the DB.** `join`/`leave` `INSERT` a row into an
   **append-only `presence_events` table** (UPDATE/DELETE blocked by triggers, the
   same immutability mechanism already used for `audit_log` / `consent_records`),
   carrying a monotonic sequence. **No advisory lock, no per-event signature** — so
   joining stays fast.
2. **A periodic checkpoint anchors them.** A background job (short interval, e.g.
   10–30 s) builds a **Merkle tree** over the presence rows since the last
   checkpoint and appends **one Vault-signed checkpoint entry into the single
   global `audit_log` chain**, committing the Merkle root and the covered sequence
   range (chained to the prior checkpoint).
3. **Tamper-evidence = an inclusion proof** of a presence row against a checkpoint's
   Merkle root, whose root is signed into the global chain.

"Per-session" is a **query index** on `presence_events`, not a separate chain.

**Reasoning.**
- **Conflation rejected (the join-path cost).** Putting presence on the existing
  chain means every join blocks on a global lock held across a Vault RTT, and
  queues rare-but-important admin entries behind high-volume presence. Two harms at
  once (join latency + audit throughput).
- **Sharding-without-an-anchor rejected (the "global value" loss).** A single
  chain's value is three *system-wide* properties: **(a) non-omission** — you can't
  delete a session's events from the one interleaved sequence without breaking the
  hash linkage; **(b) cross-domain provable ordering** — "suspended *after* joined,
  *before* left"; **(c) one witnessable head** to anchor externally. Independent
  per-session chains lose all three: a whole shard (an entire session's presence)
  can be dropped with no trace — defeating the exact forensic question Decree 147
  asks — ordering across domains degrades to forgeable wall-clock, and N heads go
  un-witnessed. **The checkpoint restores all three** by re-anchoring the
  high-volume data into the single signed chain (the Certificate-Transparency
  model: per-log Merkle tree + signed tree head folded into a trusted root).
- **The checkpoint window is covered in layers.** Between an event and the next
  checkpoint a row is in the DB but not yet cryptographically anchored. **Append-only
  triggers** make rows immutable at the SQL layer *immediately* (tampering needs
  superuser/DDL, not ordinary writes); the checkpoint then **upgrades** that to
  portable, externally-verifiable crypto proof seconds later. A checkpoint is **one
  signature regardless of event volume**, so a short interval is cheap. (Optional
  strongest non-omission: hand the joiner a signed join receipt at join time.) The
  window is the price of removing per-event signing, and the triggers pay most of
  it back instantly.

**Considered and rejected.**
- (A) Presence on the existing admin chain — conflation, above.
- (B) A dedicated single presence chain, per-event signed — a single chain still
  needs a serializing lock (contention at join concurrency) and pays the Vault RTT
  per append.
- (C) Per-session sharded chains — lose the global value unless anchored; even
  anchored, more chains to manage than a checkpoint.
- (Windowless alternative, recorded) Per-event signing with a **separate fast
  in-process ed25519 key** (microseconds, not a Vault RTT) gives a zero-lag anchor,
  but still needs a lock (→ contention/sharding) and puts that key in-process
  (weaker custody). Acceptable trade for some, but not chosen: presence is
  high-concurrency and we prefer one anchoring model + Vault-held keys.
- (Out of scope) Deriving access control from the audit trail — see ADR-011; the
  log is evidentiary, not an authorization source.

**Trade-offs.** A bounded un-anchored window (mitigated by triggers); a new
**background process** (first in the codebase — deploy complexity); more
operational moving parts (the checkpoint worker). **Assumptions.** Presence volume
is high/concurrent enough to justify decoupling — if it turns out low, the
windowless per-event-local-key option (recorded above) would be simpler.

**Revisit when.** Measured presence volume is low (consider the simpler windowless
option); or a regulator requires *participant-verifiable* presence (add signed join
receipts); or the checkpoint worker's deploy model needs revisiting.

**Confidence/review.** Design medium-high; **a crypto reviewer should check the
Merkle/checkpoint construction and the window analysis before prod.**

**Consequences / how it lands.**
- New `presence_events` table: append-only (triggers), monotonic seq, columns ~
  `(id, seq, session_id, user_id, action[join|leave], role, occurred_at)`.
- `session.Join`/`Leave` add a single cheap INSERT; no change to their latency
  profile beyond one indexed insert.
- New checkpoint worker — build it idempotent and resumable (records the last
  covered seq). Open sub-decision: goroutine in `authd` vs a separate `cmd/` worker
  (lean: goroutine first; no new deployable).
- Verifier support: given a presence row + its checkpoint, recompute the Merkle path
  to the signed root, then verify that root in the global chain (reuses ADR-006's
  signing/verification).
- Signing via Vault (ADR-005): one sign per checkpoint amortises the RTT.
- Build staged into two PRs: (1) append-only table + hot-path ingestion; (2) the
  checkpoint worker + verifier.

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

**Trade-offs.** `auth_request` puts authd in the authz path of each playback (a
small per-request cost) — chosen over leak-prone bare presigned/bearer URLs.
**Deferred / gated.** Full value pairs with payments/entitlements; the interim
expiry shortening + playback-audit entry can ship independently. **Revisit when.**
Recordings become entitlement-gated (prioritise then). **Confidence/review.**
Design settled; Pending build; security review of the serving authz before prod.

**Update (2026-06-28, ADR-013).** The trigger partially fired: entitlement gating
now exists at the **application layer** (the `playback` handler returns 402 for a
paid class without ownership). This does **not** discharge ADR-011 — the
`secure_link` URL, once issued, is still a leak-prone bearer token. The
identity-bound serving authz (nginx `auth_request`) and the `recording.played`
audit entry remain Pending; prioritise now that paid recordings are reachable.

**Update (2026-06-28) — interim shipped + two findings for the serving authz.**
- **Shipped (interim):** the playback URL's validity window is now configurable
  (`LAPLAT_PLAYBACK_TTL`) and defaulted to **5m** (from a hardcoded 1h) — a 12×
  smaller leak window while the bearer URL remains. Done independently of the
  `auth_request` build.
- **Finding 1 — "identity" is necessarily a scoped token, not the session.** The
  browser fetches recordings from nginx on a **different origin** than the BFF
  that holds the session cookie, so nginx/authd cannot see the user's session.
  The realistic `auth_request` binding is therefore a **per-user, per-recording,
  short-lived signed token** authd validates and re-checks against live
  entitlement — not the literal session. (Routing bytes through the BFF to carry
  the cookie is rejected: it puts the app in the byte path, against ADR-012.)
- **Finding 2 — the `recording.played` audit must hook the serving check, not the
  listing endpoint.** The BFF calls the playback *listing* endpoint from catalog
  and dashboard `load` (on every page render, per session); auditing there would
  put Vault-signed, advisory-locked writes on a page-load hot path — the exact
  anti-pattern ADR-010 removed for presence. So the audit belongs in the
  `auth_request` serving check (fires on real byte access), deduped to once per
  grant, not per range request. It ships **with** the `auth_request` work, not
  before it.

**Update (2026-06-28) — Part 2 shipped; ADR-011 now Accepted (built).** The
identity-bound serving authz is in: nginx `auth_request`s every recording byte
fetch to authd's `GET /v1/recordings/authz`, which verifies a per-viewer,
per-recording HMAC playback token (replacing the `secure_link` md5), confirms the
token is for the requested file, re-checks `EnsureRecordingAccess` **live** (a
mid-window revocation now bites), and writes a `recording.played` audit entry
**deduped once per grant** (so per-range subrequests don't spam the signed chain).
Bytes never transit authd; nginx holds no secret (authd signs the token with
`LAPLAT_RECORDINGS_SECRET`). What this deliberately does NOT change: the token is
still URL-borne, but it is now scoped, short-lived, live-revocable and audited —
possession alone no longer grants durable access.
- **Residual — rate limiting (resolved).** `/v1/recordings/authz` sat behind the
  global per-IP limiter, and nginx is a single source IP, so heavy scrubbing (many
  range requests) could trip it. Fixed: `RateLimiter.LimitExcept` exempts the
  server-to-server paths (`/v1/recordings/authz`, `/v1/webhooks/`) from the per-IP
  limit — they carry their own token/signature auth, so the per-user limit does
  not apply. nginx-side subrequest caching remains a possible optimisation.
- **Verification.** Go side is unit + integration tested; the nginx/compose wiring
  is verified by inspection and needs a live `docker compose` smoke.

---

## ADR-012 — Storage tiers: S3-compatible object store on a separate host; DB for text; no block; file deferred
**Date:** 2026-06-27 · **Status:** Accepted (direction) / Pending (build) · **Links:** issue #45 item 1 context, ADR-005, ADR-011

**Context.** Production storage for recordings (and other binary content). The dev
stack writes recordings to a shared local volume served by nginx — which couples
the storage to the app/serving host and bounds capacity by that host's disk. How
should prod store content, and do we need object / file / block tiers?

**Decision.**
- **Object storage (S3-compatible / S3 API)** is the content tier for **all
  binary blobs** — recordings, images, post attachments, avatars. It lives on a
  **separate physical/virtual host** from the app tier.
- **Physically decoupled, runtime-coupled.** App and storage run on separate
  infrastructure, but the app depends on storage at runtime and reaches it
  synchronously over a **private IP network**. This is deployment/blast-radius
  separation, not eventual-consistency decoupling — so storage-tier HA/DR matters
  to app availability (see DR below).
- **Block storage — not adopted.** No workload here needs a raw block device
  shared across serving hosts.
- **File / POSIX (NFS) — not adopted now.** Forum **post bodies are structured
  data → Postgres** (TEXT + full-text search), not files; what is blob-shaped in a
  forum is **attachments**, which are objects. A file/POSIX tier is justified only
  by a concrete need for shared-mutable-filesystem or partial-in-place-write
  semantics, which nothing currently has. Deferred, not foreclosed: the chosen
  object backends (MinIO / Ceph / SeaweedFS) can expose a file gateway later.

**So the tiering is:** Postgres (structured data, incl. forum text) · Object
storage (all binary blobs) · *(File — only if a real POSIX need appears)*.

**Reasoning.**
- Recordings/images/attachments are immutable media blobs served over HTTP to many
  readers — object storage's exact sweet spot, and it provides replication,
  versioning, Object Lock (WORM), erasure coding, and presigned URLs as built-in
  primitives. NFS-over-IP instead brings distributed-lock/latency pain, weak
  host-based auth, and a SPOF unless clustered (i.e. a worse object store).
- Forum text in the DB keeps it queryable/editable/searchable; treating posts as
  files would discard that for no benefit.
- Decoupling the storage host removes the app-disk-exhaustion failure mode (the
  original concern) and lets the media tier scale independently of app instances.

**Consequences / how it lands.**
- **Write path:** LiveKit egress uploads **directly** to the bucket (it has a
  native S3 sink); the egress request is already a `map[string]any` and
  `EgressInfo.Output()` already carries a remote location, so this is a small,
  localized change. Introduce a `BlobStore` interface in the content/recording
  domain (mirroring the existing `Egress` interface) — a clean seam in the modular
  monolith.
- **Serve path:** a dedicated content origin/vhost in front of the bucket, with
  the app kept out of the byte path; access **identity-gated per ADR-011** (the
  object choice does not by itself solve the leak/authz problem — presigned URLs
  are still bearer tokens).
- **DR:** async bucket/site **replication to a second in-country site**
  (active-passive) + intra-site erasure coding.
- **Retention:** lifecycle rules to expire after the Decree-147 window, with
  **Object Lock** for immutability of the retained legal record.
- **Don't-forget pairings:** recording **start quotas / rate limits** (decoupling
  changes the blast radius from full disk to unbounded cost, not the need to bound
  it); private subnet, TLS, **scoped per-purpose credentials** (egress write-only;
  serving read-only), **encryption at rest** (recordings are PII).

**Trade-offs.** Self-hosting object storage is real operational burden; the
runtime coupling puts storage DR on the app's availability critical path.
**Assumptions.** In-country self-hosting is viable for residency. **Deferred.** The
whole tier's build (Pending); a file/POSIX tier; and the self-host-vs-cloud
sub-decision. **Revisit when.** A concrete POSIX need appears (add a file tier), or
the residency/ops calculus shifts (cloud vs self-host). **Confidence/review.**
Direction settled; **infra/SRE review for DR + capacity and security review for
network/credential isolation before prod.**

**Open sub-decision.** Self-hosted (MinIO / Ceph) vs cloud S3 — a trade between
**data residency + control** (Decree 147/PDPL favours in-country self-host, per
ADR-005's reasoning) and **operational burden**. Not settled here.

---

## ADR-013 — Entitlements: durable ownership gate, built ahead of the payment provider
**Date:** 2026-06-28 · **Status:** Accepted (model + gate) / Pending (payment provider) · **Links:** ACCESS-MODEL.md, ADR-008, ADR-011, PR #52

**Context.** Paid content (paid classes, and later paid recordings) needs an
access gate, but the payment provider (Stripe/VNPay) is blocked on a merchant
account. What can be built now, and how should "owns this" be modelled, given
ACCESS-MODEL's rule that owned content is **entitlement-gated, not tier-gated**?

**Decision.** Build the non-provider half now and leave a one-call seam for the
provider.
1. **A durable `entitlements` table** — one row = an account owns a resource.
   Operational state, not a ledger: mutable (`revoked_at` for refund/chargeback),
   a partial-unique index for one *active* row per `(subject, resource)`, an
   optional `expires_at`. An entitlement is **never** revoked by an identity
   downgrade — you keep what you bought.
2. **`classes.price_cents` marks paid content** (0 = free floor). Free classes
   stay on the tier ladder and need no entitlement, so wiring the gate in changes
   nothing for existing content. The **class is the sellable unit**; a recording
   inherits access from its session's class (a direct/classless session is free).
3. **The gate lives in the service/application layer** (`entitlement.Service`
   `EnsureClassAccess` / `EnsureRecordingAccess`), consulted by class enrollment
   and recording playback as *optional* dependencies (nil = pre-payments
   behaviour). Paid-without-ownership → HTTP 402.
4. **Grants come from a moderator today** (`POST /v1/entitlements`, comp/support)
   so the gate is exercisable end-to-end; on a completed charge a provider will
   call the same `Service.Grant(subject, "class", id, "purchase", cents, …)`.

**Reasoning.** Separating the buildable model from the blocked provider closes a
half-built loop now and de-risks payments to a last-mile integration. Gating on
ownership (a row keyed to an account) rather than tier is what ACCESS-MODEL
requires and is what makes ownership survive a downgrade. Pricing on `classes`
(read via a one-column query) avoids regenerating the sqlc layer for `GetClass`.

**Trade-offs.** (a) The app-layer gate is **not** the leak-proof serving bind —
a `secure_link` playback URL, once issued, is still a bearer token; ADR-011's
identity-bound serving authz is still needed (see its 2026-06-28 update). (b)
Pricing is modelled per-class only — per-recording or subscription pricing is a
later schema change. (c) Entitlements are operational state, so the **payment**
that creates one is what should be audited; an audit entry on grant/revoke is
deferred.

**Alternatives.** A `price`/`is_free` flag with no ownership table (can't express
"who owns what"); putting entitlements on the audit ledger (rejected per ADR-011 —
the log is evidentiary, not an authorization source).

**Revisit when.** The payment provider is wired (build the charge→Grant callback
and audit it); per-recording or subscription pricing is needed; or ADR-011's
serving-layer authz lands (the app-layer gate then becomes defence-in-depth).
**Confidence/review.** High for the model + gate; the money path needs review
when the provider is chosen.
