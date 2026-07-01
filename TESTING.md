# Testing conventions

How we test during code production. Engineering process (not product design), so
it lives in-repo. Every target here is a `make` command — see the `Makefile`.

## Tiers

### 1. Unit — `make test`
Pure logic, no I/O. `*_test.go` beside the code; use a black-box (`_test`)
package when testing only the public contract. Depend on interfaces and supply
in-memory fakes (e.g. `RevocationStore`). Table-driven past ~2 cases. Runs
anywhere, on every change.

### 2. Integration — `make test-integration`
Real infrastructure, gated by the `//go:build integration` tag. `internal/dbtest`
boots a throwaway local Postgres (`initdb` → `pg_ctl` → apply the goose
migrations → unix socket → teardown via `t.Cleanup`). This is the **only** way to
prove the things Go cannot: that migrations apply, that SQL queries are correct,
and that **triggers and CHECK constraints fire** (the adult-activation gate and
the direct-session participant cap). Skipped automatically when no Postgres is
present.

### 3. Regression — a discipline, not a test type
Durable suites that must never be deleted:

- **Security-acceptance** — `make test-security`. One test per **Critical**
  threat ID, named `TestThreat_<ID>_<desc>` so the whole gate is `go test -run
  '^TestThreat_'`. This is the regression gate for security properties and is
  exactly what the definition-of-done requires. Current coverage:

  | Threat | Test(s) | Where |
  |---|---|---|
  | A-1 (JWT forgery / alg confusion) | `TestThreat_A1_RejectsAlgNone`, `_RejectsHMACConfusion`, `_RejectsTamperedPayload`, `_RejectsUnknownKeyID`, `_RejectsWrongKey` | `pkg/token` |
  | A-2 (consent-ledger integrity) | `TestThreat_A2_ConsentSignatureCoversGranted`, `_ConsentEncodingNoFieldInjection` | `pkg/contracts` |
  | A-3 (grant over-scoping) | `TestThreat_A3_GrantLeastPrivilege` | `pkg/contracts` |
  | A-5 (token replay / revocation) | `TestThreat_A5_RejectsExpired`, `_RejectsDenylistedJTI`, `_RejectsSupersededTokenVersion` (`pkg/token`); `_RefreshReuseRevokesFamily` *(integration, `internal/store`)* | `pkg/token`, `internal/store` |
  | B-1/B-2 (subject injection) | `TestThreat_B2_SubjectTokenRejectsInjection` | `pkg/validate` |
  | C-4 (direct-session DoS) | `TestThreat_C4_DirectSessionParticipantCap`, `_DirectSessionCapIsConcurrencySafe` *(integration)* | `internal/dbtest` |

- **Contract-golden** — `TestGolden_*` in `pkg/contracts` snapshot the wire shape
  of the frozen contracts (JWT claim keys, canonical consent encoding, NATS
  subjects). A golden changes only as a deliberate, reviewed contract change.
- **Bug-fix rule** — every fixed bug gets a red→green test first, referencing the
  cause.

## Malicious-input testing
Input validators (`pkg/validate`) are unit-tested for both accept and reject
cases, plus **Go native fuzzing** (`make fuzz`) for parsers/validators that face
untrusted input — e.g. `FuzzSubjectToken` asserts no accepted value can carry a
NATS subject metacharacter. Add a fuzz target whenever a new parser/validator
touches untrusted bytes (e.g. signalling/SDP parsing — C-7 — when it lands).

## Manual smoke tests
Some paths need infrastructure that can't run in a plain dev container. The
recording capture path is the main one: real egress needs LiveKit + headless
Chrome compositing a live participant's media. The *control plane* around it
(webhook ingest, signature verification, the recording state machine) is still
verifiable without any of that:

- `scripts/egress-smoke.sh` forges a correctly-signed LiveKit webhook (and a
  deliberately bad one) and fires the egress lifecycle at a running authd:
  - default: asserts a valid webhook is accepted (200) and a forged one rejected
    (401) — ingest + signature gate, no DB needed;
  - `--with-db`: seeds a session + recording row and drives it
    `starting → active → completed` via the webhooks, reading the row back.

- `scripts/playback-authz-smoke.sh` exercises the recording playback
  serving-authz (ADR-011): it forges playback tokens the way authd mints them
  (HMAC over `<subject>|<recordingID>|<exp>`, keyed by `LAPLAT_RECORDINGS_SECRET`)
  and asserts authd's `GET /v1/recordings/authz` decisions:
  - default: token-rejection ladder (missing/tampered/expired/wrong-key → 401;
    valid-but-unknown-recording → 403), no DB needed;
  - `--with-db`: seeds a completed recording and checks the allow path
    (valid token + correct file → 204; wrong file → 403), plus the nginx wiring
    (a tokenless fetch through nginx is rejected by `auth_request` → 401).

  To exercise the *real* media pipeline (occasional, local-only — too
  resource-heavy for CI), publish a synthetic track headlessly with the LiveKit
  CLI (`lk room join --publish-demo <room>`), then start a room-composite egress.

## Quality gate
`make check` = `lint` (gofmt + `go vet`) + `test` + `test-security`. Run before
pushing. `make cover` reports coverage (tracked, not enforced); the
security-acceptance suite is the hard gate, not a coverage number. `make vuln`
runs `govulncheck` (E-2).

## CI
GitHub Actions (`.github/workflows/ci.yml`) runs on pushes to `master`/`claude/**`
and on every PR: module hygiene (`go mod verify` + tidy-drift check), `make check`
(gofmt + vet + unit + security-acceptance), `make test-integration` (boots an
ephemeral Postgres from the apt-installed server binaries), and `make vuln`
(`govulncheck`, E-2) on the pinned `go1.25.11` toolchain.
