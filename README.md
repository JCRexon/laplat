# laplat

A Vietnamese live-learning platform: instructors run live classes (video via
LiveKit), learners enrol, attend, and watch recordings. Identity assurance climbs
a ladder — `none → declared → phone_verified → verified` — to satisfy Vietnam's
Decree 147 / PDPL obligations, with a tamper-evident audit and consent trail for
the parts that matter legally.

- **Backend:** Go service `authd` (auth, identity, classes, sessions, recordings,
  moderation, consent, audit) over Postgres.
- **Frontend:** SvelteKit, run as a BFF — tokens live only in httpOnly cookies and
  the server proxies `authd`.
- **Architecture:** a pragmatic modular monolith (one deployable; per-domain
  Service + Handler modules; a shared `pkg/` kernel). See ADR-007.

## Running it

See **[RUNNING.md](RUNNING.md)** for the local dev stack (`docker compose up`) and
the pre-prod overlay with Vault-backed signing.

## Documentation

| Doc | What it covers |
| --- | --- |
| **[DECISIONS.md](DECISIONS.md)** | Architecture decision log — the structural questions raised, the decisions taken, and the **reasoning** behind each (ADR format), for review and future learning. |
| [ACCESS-MODEL.md](ACCESS-MODEL.md) | The identity-assurance ladder and what each tier unlocks. |
| [AUTH-EXTENSIBILITY.md](AUTH-EXTENSIBILITY.md) | Extension seams for new auth/assurance mechanisms. |
| [AUDIT.md](AUDIT.md) | The tamper-evident, hash-chained, signed audit trail. |
| [RUNNING.md](RUNNING.md) | Local dev + pre-prod stacks, environment configuration. |
| [TESTING.md](TESTING.md) | How the test suites (unit + integration) are run. |
| [HANDOFF.md](HANDOFF.md) | Current state and in-flight / next work. |

Start with **DECISIONS.md** if you want the *why* behind how the project is
shaped; it links out to the deeper design docs above.

---
Copyright (c) 2026 James Miles. All Rights Reserved.
