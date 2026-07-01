# Audit — the tamper-evident action trail

The third leg of the trio: **authentication** proves who you are, **assurance**
proves how well your identity is established, and **audit** proves *what was done
to whom, by whom, and when* — durably and without after-the-fact alteration.

For a platform handling national-ID eKYC under Decree 147 / PDPL, audit is not
optional: a regulator asks "show me who verified, moderated, or downgraded this
person's identity, and prove the record wasn't edited." Current-state columns
(`users.status`, `identity_vault.verification_status`, `users.can_instruct`)
answer *what is true now*; they cannot answer *what happened*. The audit log
fills that gap.

## Design

An append-only, hash-chained, server-signed `audit_log`. The discipline is
lifted straight from the consent-ledger spec already in the codebase
(`pkg/contracts/consent.go`) and generalised: insert-only, every field
length-prefixed into canonical signed bytes, each entry chained to its
predecessor, immutability enforced in the database.

### The entry

Each privileged action writes one row:

| Field | Meaning |
| --- | --- |
| `seq` | total order (bigserial) — the chain's spine |
| `occurred_at` | server timestamp |
| `actor_id` | the authenticated subject who acted (`null` for system actions) |
| `actor_role` | the authority exercised: `platform_moderator`, `self`, `system` |
| `action` | e.g. `user.suspended`, `instructor.granted` |
| `target_type` / `target_id` | what was acted on (`user`, `session`, …) |
| `metadata` | action-specific JSON (e.g. reason, prior value) |
| `prev_hash` | hash of the previous entry — the chain link |
| `entry_hash` | `SHA-256` over this entry's canonical `SignedPayload` (which includes `prev_hash`) |
| `signing_key_id` / `signature` | ed25519 signature over `entry_hash`, key id for rotation-safe verify |

### Three guarantees

1. **Append-only at the source.** Every privileged mutation writes its audit row
   **in the same transaction** as the state change — so there is no committed
   action without its trail, and no trail for an action that rolled back.
2. **Immutable at rest.** A trigger blocks `UPDATE` and `DELETE` on `audit_log`
   (the same trigger-as-defence-in-depth pattern as the adult-activation and
   participant-cap constraints). Even a privileged DB user editing history trips
   the trigger; tampering by row replacement breaks the hash chain.
3. **Tamper-evident.** `entry_hash` chains each row to the last and is ed25519
   signed. `VerifyAuditChain` walks the log and fails on any broken link,
   recomputed-hash mismatch, or bad signature — so silent edits are detectable
   even by someone who could bypass the trigger.

### Concurrency

The chain needs a total order, so an append takes a transaction-scoped advisory
lock before reading the tail hash and inserting. Privileged actions
(moderation, identity changes) are low-volume, so serialising them is free. The
one high-volume stream — session join/leave **presence** — deliberately does
**not** take this lock per event: it writes to an append-only `presence_events`
table and is folded into this chain periodically as a single Vault-signed Merkle
checkpoint (ADR-010), so the global lock and the per-append signature are paid
once per checkpoint, not once per join.

## The seam

`AuditEntry` and its canonical encoding live in `pkg/contracts`; the signer and
the chained insert live in the store. A service records by handing the store an
`AuditInput` (actor, action, target, optional metadata) — the store assembles the
chain, signs, and inserts atomically with the mutation. Adding an audited action
is a new `AuditAction` constant plus passing an `AuditInput` to the audited store
method — no new infrastructure. Same Lego shape as the assurance signals (see
AUTH-EXTENSIBILITY.md).

```go
// 1. name the action (pkg/contracts/audit.go)
const ActionUserSuspended AuditAction = "user.suspended"

// 2. the store method records it in-transaction with the mutation
store.SuspendUserAudited(ctx, store.AuditInput{
    ActorID: claims.Subject, ActorRole: contracts.AuditRoleModerator,
    Action: contracts.ActionUserSuspended, TargetType: "user", TargetID: targetID,
})
```

## Coverage

| Action | Audited | Notes |
| --- | --- | --- |
| `moderation.Suspend` | ✅ | `user.suspended` (+ session revocation, same tx) |
| `moderation.Reinstate` | ✅ | `user.reinstated` |
| `moderation.SetInstructor` | ✅ | `instructor.granted` / `instructor.revoked` |
| `auth.BecomeInstructor` | ✅ | `instructor.self_granted` (actor = self) |
| session join / leave (presence) | ✅ | `presence.checkpoint` — a periodic Merkle checkpoint anchors `presence_events` into this chain (ADR-010), not one entry per join |
| recording playback access | ✅ | `recording.played` — written at the serving-authz check, deduped once per grant (ADR-011) |
| admin eKYC bootstrap (`adminctl`) | ⛔ planned | operator CLI, not a runtime request |
| eKYC verify / tier transition (runtime) | ⛔ planned | rides with the eKYC provider work |

## Status

- **Built:** the `audit_log` (immutable, hash-chained, signed) + `VerifyAuditChain`,
  wired into all live moderation actions and instructor self-apply; **presence
  auditing** — append-only `presence_events` folded into the chain via periodic
  Vault-signed Merkle checkpoints, with an inclusion-proof verifier (ADR-010).
- **Planned:** runtime eKYC/tier-transition audit (with the eKYC provider).
