# Auth extensibility — the Lego-brick pattern

How to add a new authentication or identity-assurance requirement without
rewiring the auth core. The goal: a new *kind* of mechanism is "write one brick,
register it" — no edits to the assembly, the mint hot path, or schema enums.

The discipline that makes this work is one separation:

> **Authentication** (proving you control an account) is a different axis from
> **assurance** (how strongly your identity is established).

A mechanism can land on either axis — and some, like biometrics, can land on
*both*. Conflating them is what forces edits to spread. Keep them apart and each
becomes an independent registry.

## The two axes

| Axis | Question it answers | Examples | Extension seam |
| --- | --- | --- | --- |
| **Authentication** | "Do you control this account?" | email/phone OTP, Google/Apple/Zalo federation, WebAuthn passkey, FaceID unlock | `AuthMethod` registry |
| **Assurance** | "How well is your identity proven?" | self-attestation, phone verification, eKYC, biometric liveness/match | `Signal` + policy + `SignalSource` registry |

## Where the welds were

Before this pattern, three assembly points fought new *kinds* (vs. mere variants
of an existing kind, which the `Connector` port already handled cleanly):

1. **`allowedProviders` map (`internal/auth/federation.go`) + a DB `CHECK`
   constraint** on `federated_identities.provider`. A new provider meant editing
   the map **and** a migration to widen the `CHECK` — coupled edits across code
   and schema (`migrations/00010_zalo_provider.sql` is exactly that).
2. **`identityState()` — a fixed if/else ladder** (`internal/auth/service.go`)
   reading two hand-threaded booleans plus a closed
   `verification_status IN ('none','pending','verified')` enum. A new assurance
   signal meant a new repo read, a new `mint()` parameter, a new branch here, and
   a migration to widen the enum.
3. **Login methods weren't unified** — `Federation`, `PhoneLogin`, `EmailLogin`
   are three bespoke services with their own routes and no shared abstraction.

## The three bricks

### Brick 1 — `AuthMethod` registry (authentication axis) — *planned*

A uniform interface every login mechanism implements, registered by name and
served by generic routes (`/v1/auth/{method}/begin|complete`):

```go
type AuthMethod interface {
    Name() string
    Begin(ctx, BeginRequest) (BeginResponse, error)    // send OTP / build redirect / WebAuthn challenge
    Complete(ctx, CompleteRequest) (Principal, error)  // verify → proven external identity
}
```

`Principal{Kind, Subject}` is the proven external identity — `(google, sub)`,
`(phone, e164)`, `(passkey, credID)` — which the existing user-resolution +
`IssueSession` path consumes unchanged. The three current flows collapse into
implementations; a new login factor is one impl + one registry entry, no new
routes.

### Brick 2 — assurance as data, not branches (assurance axis) — *implemented*

The tier is no longer computed by a hand-written cascade. Three pieces, in
`internal/auth/assurance.go`:

- **`Signal`** — a discrete verified fact, an **open** set:
  `adult_attested`, `phone_verified`, `ekyc_verified`, `ekyc_pending`, and any
  future `biometric_liveness`, …
- **`SignalSet`** — the signals a user currently holds.
- **The policy** — an ordered `[]tierRule` mapping *required signals → tier*,
  evaluated highest-tier-first. This is **data**: a new tier or a new signal
  contribution is a row, not a branch.

```go
var defaultAssurancePolicy = assurancePolicy{
    {contracts.IdentityVerified,      []Signal{SignalEKYCVerified}},
    {contracts.IdentityPhoneVerified, []Signal{SignalPhoneVerified, SignalAdultAttested}},
    {contracts.IdentityDeclared,      []Signal{SignalAdultAttested}},
    {contracts.IdentityPending,       []Signal{SignalEKYCPending}},
}
```

Signals are gathered from sources. The built-in signals derive from data `mint()`
already holds (zero extra reads), and **new** signals snap in via a registry:

```go
type SignalSource interface {
    Signals(ctx context.Context, userID string) ([]Signal, error)
}

svc.RegisterSignalSource(biometricSource)   // the snap-in entry point
```

`mint()` builds the held set (built-ins ∪ registered sources) and evaluates the
policy. `identityState()` is kept as a thin wrapper over the policy so its
behavior table-test still proves the mapping unchanged.

### Brick 3 — reference tables, not `CHECK` enums (schema) — *planned*

Replace `provider IN (...)` and `verification_status IN (...)` CHECKs with FK'd
reference tables, so registering a brick is a *data insert*, not a *migration*.
(Trade-off: CHECKs are airtight; reference tables are extensible — for a snap-in
goal, FK'd tables win while preserving integrity.)

## Worked example: adding biometrics

Biometrics is the stress test because it lands on **both** axes, and the cost
after the refactor is one brick per axis:

| Intent | Before | After |
| --- | --- | --- |
| **As a login factor** (FaceID/passkey unlock proves account control) | new bespoke service + routes (~4 files) | one `AuthMethod` impl + 1 registry line *(needs Brick 1)* |
| **As an assurance signal** (liveness + match vs. national ID raises the tier) | edit `identityState()` + `mint()` + new repo read + **migrate the enum** (~5 files, 2 layers) | one `SignalSource` impl emitting `biometric_liveness` + 1 policy row *(Brick 2, today)* |

For the assurance case, concretely:

```go
// 1. declare the signal (open set — no enum migration)
const SignalBiometricLiveness Signal = "biometric_liveness"

// 2. add a policy row (e.g. liveness is an alternative path to verified)
{contracts.IdentityVerified, []Signal{SignalBiometricLiveness}},

// 3. register a source that reports it
svc.RegisterSignalSource(biometricLivenessSource{repo})
```

No edit to `mint()`, `identityState()`, or the assembly. That is the Lego test
passing.

## Status

- **Brick 2 (assurance policy + signal registry):** implemented.
- **Brick 1 (`AuthMethod` registry):** planned — unifies the three login flows.
- **Brick 3 (reference tables):** planned — alongside Brick 1.
