# Access model — assurance tiers & capabilities

How the platform decides who may do what. This is product design (the policy),
not the mechanism, so it lives in-repo next to the code that enforces it.

The guiding principle: **assurance climbs with risk.** Passive consumption asks
for nothing; real-time interaction asks for a verified phone (the Decree 147
floor); money and hosting ask for eKYC. Each rung proves only as much identity as
its actions warrant, and no PII ever rides in a token claim — a claim states the
*level* of assurance, never the underlying identity.

## The ladder

The assurance tier is a single cumulative, ordered value
(`none < declared < phone_verified < verified`), defined as
`IdentityVerificationState` in [`pkg/contracts/token.go`](pkg/contracts/token.go)
and derived at token-mint time by `identityState()` in
[`internal/auth/service.go`](internal/auth/service.go).

| Tier | Proves | Unlocks |
| --- | --- | --- |
| `none` | nothing (authenticated account only) | browse the catalog and **free** recordings |
| `declared` | self-attested 18+ (ToS attestation) | general features, schedule browse |
| `phone_verified` | declared **+ a verified phone** | live sessions, 1:1 calls, posting/publishing |
| `verified` | eKYC-verified adult (national ID) | payments, paid recordings, becoming an instructor |

`pending` is orthogonal: an eKYC check is in flight. A user keeps their existing
tier while a verification is pending.

Read the rungs as three risk bands:

- **watch** (passive) → no proof
- **interact live** (presence, real time) → phone-verified adult — the Decree 147
  interaction floor, satisfied by phone rather than national ID
- **transact / instruct** (money, hosting) → eKYC adult

## Adults-only is an invariant, not a per-content gate

There is no minor tier. The lowest *active* account state, `declared`, already
requires an 18+ attestation, and the database backs it: the
`enforce_adult_activation` trigger
([`migrations/00007_tiered_assurance.sql`](migrations/00007_tiered_assurance.sql))
refuses to activate any account without either eKYC `is_adult` **or** an
`adult_attested` ToS row. So **active member ⟹ adult, by construction** —
"members-only" and "adults-only" collapse into the same gate. What the ladder
grades is not adult-vs-minor but *how strongly* adulthood is proven.

If a user later loses the basis for their tier (eKYC revoked with no attestation
to fall back on), the `enforce_identity_downgrade` trigger
([`migrations/00004_identity_downgrade_and_cap_semantics.sql`](migrations/00004_identity_downgrade_and_cap_semantics.sql))
suspends the account and bumps `token_version`, so outstanding tokens die within
one refresh cycle.

## Capabilities are separate from tiers

Two **global** capabilities ride in the token alongside the tier
([`pkg/contracts/token.go`](pkg/contracts/token.go)):

- `can_instruct` — may create and host classes.
- `platform_moderator` — may suspend/reinstate accounts and grant/revoke
  instructor status.

Per-room and per-class roles are deliberately **not** capabilities — they are
derived server-side at grant-mint time from class membership / session
participation, which keeps privilege scoping per-room and prevents grant
over-scoping and cross-room access by construction.

A capability is gated by a tier at the point it is *acquired*: becoming an
instructor (`POST /v1/instructor/apply`) requires `verified` (eKYC), so every
instructor is an eKYC adult. A moderator can also grant/revoke `can_instruct`
directly ([`internal/moderation`](internal/moderation)).

## Owned content is entitlement-gated, not tier-gated

Tiers gate the **discovery funnel**, not content a user already owns. A
**purchased** recording is gated by *entitlement* (you own it), never by current
tier:

- Payment sits at `verified`, so the buyer cleared eKYC to pay — adult assurance
  is already subsumed, and no separate attestation check is needed to watch.
- The entitlement is **durable across a later downgrade**: if a buyer drops below
  `verified` afterward, they still own what they bought. (Were they to fall all
  the way out of an adult basis, the downgrade trigger suspends them and the
  question is moot.)
- Only **free** recordings sit on the tier ladder, at the `none` floor.

Paid content is therefore members-only by necessity: an entitlement is a row
keyed to an account, so there is no anonymous purchase to track.

## Where it's enforced

Gates live in the service layer (checked on every request from token claims, so a
downgrade takes effect immediately rather than waiting out a token's TTL):

| Action | Requirement | Enforced in |
| --- | --- | --- |
| Browse published catalog | none | `ListPublished` — [`internal/class/class.go`](internal/class/class.go) |
| Browse a class's schedule | `declared` | `ListForClass`/`Detail` — [`internal/session/session.go`](internal/session/session.go) |
| Create / join a live session | `phone_verified` | `MeetsPhoneVerification()` — [`internal/session/session.go`](internal/session/session.go) |
| Create a class | `phone_verified` + `can_instruct` | `Create` — [`internal/class/class.go`](internal/class/class.go) |
| Enroll in a class | `declared` (+ entitlement if paid) | `Enroll` — [`internal/class/enrollment.go`](internal/class/enrollment.go) |
| Play a recording | none if free; entitlement if paid | `playback` — [`internal/recording/http.go`](internal/recording/http.go) |
| Grant / revoke an entitlement | `platform_moderator` (until a payment provider drives it) | [`internal/entitlement`](internal/entitlement) |
| Become an instructor | `verified` (eKYC) | `POST /v1/instructor/apply` — [`internal/auth`](internal/auth) |
| Suspend / reinstate / set-instructor | `platform_moderator` | [`internal/moderation`](internal/moderation) |

Claim helpers (`MeetsAdultDeclaration`, `MeetsPhoneVerification`,
`IsVerifiedAdult`, `HasCapability`) live in
[`pkg/contracts/token.go`](pkg/contracts/token.go).

## Built vs. planned

- **Built:** the tier ladder and claim helpers, adult-activation and downgrade
  triggers, class catalog + sessions, instructor onboarding (self-apply +
  moderator grant/revoke), platform moderation, the recording-consent ledger
  ([`internal/consent`](internal/consent) — append-only, signed, with a
  `RecordingAllowed` gate and a withdrawal that stops recording, D-2), and the
  recording control plane ([`internal/recording`](internal/recording) — starts
  LiveKit egress only behind that gate, host-triggered, stop-on-withdrawal), and
  the **entitlements gate** ([`internal/entitlement`](internal/entitlement) — a
  durable per-account ownership record; `classes.price_cents` marks paid content;
  enrollment and recording playback consult it; free content is unchanged; an
  entitlement survives a later downgrade). Grants come from a moderator today
  (comp/support); a payment provider will drive them on a completed charge.
- **Built (media infra):** a LiveKit + egress server in the stack so recordings
  capture end-to-end, webhook-driven egress status reconciliation, and recording
  playback (nginx `secure_link`-signed URLs).
- **In review:** Zalo (OAuth) sign-in.
- **Planned:** the payment provider (Stripe/VNPay) — the only remaining piece of
  payments now that the entitlements model + gate are built; on a completed charge
  it calls `entitlement.Service.Grant`. Also class capacity limits (a max on the
  per-class roster).
