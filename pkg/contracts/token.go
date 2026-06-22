package contracts

// AccessTokenSchemaVersion is the version of the CLAIM SHAPE below. Bump it
// only when the structure of the claims changes (so consumers can migrate).
// It is NOT a revocation lever — that is TokenVersion (A-5).
const AccessTokenSchemaVersion = 1

// TokenIssuer is the fixed `iss` claim value.
const TokenIssuer = "auth.platform"

// JWT header values. The algorithm is pinned server-side and "none" is
// rejected on verification (A-1).
const (
	TokenAlg = "EdDSA"
	TokenTyp = "JWT"
)

// IdentityVerificationState is the Decree-147 identity-verification status the
// token asserts. It states THAT verification passed, never the underlying
// identity — no PII ever rides in a claim (A-6).
type IdentityVerificationState string

const (
	IdentityVerified IdentityVerificationState = "verified"
	IdentityPending  IdentityVerificationState = "pending"
	IdentityNone     IdentityVerificationState = "none"
)

// Capability is a GLOBAL capability carried in the token. Per-room and
// per-class roles are deliberately NOT carried here — they are derived at
// grant-mint time from class membership / session participation, which keeps
// privilege scoping server-side and per-room and prevents A-3 (grant
// over-scoping) and B-2 (cross-room access) by construction.
type Capability string

const (
	// CapCanInstruct is backed by users.can_instruct.
	CapCanInstruct Capability = "can_instruct"
	// CapPlatformModerator is backed by users.is_platform_moderator. This is a
	// PLATFORM moderator; a class moderator is a per-class role, not a cap.
	CapPlatformModerator Capability = "platform_moderator"
)

// AccessTokenClaims is the frozen access-token claim set (contracts §1).
//
// Deliberately absent: is_adult / account status and any per-room role. Those
// are checked server-side at the point of use (grant-mint, post, record) so a
// suspension or demotion takes effect immediately, rather than waiting out the
// token's TTL.
type AccessTokenClaims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"` // opaque ULID — never the VN ID/phone (A-6)
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"` // short TTL (<= 15 minutes)

	// TokenID is the unique id used for single-token revocation via the
	// revoked_tokens denylist (A-5).
	TokenID string `json:"jti"`

	// SchemaVersion mirrors AccessTokenSchemaVersion: claim-shape version ONLY.
	SchemaVersion int `json:"sver"`

	// TokenVersion mirrors users.token_version. Bumping the user's
	// token_version invalidates every outstanding token for that user
	// (revoke-all): verification rejects any token whose tver does not match
	// the current users.token_version (A-5).
	TokenVersion int `json:"tver"`

	// IdentityVerification asserts the Decree-147 verification state.
	IdentityVerification IdentityVerificationState `json:"idv"`

	// Capabilities are GLOBAL capabilities only (see Capability).
	Capabilities []Capability `json:"caps"`
}

// HasCapability reports whether the claims carry the given global capability.
func (c AccessTokenClaims) HasCapability(cap Capability) bool {
	for _, have := range c.Capabilities {
		if have == cap {
			return true
		}
	}
	return false
}
