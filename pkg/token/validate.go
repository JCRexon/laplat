package token

import (
	"context"
	"errors"

	"github.com/jcrexon/laplat/pkg/contracts"
)

// Revocation errors (A-5).
var (
	// ErrRevoked means the specific token (by jti) is on the denylist.
	ErrRevoked = errors.New("token: revoked")
	// ErrTokenSuperseded means the token's tver no longer matches the user's
	// current token_version — a revoke-all has happened since it was minted.
	ErrTokenSuperseded = errors.New("token: superseded by token_version bump")
)

// RevocationStore is the state the stateless signature check cannot provide.
// In MVP this is backed by Postgres (revoked_tokens + users.token_version);
// it can move behind a cache when the platform clusters.
type RevocationStore interface {
	// IsAccessTokenRevoked reports whether a jti is denylisted (single-token
	// revocation).
	IsAccessTokenRevoked(ctx context.Context, jti string) (bool, error)
	// CurrentTokenVersion returns the user's current token_version (revoke-all
	// generation).
	CurrentTokenVersion(ctx context.Context, userID string) (int, error)
}

// Validator composes signature/time verification (A-1) with revocation checks
// (A-5). This is the type other services embed in their auth middleware — it
// depends only on a Verifier and an interface, so it crosses no service
// boundary.
type Validator struct {
	verifier    *Verifier
	revocations RevocationStore
}

// NewValidator wires a verifier to a revocation store.
func NewValidator(v *Verifier, r RevocationStore) *Validator {
	return &Validator{verifier: v, revocations: r}
}

// Validate runs the full gate: signature + alg pin + expiry (A-1), then
// single-token denylist and token_version match (A-5). It returns the claims
// only if every check passes.
func (val *Validator) Validate(ctx context.Context, tok string) (*contracts.AccessTokenClaims, error) {
	claims, err := val.verifier.Verify(tok)
	if err != nil {
		return nil, err
	}

	revoked, err := val.revocations.IsAccessTokenRevoked(ctx, claims.TokenID)
	if err != nil {
		return nil, err
	}
	if revoked {
		return nil, ErrRevoked
	}

	current, err := val.revocations.CurrentTokenVersion(ctx, claims.Subject)
	if err != nil {
		return nil, err
	}
	if claims.TokenVersion != current {
		return nil, ErrTokenSuperseded
	}

	return claims, nil
}
