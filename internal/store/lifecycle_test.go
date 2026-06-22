//go:build integration

package store_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/jcrexon/laplat/internal/auth"
	"github.com/jcrexon/laplat/pkg/contracts"
	"github.com/jcrexon/laplat/pkg/token"
)

// End-to-end proof that the token spine works through real Postgres state:
// mint (internal/auth) -> verify signature/alg/time (A-1) -> revocation checks
// backed by the store (A-5). The unit tests in pkg/token use in-memory fakes;
// this exercises the same Validator against the actual revoked_tokens table and
// users.token_version column.
func Test_AccessTokenLifecycle_EndToEnd(t *testing.T) {
	s, ctx := newStore(t)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := token.NewSigner("kid-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	minter, err := auth.NewMinter(signer, contracts.TokenIssuer, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	verifier := token.NewVerifier(map[string]ed25519.PublicKey{"kid-1": pub})
	validator := token.NewValidator(verifier, s)

	tv, err := s.CurrentTokenVersion(ctx, userA)
	if err != nil {
		t.Fatal(err)
	}

	tok, claims, err := minter.MintAccess(userA, tv, contracts.IdentityVerified,
		[]contracts.Capability{contracts.CapCanInstruct})
	if err != nil {
		t.Fatal(err)
	}

	// 1. A freshly minted token passes the full gate against live DB state.
	got, err := validator.Validate(ctx, tok)
	if err != nil {
		t.Fatalf("fresh token should validate: %v", err)
	}
	if got.Subject != userA {
		t.Fatalf("subject = %q, want %q", got.Subject, userA)
	}

	// 2. Single-token revocation (A-5): denylisting this jti rejects exactly it.
	if err := s.RevokeAccessToken(ctx, claims.TokenID, time.Unix(claims.ExpiresAt, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := validator.Validate(ctx, tok); !errors.Is(err, token.ErrRevoked) {
		t.Fatalf("denylisted token: got %v, want ErrRevoked", err)
	}

	// 3. Revoke-all (A-5): an otherwise-valid token is superseded by a
	//    token_version bump.
	tok2, _, err := minter.MintAccess(userA, tv, contracts.IdentityVerified, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validator.Validate(ctx, tok2); err != nil {
		t.Fatalf("second token should validate before the bump: %v", err)
	}
	if _, err := s.RevokeAllForUser(ctx, userA); err != nil {
		t.Fatal(err)
	}
	if _, err := validator.Validate(ctx, tok2); !errors.Is(err, token.ErrTokenSuperseded) {
		t.Fatalf("after revoke-all: got %v, want ErrTokenSuperseded", err)
	}
}
