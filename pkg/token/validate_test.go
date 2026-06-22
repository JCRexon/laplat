package token

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/jcrexon/laplat/pkg/contracts"
)

// memRevocations is an in-memory RevocationStore for tests. The Postgres-backed
// implementation lands when the DB is wired.
type memRevocations struct {
	denylisted map[string]bool
	versions   map[string]int
}

func newMemRevocations() *memRevocations {
	return &memRevocations{denylisted: map[string]bool{}, versions: map[string]int{}}
}

func (m *memRevocations) IsAccessTokenRevoked(_ context.Context, jti string) (bool, error) {
	return m.denylisted[jti], nil
}

func (m *memRevocations) CurrentTokenVersion(_ context.Context, userID string) (int, error) {
	return m.versions[userID], nil
}

func newSignedToken(t *testing.T, claims contracts.AccessTokenClaims) (string, *Verifier) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := NewSigner("k1", priv)
	tok, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	return tok, NewVerifier(map[string]ed25519.PublicKey{"k1": pub})
}

func validClaims() contracts.AccessTokenClaims {
	now := time.Now()
	return contracts.AccessTokenClaims{
		Issuer:       contracts.TokenIssuer,
		Subject:      "user-1",
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(10 * time.Minute).Unix(),
		TokenID:      "jti-1",
		TokenVersion: 1,
	}
}

func TestValidateOK(t *testing.T) {
	claims := validClaims()
	tok, v := newSignedToken(t, claims)
	rev := newMemRevocations()
	rev.versions["user-1"] = 1

	val := NewValidator(v, rev)
	if _, err := val.Validate(context.Background(), tok); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

// A-5: a denylisted jti is rejected (single-token revocation).
func TestValidateRejectsDenylistedJTI(t *testing.T) {
	claims := validClaims()
	tok, v := newSignedToken(t, claims)
	rev := newMemRevocations()
	rev.versions["user-1"] = 1
	rev.denylisted["jti-1"] = true

	val := NewValidator(v, rev)
	if _, err := val.Validate(context.Background(), tok); !errors.Is(err, ErrRevoked) {
		t.Fatalf("want ErrRevoked, got %v", err)
	}
}

// A-5: bumping the user's token_version invalidates an already-minted token
// (revoke-all).
func TestValidateRejectsSupersededTokenVersion(t *testing.T) {
	claims := validClaims() // minted at tver 1
	tok, v := newSignedToken(t, claims)
	rev := newMemRevocations()
	rev.versions["user-1"] = 2 // bumped after minting

	val := NewValidator(v, rev)
	if _, err := val.Validate(context.Background(), tok); !errors.Is(err, ErrTokenSuperseded) {
		t.Fatalf("want ErrTokenSuperseded, got %v", err)
	}
}
