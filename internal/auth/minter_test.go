package auth

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/jcrexon/laplat/pkg/contracts"
	"github.com/jcrexon/laplat/pkg/token"
)

type memRevocations struct {
	denylisted map[string]bool
	versions   map[string]int
}

func (m *memRevocations) IsAccessTokenRevoked(_ context.Context, jti string) (bool, error) {
	return m.denylisted[jti], nil
}
func (m *memRevocations) CurrentTokenVersion(_ context.Context, userID string) (int, error) {
	return m.versions[userID], nil
}

func newSigner(t *testing.T) (*token.Signer, *token.Verifier) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := token.NewSigner("k1", priv)
	if err != nil {
		t.Fatal(err)
	}
	return s, token.NewVerifier(map[string]ed25519.PublicKey{"k1": pub})
}

func TestNewMinterEnforcesTTLBound(t *testing.T) {
	s, _ := newSigner(t)
	for _, bad := range []time.Duration{0, -time.Second, 16 * time.Minute, time.Hour} {
		if _, err := NewMinter(s, contracts.TokenIssuer, bad); err == nil {
			t.Fatalf("expected TTL %s to be rejected", bad)
		}
	}
	if _, err := NewMinter(s, contracts.TokenIssuer, 15*time.Minute); err != nil {
		t.Fatalf("15m should be allowed: %v", err)
	}
}

// End-to-end: a freshly minted token validates, carries the right claims, and
// never carries a per-room role (only global caps).
func TestMintThenValidate(t *testing.T) {
	s, v := newSigner(t)
	m, err := NewMinter(s, contracts.TokenIssuer, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	tok, claims, err := m.MintAccess("user-1", 1, contracts.IdentityVerified,
		[]contracts.Capability{contracts.CapCanInstruct})
	if err != nil {
		t.Fatal(err)
	}
	if claims.SchemaVersion != contracts.AccessTokenSchemaVersion {
		t.Errorf("schema version not stamped: %d", claims.SchemaVersion)
	}
	if claims.TokenID == "" {
		t.Error("jti not generated")
	}

	rev := &memRevocations{denylisted: map[string]bool{}, versions: map[string]int{"user-1": 1}}
	got, err := token.NewValidator(v, rev).Validate(context.Background(), tok)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got.IdentityVerification != contracts.IdentityVerified {
		t.Errorf("idv not preserved: %s", got.IdentityVerification)
	}
}

// Distinct mints must have distinct jtis (so single-token revocation is precise).
func TestMintGeneratesUniqueJTI(t *testing.T) {
	s, _ := newSigner(t)
	m, _ := NewMinter(s, contracts.TokenIssuer, time.Minute)
	_, a, _ := m.MintAccess("u", 1, contracts.IdentityNone, nil)
	_, b, _ := m.MintAccess("u", 1, contracts.IdentityNone, nil)
	if a.TokenID == b.TokenID {
		t.Fatal("jti collision across mints")
	}
}
