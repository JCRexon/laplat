package token

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jcrexon/laplat/pkg/contracts"
)

func newKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return pub, priv
}

func sampleClaims() contracts.AccessTokenClaims {
	now := time.Now()
	return contracts.AccessTokenClaims{
		Issuer:               contracts.TokenIssuer,
		Subject:              "user-1",
		IssuedAt:             now.Unix(),
		ExpiresAt:            now.Add(10 * time.Minute).Unix(),
		TokenID:              "jti-1",
		SchemaVersion:        contracts.AccessTokenSchemaVersion,
		TokenVersion:         1,
		IdentityVerification: contracts.IdentityVerified,
		Capabilities:         []contracts.Capability{contracts.CapCanInstruct},
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv := newKeyPair(t)
	signer, err := NewSigner("k1", priv)
	if err != nil {
		t.Fatal(err)
	}
	v := NewVerifier(map[string]ed25519.PublicKey{"k1": pub})

	tok, err := signer.Sign(sampleClaims())
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Subject != "user-1" || !got.HasCapability(contracts.CapCanInstruct) {
		t.Fatalf("claims not round-tripped: %+v", got)
	}
}

// A-1: a token with alg "none" and no signature must be rejected.
func TestThreat_A1_RejectsAlgNone(t *testing.T) {
	pub, _ := newKeyPair(t)
	v := NewVerifier(map[string]ed25519.PublicKey{"k1": pub})

	hb, _ := json.Marshal(map[string]string{"alg": "none", "typ": "JWT", "kid": "k1"})
	pb, _ := json.Marshal(sampleClaims())
	forged := b64(hb) + "." + b64(pb) + "." // empty signature

	_, err := v.Verify(forged)
	if !errors.Is(err, ErrUnsupportedAlg) {
		t.Fatalf("want ErrUnsupportedAlg, got %v", err)
	}
}

// A-1: HS/RS confusion — attacker uses the Ed25519 public key as an HMAC
// secret and claims alg HS256. Must be rejected at the alg pin.
func TestThreat_A1_RejectsHMACConfusion(t *testing.T) {
	pub, _ := newKeyPair(t)
	v := NewVerifier(map[string]ed25519.PublicKey{"k1": pub})

	hb, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT", "kid": "k1"})
	pb, _ := json.Marshal(sampleClaims())
	signingInput := b64(hb) + "." + b64(pb)
	mac := hmac.New(sha256.New, pub) // public key abused as shared secret
	mac.Write([]byte(signingInput))
	forged := signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	_, err := v.Verify(forged)
	if !errors.Is(err, ErrUnsupportedAlg) {
		t.Fatalf("want ErrUnsupportedAlg, got %v", err)
	}
}

func TestThreat_A1_RejectsTamperedPayload(t *testing.T) {
	pub, priv := newKeyPair(t)
	signer, _ := NewSigner("k1", priv)
	v := NewVerifier(map[string]ed25519.PublicKey{"k1": pub})

	tok, _ := signer.Sign(sampleClaims())
	parts := strings.Split(tok, ".")

	// Re-encode a payload with escalated capabilities, keep the old signature.
	tampered := sampleClaims()
	tampered.Capabilities = []contracts.Capability{contracts.CapPlatformModerator}
	pb, _ := json.Marshal(tampered)
	forged := parts[0] + "." + b64(pb) + "." + parts[2]

	_, err := v.Verify(forged)
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

func TestThreat_A1_RejectsUnknownKeyID(t *testing.T) {
	_, priv := newKeyPair(t)
	otherPub, _ := newKeyPair(t)
	signer, _ := NewSigner("k1", priv)
	v := NewVerifier(map[string]ed25519.PublicKey{"k2": otherPub}) // k1 not trusted

	tok, _ := signer.Sign(sampleClaims())
	_, err := v.Verify(tok)
	if !errors.Is(err, ErrUnknownKeyID) {
		t.Fatalf("want ErrUnknownKeyID, got %v", err)
	}
}

func TestThreat_A1_RejectsWrongKey(t *testing.T) {
	_, priv := newKeyPair(t)
	wrongPub, _ := newKeyPair(t)
	signer, _ := NewSigner("k1", priv)
	v := NewVerifier(map[string]ed25519.PublicKey{"k1": wrongPub}) // same kid, wrong key

	tok, _ := signer.Sign(sampleClaims())
	_, err := v.Verify(tok)
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

// A-5: short-TTL enforcement — an expired token must not validate.
func TestThreat_A5_RejectsExpired(t *testing.T) {
	pub, priv := newKeyPair(t)
	signer, _ := NewSigner("k1", priv)
	v := NewVerifier(map[string]ed25519.PublicKey{"k1": pub})

	claims := sampleClaims()
	claims.IssuedAt = time.Now().Add(-2 * time.Hour).Unix()
	claims.ExpiresAt = time.Now().Add(-time.Hour).Unix()
	tok, _ := signer.Sign(claims)

	_, err := v.Verify(tok)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	pub, _ := newKeyPair(t)
	v := NewVerifier(map[string]ed25519.PublicKey{"k1": pub})
	for _, tok := range []string{"", "a.b", "a.b.c.d", "not-base64.@.@"} {
		if _, err := v.Verify(tok); err == nil {
			t.Fatalf("expected error for %q", tok)
		}
	}
}
