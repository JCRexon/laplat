package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"testing"
	"time"
)

// --- test signing helpers ----------------------------------------------------

func sign(t *testing.T, header map[string]string, claims map[string]any, signer func([]byte) []byte) string {
	t.Helper()
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	input := b64.EncodeToString(hb) + "." + b64.EncodeToString(cb)
	sig := signer([]byte(input))
	return input + "." + b64.EncodeToString(sig)
}

func rsaSigner(t *testing.T, key *rsa.PrivateKey) func([]byte) []byte {
	return func(in []byte) []byte {
		h := sha256.Sum256(in)
		s, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
}

func ecSigner(t *testing.T, key *ecdsa.PrivateKey) func([]byte) []byte {
	return func(in []byte) []byte {
		h := sha256.Sum256(in)
		r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
		if err != nil {
			t.Fatal(err)
		}
		// JOSE ES256 = fixed-width r||s, 32 bytes each.
		out := make([]byte, 64)
		r.FillBytes(out[:32])
		s.FillBytes(out[32:])
		return out
	}
}

func baseClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss":   "https://accounts.google.com",
		"sub":   "user-123",
		"aud":   "client-abc",
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Add(-time.Minute).Unix(),
		"nonce": "nonce-xyz",
		"email": "a@example.com",
	}
}

func rsaProvider(t *testing.T) (*Provider, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ks := &StaticKeySet{keys: map[string]keyEntry{"r1": {key: &key.PublicKey, alg: "RS256"}}}
	p := &Provider{Name: "google", Issuer: "https://accounts.google.com", Audience: "client-abc", Keys: ks}
	return p, key
}

// --- tests -------------------------------------------------------------------

func TestVerify_RS256_OK(t *testing.T) {
	p, key := rsaProvider(t)
	tok := sign(t, map[string]string{"alg": "RS256", "kid": "r1"}, baseClaims(time.Now()), rsaSigner(t, key))
	claims, err := p.Verify(context.Background(), tok, "nonce-xyz")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Subject != "user-123" || claims.Email != "a@example.com" {
		t.Fatalf("claims = %+v", claims)
	}
}

func TestVerify_ES256_OK(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ks := &StaticKeySet{keys: map[string]keyEntry{"e1": {key: &key.PublicKey, alg: "ES256"}}}
	p := &Provider{Name: "apple", Issuer: "https://appleid.apple.com", Audience: "com.laplat.app", Keys: ks}
	claims := baseClaims(time.Now())
	claims["iss"] = "https://appleid.apple.com"
	claims["aud"] = "com.laplat.app"
	claims["email_verified"] = "true" // Apple sends a string
	tok := sign(t, map[string]string{"alg": "ES256", "kid": "e1"}, claims, ecSigner(t, key))
	got, err := p.Verify(context.Background(), tok, "nonce-xyz")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !got.EmailVerified {
		t.Fatal("apple email_verified string not parsed to true")
	}
}

func TestVerify_Rejections(t *testing.T) {
	now := time.Now()
	t.Run("tampered signature", func(t *testing.T) {
		p, key := rsaProvider(t)
		tok := sign(t, map[string]string{"alg": "RS256", "kid": "r1"}, baseClaims(now), rsaSigner(t, key))
		if _, err := p.Verify(context.Background(), tok+"x", ""); err == nil {
			t.Fatal("expected signature failure")
		}
	})
	t.Run("unknown kid", func(t *testing.T) {
		p, key := rsaProvider(t)
		tok := sign(t, map[string]string{"alg": "RS256", "kid": "nope"}, baseClaims(now), rsaSigner(t, key))
		if _, err := p.Verify(context.Background(), tok, ""); err == nil {
			t.Fatal("expected unknown-key failure")
		}
	})
	t.Run("alg mismatch", func(t *testing.T) {
		p, key := rsaProvider(t)
		// Key r1 is registered RS256; claim ES256 in the header.
		tok := sign(t, map[string]string{"alg": "ES256", "kid": "r1"}, baseClaims(now), rsaSigner(t, key))
		if _, err := p.Verify(context.Background(), tok, ""); err == nil {
			t.Fatal("expected alg-mismatch failure")
		}
	})
	t.Run("wrong issuer", func(t *testing.T) {
		p, key := rsaProvider(t)
		c := baseClaims(now)
		c["iss"] = "https://evil.example.com"
		tok := sign(t, map[string]string{"alg": "RS256", "kid": "r1"}, c, rsaSigner(t, key))
		if _, err := p.Verify(context.Background(), tok, ""); err == nil {
			t.Fatal("expected issuer failure")
		}
	})
	t.Run("wrong audience", func(t *testing.T) {
		p, key := rsaProvider(t)
		c := baseClaims(now)
		c["aud"] = "someone-else"
		tok := sign(t, map[string]string{"alg": "RS256", "kid": "r1"}, c, rsaSigner(t, key))
		if _, err := p.Verify(context.Background(), tok, ""); err == nil {
			t.Fatal("expected audience failure")
		}
	})
	t.Run("expired", func(t *testing.T) {
		p, key := rsaProvider(t)
		c := baseClaims(now)
		c["exp"] = now.Add(-time.Hour).Unix()
		tok := sign(t, map[string]string{"alg": "RS256", "kid": "r1"}, c, rsaSigner(t, key))
		if _, err := p.Verify(context.Background(), tok, ""); err == nil {
			t.Fatal("expected expiry failure")
		}
	})
	t.Run("nonce mismatch", func(t *testing.T) {
		p, key := rsaProvider(t)
		tok := sign(t, map[string]string{"alg": "RS256", "kid": "r1"}, baseClaims(now), rsaSigner(t, key))
		if _, err := p.Verify(context.Background(), tok, "different-nonce"); err == nil {
			t.Fatal("expected nonce failure")
		}
	})
}

// aud may be a JSON array; the configured audience must be present.
func TestVerify_AudienceArray(t *testing.T) {
	p, key := rsaProvider(t)
	c := baseClaims(time.Now())
	c["aud"] = []string{"other", "client-abc"}
	tok := sign(t, map[string]string{"alg": "RS256", "kid": "r1"}, c, rsaSigner(t, key))
	if _, err := p.Verify(context.Background(), tok, "nonce-xyz"); err != nil {
		t.Fatalf("array audience should pass: %v", err)
	}
}

// ParseJWKS builds a working keyset from a JWKS JSON document.
func TestParseJWKS_RoundTrip(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	eBytes := big.NewInt(int64(key.E)).Bytes()
	doc, _ := json.Marshal(jwkSet{Keys: []jwk{{
		Kty: "RSA", Kid: "r1", Alg: "RS256",
		N: b64.EncodeToString(key.N.Bytes()),
		E: b64.EncodeToString(eBytes),
	}}})
	ks, err := ParseJWKS(doc)
	if err != nil {
		t.Fatalf("parse jwks: %v", err)
	}
	p := &Provider{Name: "google", Issuer: "https://accounts.google.com", Audience: "client-abc", Keys: ks}
	tok := sign(t, map[string]string{"alg": "RS256", "kid": "r1"}, baseClaims(time.Now()), rsaSigner(t, key))
	if _, err := p.Verify(context.Background(), tok, ""); err != nil {
		t.Fatalf("verify with parsed jwks: %v", err)
	}
}
