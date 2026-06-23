// Package oidc verifies OpenID Connect ID tokens from external providers
// (Sign in with Google / Apple) using only the Go standard library — the same
// rationale as pkg/token: every login path depends on this, so its dependency
// surface is kept at zero (E-2), and the algorithm handling is auditable in one
// place. It supports RS256 (Google) and ES256 (Apple).
//
// This package only PROVES who the external account is. It does not establish
// adult identity verification; that is a separate eKYC concern.
package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Sentinel errors (compare with errors.Is).
var (
	ErrMalformed      = errors.New("oidc: malformed id token")
	ErrUnsupportedAlg = errors.New("oidc: unsupported alg")
	ErrUnknownKey     = errors.New("oidc: no verification key for kid")
	ErrBadSignature   = errors.New("oidc: signature verification failed")
	ErrClaims         = errors.New("oidc: claim validation failed")
)

// Claims are the verified ID-token claims callers care about.
type Claims struct {
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	Nonce         string
	IssuedAt      time.Time
	Expiry        time.Time
}

// KeySet resolves a provider's signing keys by key id.
type KeySet interface {
	// VerificationKey returns the public key for kid and the JOSE alg it signs
	// with ("RS256" or "ES256").
	VerificationKey(ctx context.Context, kid string) (crypto.PublicKey, string, error)
}

// Provider verifies tokens for one issuer/audience using a KeySet.
type Provider struct {
	Name     string // "google" / "apple"
	Issuer   string // expected iss
	Audience string // expected aud (the OAuth client id)
	Keys     KeySet

	// Now and Leeway are overridable; defaults are time.Now and 60s.
	Now    func() time.Time
	Leeway time.Duration
}

func (p *Provider) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Provider) leeway() time.Duration {
	if p.Leeway != 0 {
		return p.Leeway
	}
	return 60 * time.Second
}

type joseHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// rawClaims handles aud being either a string or an array (both are legal).
type rawClaims struct {
	Iss           string          `json:"iss"`
	Sub           string          `json:"sub"`
	Aud           json.RawMessage `json:"aud"`
	Exp           int64           `json:"exp"`
	Iat           int64           `json:"iat"`
	Nonce         string          `json:"nonce"`
	Email         string          `json:"email"`
	EmailVerified emailVerified   `json:"email_verified"`
}

// Verify checks the token's signature and claims. expectedNonce, when non-empty,
// must match the token's nonce (CSRF/replay binding from the auth request). The
// signature is verified BEFORE any claim is trusted.
func (p *Provider) Verify(ctx context.Context, idToken, expectedNonce string) (*Claims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, ErrMalformed
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, ErrMalformed
	}
	var h joseHeader
	if err := json.Unmarshal(hb, &h); err != nil {
		return nil, ErrMalformed
	}

	key, alg, err := p.Keys.VerificationKey(ctx, h.Kid)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrUnknownKey, h.Kid)
	}
	// The header alg must match what the key is registered for, and must be one
	// we support — this is the algorithm pin (no "none", no confusion).
	if h.Alg != alg {
		return nil, ErrUnsupportedAlg
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, ErrMalformed
	}
	if err := verifySignature(alg, key, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		return nil, err
	}

	pb, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, ErrMalformed
	}
	var rc rawClaims
	if err := json.Unmarshal(pb, &rc); err != nil {
		return nil, ErrMalformed
	}

	if rc.Iss != p.Issuer {
		return nil, fmt.Errorf("%w: issuer %q != %q", ErrClaims, rc.Iss, p.Issuer)
	}
	if !audienceContains(rc.Aud, p.Audience) {
		return nil, fmt.Errorf("%w: audience mismatch", ErrClaims)
	}
	if rc.Sub == "" {
		return nil, fmt.Errorf("%w: empty subject", ErrClaims)
	}
	now := p.now()
	if rc.Exp == 0 || now.After(time.Unix(rc.Exp, 0).Add(p.leeway())) {
		return nil, fmt.Errorf("%w: token expired", ErrClaims)
	}
	if rc.Iat != 0 && now.Add(p.leeway()).Before(time.Unix(rc.Iat, 0)) {
		return nil, fmt.Errorf("%w: issued in the future", ErrClaims)
	}
	if expectedNonce != "" && rc.Nonce != expectedNonce {
		return nil, fmt.Errorf("%w: nonce mismatch", ErrClaims)
	}

	return &Claims{
		Issuer:        rc.Iss,
		Subject:       rc.Sub,
		Email:         rc.Email,
		EmailVerified: bool(rc.EmailVerified),
		Nonce:         rc.Nonce,
		IssuedAt:      time.Unix(rc.Iat, 0),
		Expiry:        time.Unix(rc.Exp, 0),
	}, nil
}

func verifySignature(alg string, key crypto.PublicKey, signingInput, sig []byte) error {
	digest := sha256.Sum256(signingInput)
	switch alg {
	case "RS256":
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return ErrUnsupportedAlg
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
			return ErrBadSignature
		}
		return nil
	case "ES256":
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return ErrUnsupportedAlg
		}
		if len(sig) != 64 {
			return ErrBadSignature
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(pub, digest[:], r, s) {
			return ErrBadSignature
		}
		return nil
	default:
		return ErrUnsupportedAlg
	}
}

func audienceContains(raw json.RawMessage, want string) bool {
	if len(raw) == 0 {
		return false
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return one == want
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		for _, a := range many {
			if a == want {
				return true
			}
		}
	}
	return false
}

var b64 = base64.RawURLEncoding

// emailVerified accepts the bool that Google sends and the string ("true")
// that Apple sends.
type emailVerified bool

func (e *emailVerified) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	*e = emailVerified(s == "true")
	return nil
}

// --- key material ------------------------------------------------------------

// jwk is one JSON Web Key (RSA or EC P-256).
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

// parseJWK converts a JWK into a public key and its JOSE alg.
func parseJWK(k jwk) (crypto.PublicKey, string, error) {
	switch k.Kty {
	case "RSA":
		n, err := b64.DecodeString(k.N)
		if err != nil {
			return nil, "", fmt.Errorf("jwk rsa n: %w", err)
		}
		e, err := b64.DecodeString(k.E)
		if err != nil {
			return nil, "", fmt.Errorf("jwk rsa e: %w", err)
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		return pub, "RS256", nil
	case "EC":
		if k.Crv != "P-256" {
			return nil, "", fmt.Errorf("jwk ec: unsupported curve %q", k.Crv)
		}
		x, err := b64.DecodeString(k.X)
		if err != nil {
			return nil, "", fmt.Errorf("jwk ec x: %w", err)
		}
		y, err := b64.DecodeString(k.Y)
		if err != nil {
			return nil, "", fmt.Errorf("jwk ec y: %w", err)
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		return pub, "ES256", nil
	default:
		return nil, "", fmt.Errorf("jwk: unsupported kty %q", k.Kty)
	}
}

// StaticKeySet is a fixed set of keys by kid — used in tests and for pinned
// keys. Parse a JWKS document with ParseJWKS.
type StaticKeySet struct {
	keys map[string]keyEntry
}

type keyEntry struct {
	key crypto.PublicKey
	alg string
}

// ParseJWKS builds a StaticKeySet from a JWKS JSON document.
func ParseJWKS(doc []byte) (*StaticKeySet, error) {
	var set jwkSet
	if err := json.Unmarshal(doc, &set); err != nil {
		return nil, fmt.Errorf("oidc: parse jwks: %w", err)
	}
	ks := &StaticKeySet{keys: map[string]keyEntry{}}
	for _, k := range set.Keys {
		pub, alg, err := parseJWK(k)
		if err != nil {
			return nil, err
		}
		ks.keys[k.Kid] = keyEntry{key: pub, alg: alg}
	}
	return ks, nil
}

// VerificationKey implements KeySet.
func (s *StaticKeySet) VerificationKey(_ context.Context, kid string) (crypto.PublicKey, string, error) {
	e, ok := s.keys[kid]
	if !ok {
		return nil, "", ErrUnknownKey
	}
	return e.key, e.alg, nil
}
