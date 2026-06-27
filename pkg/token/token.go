// Package token implements minimal, dependency-free EdDSA (Ed25519) JWT
// signing and verification over contracts.AccessTokenClaims.
//
// It deliberately uses ONLY the Go standard library — no third-party JWT
// dependency — for two reasons:
//
//   - Supply-chain surface (E-2): every service that authenticates imports a
//     token verifier, so this is the worst place to take a dependency.
//   - Auditability of the A-1 guarantee: algorithm pinning lives in one place.
//     The verifier accepts "EdDSA" and rejects everything else, so `alg:none`
//     and HS/RS key-confusion attacks fail by construction — you can read the
//     single comparison that enforces it.
package token

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jcrexon/laplat/pkg/contracts"
	"github.com/jcrexon/laplat/pkg/signing"
)

// Sentinel errors. Callers may compare with errors.Is.
var (
	ErrMalformedToken = errors.New("token: malformed")
	ErrUnsupportedAlg = errors.New("token: unsupported alg (only EdDSA accepted)")
	ErrUnknownKeyID   = errors.New("token: unknown key id")
	ErrBadSignature   = errors.New("token: signature verification failed")
	ErrExpired        = errors.New("token: expired")
	ErrNotYetValid    = errors.New("token: not yet valid")
)

// jwtHeader is the JOSE header. Only alg/typ/kid are used.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

func b64(p []byte) string { return base64.RawURLEncoding.EncodeToString(p) }

func unb64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// Signer mints access tokens. It delegates the raw Ed25519 signature to a
// signing.KeySigner, so the private key can live in-process (the default) or
// behind a remote signer (Vault/HSM) and never enter this process — A-1. Only
// the auth service holds a Signer.
type Signer struct {
	ks signing.KeySigner
}

// NewSigner builds a Signer over an in-process Ed25519 key. Retained as the
// convenience constructor for the env-var key path and tests; for a remote
// backend use NewSignerFromKeySigner.
func NewSigner(kid string, key ed25519.PrivateKey) (*Signer, error) {
	ks, err := signing.NewLocalKeySigner(kid, key)
	if err != nil {
		return nil, err
	}
	return &Signer{ks: ks}, nil
}

// NewSignerFromKeySigner builds a Signer over any KeySigner (e.g. Vault Transit),
// so the signing key need not exist in this process.
func NewSignerFromKeySigner(ks signing.KeySigner) (*Signer, error) {
	if ks == nil {
		return nil, errors.New("token: key signer required")
	}
	if ks.KeyID() == "" {
		return nil, errors.New("token: kid required")
	}
	return &Signer{ks: ks}, nil
}

// KeyID returns the signer's key id (stamped into the token header so the
// verifier can select the matching public key — rotation-safe).
func (s *Signer) KeyID() string { return s.ks.KeyID() }

// Sign serialises and signs the claims, returning a compact JWS string.
func (s *Signer) Sign(claims contracts.AccessTokenClaims) (string, error) {
	hb, err := json.Marshal(jwtHeader{Alg: contracts.TokenAlg, Typ: contracts.TokenTyp, Kid: s.ks.KeyID()})
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64(hb) + "." + b64(pb)
	sig, err := s.ks.SignRaw([]byte(signingInput))
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64(sig), nil
}

// Verifier checks a token's signature and time bounds. It resolves the signing
// key by the header `kid`, so several public keys (rotation) can be trusted at
// once. It does NOT check revocation — that needs state; see Validator.
type Verifier struct {
	keys   map[string]ed25519.PublicKey
	leeway time.Duration
	now    func() time.Time
}

// NewVerifier trusts the given kid->public-key set.
func NewVerifier(keys map[string]ed25519.PublicKey) *Verifier {
	return &Verifier{keys: keys, leeway: 30 * time.Second, now: time.Now}
}

// Verify validates structure, algorithm, signature, and time bounds, returning
// the claims on success. The signature is checked BEFORE the payload claims are
// trusted.
func (v *Verifier) Verify(tok string) (*contracts.AccessTokenClaims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, ErrMalformedToken
	}

	hb, err := unb64(parts[0])
	if err != nil {
		return nil, ErrMalformedToken
	}
	var h jwtHeader
	if err := json.Unmarshal(hb, &h); err != nil {
		return nil, ErrMalformedToken
	}

	// A-1: the single pin. Anything that is not EdDSA — including "none",
	// "HS256", "RS256" — is rejected here, before any key handling.
	if h.Alg != contracts.TokenAlg {
		return nil, ErrUnsupportedAlg
	}

	pub, ok := v.keys[h.Kid]
	if !ok || len(pub) != ed25519.PublicKeySize {
		return nil, ErrUnknownKeyID
	}

	sig, err := unb64(parts[2])
	if err != nil {
		return nil, ErrMalformedToken
	}
	signingInput := parts[0] + "." + parts[1]
	if !ed25519.Verify(pub, []byte(signingInput), sig) {
		return nil, ErrBadSignature
	}

	// Signature is valid; now it is safe to read the payload.
	pb, err := unb64(parts[1])
	if err != nil {
		return nil, ErrMalformedToken
	}
	var claims contracts.AccessTokenClaims
	if err := json.Unmarshal(pb, &claims); err != nil {
		return nil, ErrMalformedToken
	}

	now := v.now()
	if claims.ExpiresAt != 0 && now.After(time.Unix(claims.ExpiresAt, 0).Add(v.leeway)) {
		return nil, ErrExpired
	}
	if claims.IssuedAt != 0 && now.Add(v.leeway).Before(time.Unix(claims.IssuedAt, 0)) {
		return nil, ErrNotYetValid
	}
	return &claims, nil
}
