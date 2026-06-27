// Package audit provides the tamper-evidence primitives for the audit log: the
// entry hash, the ed25519 server signature, and chain verification. The append
// itself (which is transactional, alongside the action it records) lives in the
// store; this package holds the pure crypto so it can be unit-tested without a
// database and reused by an offline verifier. See AUDIT.md.
package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/jcrexon/laplat/pkg/contracts"
	"github.com/jcrexon/laplat/pkg/signing"
)

// GenesisHash is the prev_hash of the first entry: AuditHashLen zero bytes.
func GenesisHash() []byte { return make([]byte, contracts.AuditHashLen) }

// Hash is the entry hash: SHA-256 over the entry's canonical SignedPayload
// (which includes PrevHash, so the hash chains).
func Hash(e contracts.AuditEntry) []byte {
	sum := sha256.Sum256(e.SignedPayload())
	return sum[:]
}

// Signer produces the server signature over an entry hash. It delegates the raw
// Ed25519 signature to a signing.KeySigner, so the same key material that backs
// token signing can live in-process or behind a remote signer (Vault/HSM).
type Signer struct {
	ks signing.KeySigner
}

// NewSigner wraps an in-process ed25519 key with the key id stamped into each
// entry (so verification survives key rotation). Retained as the convenience
// constructor for the env-var key path and tests; for a remote backend use
// NewSignerFromKeySigner.
func NewSigner(kid string, key ed25519.PrivateKey) (*Signer, error) {
	ks, err := signing.NewLocalKeySigner(kid, key)
	if err != nil {
		return nil, err
	}
	return &Signer{ks: ks}, nil
}

// NewSignerFromKeySigner builds a Signer over any KeySigner (e.g. Vault Transit).
func NewSignerFromKeySigner(ks signing.KeySigner) (*Signer, error) {
	if ks == nil {
		return nil, errors.New("audit: key signer required")
	}
	if ks.KeyID() == "" {
		return nil, errors.New("audit: signing key id required")
	}
	return &Signer{ks: ks}, nil
}

// KeyID returns the signer's key id.
func (s *Signer) KeyID() string { return s.ks.KeyID() }

// Sign signs an entry hash. It can fail when backed by a remote signer.
func (s *Signer) Sign(hash []byte) ([]byte, error) { return s.ks.SignRaw(hash) }

// Verifier checks an entry chain against a set of public keys, keyed by id so
// rotated-out keys still verify their historical entries.
type Verifier struct {
	keys map[string]ed25519.PublicKey
}

// NewVerifier builds a verifier over the given key set.
func NewVerifier(keys map[string]ed25519.PublicKey) *Verifier {
	return &Verifier{keys: keys}
}

// VerifyChain verifies entries in seq order: each PrevHash must equal the prior
// EntryHash (chain intact), each EntryHash must equal the recomputed hash (no
// field altered), and each signature must verify under its key id. A failure
// names the offending seq so a break is locatable. An empty slice verifies.
func (v *Verifier) VerifyChain(entries []contracts.AuditEntry) error {
	prev := GenesisHash()
	for _, e := range entries {
		if !bytes.Equal(e.PrevHash, prev) {
			return fmt.Errorf("audit: broken chain at seq %d (prev_hash mismatch)", e.Seq)
		}
		if want := Hash(e); !bytes.Equal(e.EntryHash, want) {
			return fmt.Errorf("audit: tampered entry at seq %d (hash mismatch)", e.Seq)
		}
		pub, ok := v.keys[e.SigningKeyID]
		if !ok {
			return fmt.Errorf("audit: unknown signing key %q at seq %d", e.SigningKeyID, e.Seq)
		}
		if !ed25519.Verify(pub, e.EntryHash, e.Signature) {
			return fmt.Errorf("audit: bad signature at seq %d", e.Seq)
		}
		prev = e.EntryHash
	}
	return nil
}
