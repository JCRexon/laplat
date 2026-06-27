// Package signing defines the Ed25519 signing seam shared by the token minter
// and the audit/consent ledgers. Callers depend only on KeySigner, so the
// private key can live in-process (LocalKeySigner, the MVP default) or behind a
// remote signer such as Vault Transit or a PKCS#11 HSM — in which case the key
// never enters the process. This package is deliberately standard-library only:
// it is imported by pkg/token, which must stay dependency-free (A-1 / E-2).
package signing

import (
	"crypto/ed25519"
	"errors"
)

// KeySigner produces a raw Ed25519 signature over a message, identified by a
// stable key id. The id is stamped into each token/entry so verification
// survives key rotation. SignRaw may fail (a remote signer is a network call),
// so every caller must handle the error rather than assume success.
type KeySigner interface {
	KeyID() string
	SignRaw(message []byte) ([]byte, error)
}

// LocalKeySigner signs in-process with an Ed25519 private key held in memory.
// This is the default backend; production can swap in a remote KeySigner so the
// key never exists in the process address space.
type LocalKeySigner struct {
	kid string
	key ed25519.PrivateKey
}

// NewLocalKeySigner validates the key id and key.
func NewLocalKeySigner(kid string, key ed25519.PrivateKey) (*LocalKeySigner, error) {
	if kid == "" {
		return nil, errors.New("signing: key id required")
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("signing: invalid ed25519 private key")
	}
	return &LocalKeySigner{kid: kid, key: key}, nil
}

// KeyID returns the signer's key id.
func (l *LocalKeySigner) KeyID() string { return l.kid }

// SignRaw signs the message with the in-process key. It never returns an error.
func (l *LocalKeySigner) SignRaw(message []byte) ([]byte, error) {
	return ed25519.Sign(l.key, message), nil
}
