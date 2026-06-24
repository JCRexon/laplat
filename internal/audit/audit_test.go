package audit_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/jcrexon/laplat/internal/audit"
	"github.com/jcrexon/laplat/pkg/contracts"
)

func newSignerVerifier(t *testing.T) (*audit.Signer, *audit.Verifier) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := audit.NewSigner("k1", priv)
	if err != nil {
		t.Fatal(err)
	}
	return s, audit.NewVerifier(map[string]ed25519.PublicKey{"k1": pub})
}

// mkEntry builds a signed entry chained to prev.
func mkEntry(s *audit.Signer, seq int64, prev []byte, action contracts.AuditAction) contracts.AuditEntry {
	e := contracts.AuditEntry{
		SchemaVersion: contracts.AuditSchemaVersion,
		Seq:           seq,
		OccurredAt:    1000 + seq,
		ActorID:       "mod-1",
		ActorRole:     contracts.AuditRoleModerator,
		Action:        action,
		TargetType:    "user",
		TargetID:      "u-1",
		Metadata:      []byte("{}"),
		PrevHash:      prev,
		SigningKeyID:  s.KeyID(),
	}
	e.EntryHash = audit.Hash(e)
	e.Signature = s.Sign(e.EntryHash)
	return e
}

// A well-formed chain verifies.
func TestVerifyChain_OK(t *testing.T) {
	s, v := newSignerVerifier(t)
	e1 := mkEntry(s, 1, audit.GenesisHash(), contracts.ActionUserSuspended)
	e2 := mkEntry(s, 2, e1.EntryHash, contracts.ActionUserReinstated)
	if err := v.VerifyChain([]contracts.AuditEntry{e1, e2}); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if err := v.VerifyChain(nil); err != nil {
		t.Fatalf("empty chain should verify: %v", err)
	}
}

// Editing a signed field is caught by the recomputed-hash check.
func TestVerifyChain_DetectsFieldTamper(t *testing.T) {
	s, v := newSignerVerifier(t)
	e := mkEntry(s, 1, audit.GenesisHash(), contracts.ActionUserSuspended)
	e.TargetID = "someone-else" // alter after signing
	if err := v.VerifyChain([]contracts.AuditEntry{e}); err == nil {
		t.Fatal("expected tamper detection, got nil")
	}
}

// Re-linking an entry to the wrong predecessor breaks the chain.
func TestVerifyChain_DetectsBrokenLink(t *testing.T) {
	s, v := newSignerVerifier(t)
	e1 := mkEntry(s, 1, audit.GenesisHash(), contracts.ActionUserSuspended)
	e2 := mkEntry(s, 2, []byte("not-e1-hash-............................"), contracts.ActionUserReinstated)
	if err := v.VerifyChain([]contracts.AuditEntry{e1, e2}); err == nil {
		t.Fatal("expected broken-chain error, got nil")
	}
}

// A forged signature fails verification.
func TestVerifyChain_DetectsBadSignature(t *testing.T) {
	s, v := newSignerVerifier(t)
	e := mkEntry(s, 1, audit.GenesisHash(), contracts.ActionUserSuspended)
	e.Signature[0] ^= 0xff
	if err := v.VerifyChain([]contracts.AuditEntry{e}); err == nil {
		t.Fatal("expected bad-signature error, got nil")
	}
}

// An entry signed by an unknown key id is rejected.
func TestVerifyChain_UnknownKey(t *testing.T) {
	s, _ := newSignerVerifier(t)
	v := audit.NewVerifier(map[string]ed25519.PublicKey{}) // empty key set
	e := mkEntry(s, 1, audit.GenesisHash(), contracts.ActionUserSuspended)
	if err := v.VerifyChain([]contracts.AuditEntry{e}); err == nil {
		t.Fatal("expected unknown-key error, got nil")
	}
}

func TestNewSigner_Validation(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := audit.NewSigner("", priv); err == nil {
		t.Fatal("empty kid should error")
	}
	if _, err := audit.NewSigner("k1", ed25519.PrivateKey{1, 2, 3}); err == nil {
		t.Fatal("short key should error")
	}
}
