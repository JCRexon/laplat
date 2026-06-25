package consent_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/jcrexon/laplat/internal/consent"
	"github.com/jcrexon/laplat/pkg/contracts"
)

func newKeys(t *testing.T) (ed25519.PrivateKey, *consent.Verifier) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, consent.NewVerifier(map[string]ed25519.PublicKey{"k1": pub})
}

// mkRecord builds a signed consent record chained to prev. The server signs the
// canonical SignedPayload (which includes PrevHash and Granted), so VerifyChain
// catches any later alteration or re-linking.
func mkRecord(priv ed25519.PrivateKey, id string, prev []byte, granted bool) contracts.ConsentRecord {
	r := contracts.ConsentRecord{
		SchemaVersion: contracts.ConsentSchemaVersion,
		ID:            id,
		PrevHash:      prev,
		SessionID:     "sess-1",
		SubjectID:     "u-1",
		Purpose:       contracts.ConsentPurposeSessionRecording,
		Granted:       granted,
		GrantedAt:     1000,
		SigningKeyID:  "k1",
	}
	r.Signature = ed25519.Sign(priv, r.SignedPayload())
	return r
}

// A well-formed grant→withdrawal chain verifies; an empty ledger verifies.
func TestVerifyChain_OK(t *testing.T) {
	priv, v := newKeys(t)
	r1 := mkRecord(priv, "rec-1", consent.GenesisHash(), true)
	r2 := mkRecord(priv, "rec-2", r1.Hash(), false)
	if err := v.VerifyChain([]contracts.ConsentRecord{r1, r2}); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if err := v.VerifyChain(nil); err != nil {
		t.Fatalf("empty chain should verify: %v", err)
	}
}

// Flipping Granted after signing must be caught — the consent boolean is signed.
func TestVerifyChain_DetectsGrantedTamper(t *testing.T) {
	priv, v := newKeys(t)
	r := mkRecord(priv, "rec-1", consent.GenesisHash(), true)
	r.Granted = false // forge a withdrawal into a grant's slot
	if err := v.VerifyChain([]contracts.ConsentRecord{r}); err == nil {
		t.Fatal("expected tamper detection, got nil")
	}
}

// Re-linking a record to the wrong predecessor breaks the chain.
func TestVerifyChain_DetectsBrokenLink(t *testing.T) {
	priv, v := newKeys(t)
	r1 := mkRecord(priv, "rec-1", consent.GenesisHash(), true)
	r2 := mkRecord(priv, "rec-2", []byte("not-r1-hash-............................"), false)
	if err := v.VerifyChain([]contracts.ConsentRecord{r1, r2}); err == nil {
		t.Fatal("expected broken-chain error, got nil")
	}
}

// A forged signature fails verification.
func TestVerifyChain_DetectsBadSignature(t *testing.T) {
	priv, v := newKeys(t)
	r := mkRecord(priv, "rec-1", consent.GenesisHash(), true)
	r.Signature[0] ^= 0xff
	if err := v.VerifyChain([]contracts.ConsentRecord{r}); err == nil {
		t.Fatal("expected bad-signature error, got nil")
	}
}

// A record signed by an unknown key id is rejected.
func TestVerifyChain_UnknownKey(t *testing.T) {
	priv, _ := newKeys(t)
	v := consent.NewVerifier(map[string]ed25519.PublicKey{}) // empty key set
	r := mkRecord(priv, "rec-1", consent.GenesisHash(), true)
	if err := v.VerifyChain([]contracts.ConsentRecord{r}); err == nil {
		t.Fatal("expected unknown-key error, got nil")
	}
}
