package signing

import (
	"crypto/ed25519"
	"testing"
)

func TestLocalKeySigner_SignsVerifiably(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	ks, err := NewLocalKeySigner("k1", priv)
	if err != nil {
		t.Fatalf("NewLocalKeySigner: %v", err)
	}
	if ks.KeyID() != "k1" {
		t.Fatalf("KeyID = %q, want k1", ks.KeyID())
	}
	msg := []byte("sign me")
	sig, err := ks.SignRaw(msg)
	if err != nil {
		t.Fatalf("SignRaw: %v", err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("signature did not verify under the public key")
	}
}

func TestNewLocalKeySigner_Validation(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	if _, err := NewLocalKeySigner("", priv); err == nil {
		t.Fatal("expected error for empty kid")
	}
	if _, err := NewLocalKeySigner("k1", ed25519.PrivateKey([]byte("too short"))); err == nil {
		t.Fatal("expected error for invalid key")
	}
}
