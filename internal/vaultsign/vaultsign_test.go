package vaultsign

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jcrexon/laplat/internal/audit"
	"github.com/jcrexon/laplat/pkg/contracts"
	"github.com/jcrexon/laplat/pkg/token"
)

// fakeTransit stands in for Vault's Transit sign endpoint: it signs the supplied
// input with priv and returns it in Vault's "vault:v1:<b64>" envelope.
func fakeTransit(t *testing.T, priv ed25519.PrivateKey, wantToken string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != wantToken {
			http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
			return
		}
		var req signRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		msg, err := base64.StdEncoding.DecodeString(req.Input)
		if err != nil {
			http.Error(w, "bad input", http.StatusBadRequest)
			return
		}
		sig := ed25519.Sign(priv, msg)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]string{"signature": "vault:v1:" + base64.StdEncoding.EncodeToString(sig)},
		})
	}))
}

// A token signed via the Vault-backed signer verifies under the matching public
// key — proving the request shape, signature parsing, and JWS assembly are all
// correct end to end.
func TestVaultSigner_RoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	srv := fakeTransit(t, priv, "s3cr3t")
	defer srv.Close()

	ks, err := New(Config{
		Address: srv.URL, Token: "s3cr3t", Mount: "transit", KeyName: "tok", KeyID: "k1",
	}, srv.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if ks.KeyID() != "k1" {
		t.Fatalf("KeyID = %q, want k1", ks.KeyID())
	}

	signer, err := token.NewSignerFromKeySigner(ks)
	if err != nil {
		t.Fatalf("NewSignerFromKeySigner: %v", err)
	}
	now := time.Now()
	claims := contracts.AccessTokenClaims{
		Issuer:        contracts.TokenIssuer,
		Subject:       "u-1",
		IssuedAt:      now.Unix(),
		ExpiresAt:     now.Add(5 * time.Minute).Unix(),
		SchemaVersion: contracts.AccessTokenSchemaVersion,
	}
	tok, err := signer.Sign(claims)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	v := token.NewVerifier(map[string]ed25519.PublicKey{"k1": pub})
	if _, err := v.Verify(tok); err != nil {
		t.Fatalf("Verify of Vault-signed token failed: %v", err)
	}
}

// An audit entry signed via the Vault backend verifies in VerifyChain under the
// matching public key — the tamper-evidence guarantee is unchanged by moving the
// key into Vault (same Ed25519 signature over the same entry hash, same verifier).
func TestVaultSigner_AuditChainVerifies(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	srv := fakeTransit(t, priv, "s3cr3t")
	defer srv.Close()

	ks, err := New(Config{
		Address: srv.URL, Token: "s3cr3t", Mount: "transit", KeyName: "audit", KeyID: "k1",
	}, srv.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	asig, err := audit.NewSignerFromKeySigner(ks)
	if err != nil {
		t.Fatalf("audit.NewSignerFromKeySigner: %v", err)
	}

	e := contracts.AuditEntry{
		SchemaVersion: contracts.AuditSchemaVersion,
		Seq:           1,
		OccurredAt:    1000,
		ActorID:       "mod-1",
		ActorRole:     contracts.AuditRoleModerator,
		Action:        contracts.ActionUserSuspended,
		TargetType:    "user",
		TargetID:      "u-1",
		Metadata:      []byte("{}"),
		PrevHash:      audit.GenesisHash(),
		SigningKeyID:  asig.KeyID(),
	}
	e.EntryHash = audit.Hash(e)
	sig, err := asig.Sign(e.EntryHash)
	if err != nil {
		t.Fatalf("audit Sign via vault: %v", err)
	}
	e.Signature = sig

	v := audit.NewVerifier(map[string]ed25519.PublicKey{"k1": pub})
	if err := v.VerifyChain([]contracts.AuditEntry{e}); err != nil {
		t.Fatalf("VerifyChain rejected a Vault-signed audit entry: %v", err)
	}
}

// A non-200 from Vault surfaces as an error rather than a bogus signature.
func TestVaultSigner_AuthError(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	srv := fakeTransit(t, priv, "right-token")
	defer srv.Close()

	ks, err := New(Config{
		Address: srv.URL, Token: "wrong-token", Mount: "transit", KeyName: "tok", KeyID: "k1",
	}, srv.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := ks.SignRaw([]byte("hello")); err == nil {
		t.Fatal("expected error on auth failure, got nil")
	}
}

func TestParseTransitSignature(t *testing.T) {
	raw := []byte("a 64-byte-ish signature placeholder ................")
	encoded := "vault:v3:" + base64.StdEncoding.EncodeToString(raw)
	got, err := parseTransitSignature(encoded)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if string(got) != string(raw) {
		t.Fatalf("decoded mismatch")
	}
	for _, bad := range []string{"", "novault", "vault:v1:", "vault:v1:!!notbase64!!"} {
		if _, err := parseTransitSignature(bad); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
}

func TestNew_Validation(t *testing.T) {
	cases := []Config{
		{Token: "t", KeyName: "k", KeyID: "id"},   // no address
		{Address: "x", KeyName: "k", KeyID: "id"}, // no token
		{Address: "x", Token: "t", KeyID: "id"},   // no key name
		{Address: "x", Token: "t", KeyName: "k"},  // no key id
	}
	for i, c := range cases {
		if _, err := New(c, nil); err == nil {
			t.Fatalf("case %d: expected validation error", i)
		}
	}
	// Mount defaults to "transit".
	s, err := New(Config{Address: "x", Token: "t", KeyName: "k", KeyID: "id"}, nil)
	if err != nil {
		t.Fatalf("valid config errored: %v", err)
	}
	if s.cfg.Mount != "transit" {
		t.Fatalf("mount default = %q, want transit", s.cfg.Mount)
	}
}
