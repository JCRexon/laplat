package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"
)

// env builds a getenv func from a map.
func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func seedB64(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(priv.Seed()), pub
}

func TestLoad_MinimalAppliesDefaultsAndSelfVerify(t *testing.T) {
	signing, pub := seedB64(t)
	cfg, err := Load(env(map[string]string{
		EnvDBDSN:      "postgres://x",
		EnvKid:        "kid-1",
		EnvSigningKey: signing,
	}))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.HTTPAddr != defaultHTTPAddr || cfg.AccessTTL != defaultAccessTTL || cfg.RefreshTTL != defaultRefreshTTL {
		t.Fatalf("defaults not applied: %+v", cfg)
	}
	// The signer's own public key must be in the verify set.
	got, ok := cfg.VerifyKeys["kid-1"]
	if !ok || string(got) != string(pub) {
		t.Fatalf("signer public key not self-registered for verification")
	}
}

func TestLoad_VaultSigningMakesEnvKeyOptional(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	// With Vault configured and no env signing key, Load succeeds as long as the
	// public key for the kid is published in the verify set.
	cfg, err := Load(env(map[string]string{
		EnvDBDSN:           "x",
		EnvKid:             "kid-1",
		EnvVaultAddr:       "https://127.0.0.1:8200",
		EnvVaultToken:      "tok",
		EnvVaultTransitKey: "laplat-signing",
		EnvVerifyKeys:      "kid-1:" + pubB64,
	}))
	if err != nil {
		t.Fatalf("load with vault: %v", err)
	}
	if cfg.Vault == nil || cfg.Vault.KeyName != "laplat-signing" || cfg.Vault.Mount != "transit" {
		t.Fatalf("vault config not parsed: %+v", cfg.Vault)
	}
	if cfg.SigningKey != nil {
		t.Fatalf("expected no in-process signing key under Vault")
	}

	// Without a published pubkey, Load still succeeds: the wiring layer fetches
	// the public key from Vault at startup, so config need not require it.
	cfg2, err := Load(env(map[string]string{
		EnvDBDSN:           "x",
		EnvKid:             "kid-1",
		EnvVaultAddr:       "https://127.0.0.1:8200",
		EnvVaultToken:      "tok",
		EnvVaultTransitKey: "laplat-signing",
	}))
	if err != nil {
		t.Fatalf("vault without published pubkey should load: %v", err)
	}
	if _, ok := cfg2.VerifyKeys["kid-1"]; ok {
		t.Fatal("did not expect a verify key for kid before runtime fetch")
	}

	// Partial Vault config (address without token/key) is an error.
	if _, err := Load(env(map[string]string{
		EnvDBDSN:     "x",
		EnvKid:       "kid-1",
		EnvVaultAddr: "https://127.0.0.1:8200",
	})); err == nil {
		t.Fatal("expected error for incomplete vault config")
	}
}

func TestLoad_MissingRequired(t *testing.T) {
	signing, _ := seedB64(t)
	full := map[string]string{EnvDBDSN: "x", EnvKid: "kid-1", EnvSigningKey: signing}
	for _, drop := range []string{EnvDBDSN, EnvKid, EnvSigningKey} {
		m := map[string]string{}
		for k, v := range full {
			if k != drop {
				m[k] = v
			}
		}
		if _, err := Load(env(m)); err == nil {
			t.Fatalf("expected error when %s is missing", drop)
		}
	}
}

func TestLoad_ParsesVerifyKeysAndTTLs(t *testing.T) {
	signing, _ := seedB64(t)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	other := base64.StdEncoding.EncodeToString(otherPub)

	cfg, err := Load(env(map[string]string{
		EnvDBDSN:      "x",
		EnvKid:        "kid-1",
		EnvSigningKey: signing,
		EnvVerifyKeys: "kid-2:" + other,
		EnvAccessTTL:  "5m",
		EnvRefreshTTL: "48h",
	}))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, ok := cfg.VerifyKeys["kid-2"]; !ok {
		t.Fatal("kid-2 not parsed")
	}
	if _, ok := cfg.VerifyKeys["kid-1"]; !ok {
		t.Fatal("signer kid-1 not auto-added")
	}
	if cfg.AccessTTL != 5*time.Minute || cfg.RefreshTTL != 48*time.Hour {
		t.Fatalf("TTLs = %s/%s", cfg.AccessTTL, cfg.RefreshTTL)
	}
}

func TestLoad_RejectsBadKeysAndDurations(t *testing.T) {
	signing, _ := seedB64(t)
	base := map[string]string{EnvDBDSN: "x", EnvKid: "kid-1", EnvSigningKey: signing}

	cases := []map[string]string{
		{EnvSigningKey: "!!!notbase64"},
		{EnvSigningKey: base64.StdEncoding.EncodeToString([]byte("short"))},
		{EnvVerifyKeys: "missingcolon"},
		{EnvVerifyKeys: "kid-2:" + base64.StdEncoding.EncodeToString([]byte("tooshort"))},
		{EnvAccessTTL: "notaduration"},
		{EnvRefreshTTL: "-5m"},
	}
	for _, override := range cases {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		for k, v := range override {
			m[k] = v
		}
		if _, err := Load(env(m)); err == nil {
			t.Fatalf("expected error for override %v", override)
		}
	}
}
