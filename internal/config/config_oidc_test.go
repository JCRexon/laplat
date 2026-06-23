package config

import (
	"encoding/base64"
	"testing"
)

// base env with the always-required fields, so tests can layer OIDC vars on top.
func baseEnv() map[string]string {
	seed := base64.StdEncoding.EncodeToString(make([]byte, 32))
	return map[string]string{
		EnvDBDSN:      "postgres://localhost/db",
		EnvKid:        "kid-1",
		EnvSigningKey: seed,
	}
}

func getenvFrom(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoad_OIDCDisabledByDefault(t *testing.T) {
	cfg, err := Load(getenvFrom(baseEnv()))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OIDC.Enabled() {
		t.Fatal("OIDC should be disabled with no provider env")
	}
}

func TestLoad_GoogleConfigured(t *testing.T) {
	env := baseEnv()
	env[EnvOIDCRedirectBase] = "https://laplat.example/"
	env[EnvGoogleClientID] = "gid"
	env[EnvGoogleClientSecret] = "gsecret"

	cfg, err := Load(getenvFrom(env))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OIDC.Google == nil || cfg.OIDC.Google.ClientID != "gid" {
		t.Fatalf("google not parsed: %+v", cfg.OIDC.Google)
	}
	if cfg.OIDC.Apple != nil {
		t.Fatal("apple should be nil")
	}
	if cfg.OIDC.RedirectBase != "https://laplat.example" { // trailing slash trimmed
		t.Fatalf("redirect base = %q", cfg.OIDC.RedirectBase)
	}
}

func TestLoad_AppleConfiguredDecodesKey(t *testing.T) {
	env := baseEnv()
	env[EnvOIDCRedirectBase] = "https://laplat.example"
	env[EnvAppleClientID] = "com.laplat.app"
	env[EnvAppleTeamID] = "TEAM"
	env[EnvAppleKeyID] = "KEY"
	env[EnvApplePrivateKeyB64] = base64.StdEncoding.EncodeToString([]byte("-----PEM-----"))

	cfg, err := Load(getenvFrom(env))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OIDC.Apple == nil || string(cfg.OIDC.Apple.PrivateKey) != "-----PEM-----" {
		t.Fatalf("apple key not decoded: %+v", cfg.OIDC.Apple)
	}
}

func TestLoad_OIDCRejectsPartialAndMissingRedirect(t *testing.T) {
	cases := []struct {
		name string
		mut  func(map[string]string)
	}{
		{"partial google", func(e map[string]string) {
			e[EnvOIDCRedirectBase] = "https://x"
			e[EnvGoogleClientID] = "gid" // secret missing
		}},
		{"partial apple", func(e map[string]string) {
			e[EnvOIDCRedirectBase] = "https://x"
			e[EnvAppleClientID] = "a"
			e[EnvAppleTeamID] = "t" // key id + private key missing
		}},
		{"apple bad base64", func(e map[string]string) {
			e[EnvOIDCRedirectBase] = "https://x"
			e[EnvAppleClientID] = "a"
			e[EnvAppleTeamID] = "t"
			e[EnvAppleKeyID] = "k"
			e[EnvApplePrivateKeyB64] = "!!!not base64!!!"
		}},
		{"enabled without redirect base", func(e map[string]string) {
			e[EnvGoogleClientID] = "gid"
			e[EnvGoogleClientSecret] = "gsecret"
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := baseEnv()
			c.mut(env)
			if _, err := Load(getenvFrom(env)); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}
