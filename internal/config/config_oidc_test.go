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

func TestLoad_ZaloConfigured(t *testing.T) {
	env := baseEnv()
	env[EnvOIDCRedirectBase] = "https://laplat.example"
	env[EnvZaloAppID] = "zapp"
	env[EnvZaloAppSecret] = "zsecret"
	cfg, err := Load(getenvFrom(env))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OIDC.Zalo == nil || cfg.OIDC.Zalo.AppID != "zapp" {
		t.Fatalf("zalo not parsed: %+v", cfg.OIDC.Zalo)
	}
	if !cfg.OIDC.Enabled() {
		t.Fatal("OIDC should be enabled with Zalo")
	}
}

func TestLoad_ZaloPartialRejected(t *testing.T) {
	env := baseEnv()
	env[EnvOIDCRedirectBase] = "https://x"
	env[EnvZaloAppID] = "zapp" // secret missing
	if _, err := Load(getenvFrom(env)); err == nil {
		t.Fatal("expected error for partial Zalo config")
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

func TestLoad_SMTPDisabledByDefault(t *testing.T) {
	cfg, err := Load(getenvFrom(baseEnv()))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SMTP != nil {
		t.Fatal("SMTP should be nil with no email env")
	}
}

func TestLoad_SMTPConfigured(t *testing.T) {
	env := baseEnv()
	env[EnvSMTPHost] = "smtp.example.com"
	env[EnvSMTPPort] = "587"
	env[EnvSMTPFrom] = "noreply@laplat.example"
	env[EnvSMTPUsername] = "u"
	env[EnvSMTPPassword] = "p"

	cfg, err := Load(getenvFrom(env))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SMTP == nil || cfg.SMTP.Host != "smtp.example.com" || cfg.SMTP.From != "noreply@laplat.example" {
		t.Fatalf("smtp not parsed: %+v", cfg.SMTP)
	}
}

func TestLoad_SMTPRejectsPartial(t *testing.T) {
	env := baseEnv()
	env[EnvSMTPHost] = "smtp.example.com" // port + from missing
	if _, err := Load(getenvFrom(env)); err == nil {
		t.Fatal("expected error for partial SMTP config")
	}
}

func TestLoad_SMSDisabledByDefault(t *testing.T) {
	cfg, err := Load(getenvFrom(baseEnv()))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SMS != nil {
		t.Fatal("SMS should be nil with no provider env")
	}
}

func TestLoad_SMSProviders(t *testing.T) {
	t.Run("twilio", func(t *testing.T) {
		env := baseEnv()
		env[EnvSMSProvider] = "twilio"
		env[EnvSMSFrom] = "+15550000000"
		env[EnvSMSTwilioSID] = "AC1"
		env[EnvSMSTwilioAuthToken] = "tok"
		cfg, err := Load(getenvFrom(env))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.SMS == nil || cfg.SMS.Provider != "twilio" || cfg.SMS.TwilioSID != "AC1" {
			t.Fatalf("twilio not parsed: %+v", cfg.SMS)
		}
	})
	t.Run("generic", func(t *testing.T) {
		env := baseEnv()
		env[EnvSMSProvider] = "generic"
		env[EnvSMSGatewayURL] = "https://sms.example/send"
		cfg, err := Load(getenvFrom(env))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.SMS == nil || cfg.SMS.GatewayURL == "" {
			t.Fatalf("generic not parsed: %+v", cfg.SMS)
		}
	})
}

func TestLoad_SMSRejectsBadConfig(t *testing.T) {
	cases := map[string]func(map[string]string){
		"unknown provider": func(e map[string]string) { e[EnvSMSProvider] = "nope" },
		"twilio missing creds": func(e map[string]string) {
			e[EnvSMSProvider] = "twilio"
			e[EnvSMSFrom] = "+1555" // sid/token missing
		},
		"vonage missing from": func(e map[string]string) {
			e[EnvSMSProvider] = "vonage"
			e[EnvSMSVonageKey] = "k"
			e[EnvSMSVonageSecret] = "s" // From missing
		},
		"generic missing url": func(e map[string]string) { e[EnvSMSProvider] = "generic" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			env := baseEnv()
			mut(env)
			if _, err := Load(getenvFrom(env)); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestLoad_LiveKit(t *testing.T) {
	t.Run("disabled by default", func(t *testing.T) {
		cfg, err := Load(getenvFrom(baseEnv()))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.LiveKit != nil {
			t.Fatal("LiveKit should be nil with no env")
		}
	})
	t.Run("full", func(t *testing.T) {
		env := baseEnv()
		env[EnvLiveKitAPIKey] = "k"
		env[EnvLiveKitAPISecret] = "s"
		env[EnvLiveKitURL] = "wss://media.example"
		cfg, err := Load(getenvFrom(env))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.LiveKit == nil || cfg.LiveKit.URL != "wss://media.example" {
			t.Fatalf("livekit not parsed: %+v", cfg.LiveKit)
		}
	})
	t.Run("partial errors", func(t *testing.T) {
		env := baseEnv()
		env[EnvLiveKitAPIKey] = "k" // secret + url missing
		if _, err := Load(getenvFrom(env)); err == nil {
			t.Fatal("expected error for partial LiveKit config")
		}
	})
}

func TestLoad_EKYC(t *testing.T) {
	t.Run("disabled by default", func(t *testing.T) {
		cfg, _ := Load(getenvFrom(baseEnv()))
		if cfg.EKYC != nil {
			t.Fatal("eKYC should be nil by default")
		}
	})
	t.Run("full", func(t *testing.T) {
		env := baseEnv()
		env[EnvEKYCVendorURL] = "https://kyc.example/create"
		env[EnvEKYCWebhookSecret] = "whsecret"
		cfg, err := Load(getenvFrom(env))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.EKYC == nil || cfg.EKYC.WebhookSecret != "whsecret" {
			t.Fatalf("eKYC not parsed: %+v", cfg.EKYC)
		}
	})
	t.Run("partial errors", func(t *testing.T) {
		env := baseEnv()
		env[EnvEKYCVendorURL] = "https://kyc.example/create" // secret missing
		if _, err := Load(getenvFrom(env)); err == nil {
			t.Fatal("expected error for partial eKYC config")
		}
	})
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
