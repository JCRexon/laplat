// Package config loads the auth service's runtime configuration from the
// environment (CLAUDE.md: configuration via environment variables only — never
// committed secrets). Load takes a getenv function so it is unit-testable
// without touching the real process environment.
package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Environment variable names.
const (
	EnvHTTPAddr   = "LAPLAT_HTTP_ADDR"
	EnvDBDSN      = "LAPLAT_DB_DSN"
	EnvKid        = "LAPLAT_TOKEN_KID"
	EnvSigningKey = "LAPLAT_TOKEN_SIGNING_KEY" // base64: 32-byte seed or 64-byte key
	EnvVerifyKeys = "LAPLAT_TOKEN_VERIFY_KEYS" // "kid:base64pub,kid2:base64pub"
	EnvAccessTTL  = "LAPLAT_ACCESS_TTL"
	EnvRefreshTTL = "LAPLAT_REFRESH_TTL"

	// OIDC federated login (all optional; a provider is enabled only when its
	// full set of variables is present).
	EnvOIDCRedirectBase   = "LAPLAT_OIDC_REDIRECT_BASE" // e.g. https://laplat.example
	EnvGoogleClientID     = "LAPLAT_OIDC_GOOGLE_CLIENT_ID"
	EnvGoogleClientSecret = "LAPLAT_OIDC_GOOGLE_CLIENT_SECRET"
	EnvAppleClientID      = "LAPLAT_OIDC_APPLE_CLIENT_ID"
	EnvAppleTeamID        = "LAPLAT_OIDC_APPLE_TEAM_ID"
	EnvAppleKeyID         = "LAPLAT_OIDC_APPLE_KEY_ID"
	EnvApplePrivateKeyB64 = "LAPLAT_OIDC_APPLE_PRIVATE_KEY" // base64 of the .p8 PEM

	// Email-OTP login (optional). Enabled when host/port/from are all present.
	EnvSMTPHost     = "LAPLAT_SMTP_HOST"
	EnvSMTPPort     = "LAPLAT_SMTP_PORT"
	EnvSMTPFrom     = "LAPLAT_SMTP_FROM"
	EnvSMTPUsername = "LAPLAT_SMTP_USERNAME"
	EnvSMTPPassword = "LAPLAT_SMTP_PASSWORD"
)

// Defaults.
const (
	defaultHTTPAddr   = ":8080"
	defaultAccessTTL  = 15 * time.Minute
	defaultRefreshTTL = 30 * 24 * time.Hour
)

// Config is the resolved, validated runtime configuration.
type Config struct {
	HTTPAddr   string
	DBDSN      string
	Kid        string
	SigningKey ed25519.PrivateKey
	VerifyKeys map[string]ed25519.PublicKey
	AccessTTL  time.Duration
	RefreshTTL time.Duration
	OIDC       OIDCConfig
	SMTP       *SMTPConfig // nil unless email-OTP login is configured
}

// SMTPConfig is the (optional) email-OTP transport configuration.
type SMTPConfig struct {
	Host     string
	Port     string
	From     string
	Username string
	Password string
}

// OIDCConfig is the (optional) federated-login configuration. Google and/or
// Apple are configured independently; RedirectBase is required once either is.
// The well-known issuer/authorize/token/JWKS endpoints are not configurable —
// they are pinned in the wiring layer.
type OIDCConfig struct {
	RedirectBase string      // base URL the providers redirect back to
	Google       *GoogleOIDC // nil unless configured
	Apple        *AppleOIDC  // nil unless configured
}

// Enabled reports whether any provider is configured.
func (o OIDCConfig) Enabled() bool { return o.Google != nil || o.Apple != nil }

// GoogleOIDC is the Google client credentials.
type GoogleOIDC struct {
	ClientID     string
	ClientSecret string
}

// AppleOIDC is the Apple Sign-in credentials; PrivateKey is the decoded .p8 PEM.
type AppleOIDC struct {
	ClientID   string
	TeamID     string
	KeyID      string
	PrivateKey []byte
}

// Load reads and validates configuration. getenv is typically os.Getenv. The
// signer's own public key is always added to the verify set (deriving it from
// the signing key), so the issuer can always verify the tokens it mints even if
// the operator forgot to list it.
func Load(getenv func(string) string) (Config, error) {
	cfg := Config{
		HTTPAddr: orDefault(getenv(EnvHTTPAddr), defaultHTTPAddr),
		DBDSN:    getenv(EnvDBDSN),
		Kid:      getenv(EnvKid),
	}
	if cfg.DBDSN == "" {
		return Config{}, missing(EnvDBDSN)
	}
	if cfg.Kid == "" {
		return Config{}, missing(EnvKid)
	}

	signing, err := parseSigningKey(getenv(EnvSigningKey))
	if err != nil {
		return Config{}, err
	}
	cfg.SigningKey = signing

	verify, err := parseVerifyKeys(getenv(EnvVerifyKeys))
	if err != nil {
		return Config{}, err
	}
	// Ensure the signer can verify its own tokens.
	if _, ok := verify[cfg.Kid]; !ok {
		verify[cfg.Kid] = signing.Public().(ed25519.PublicKey)
	}
	cfg.VerifyKeys = verify

	if cfg.AccessTTL, err = parseDuration(getenv(EnvAccessTTL), defaultAccessTTL); err != nil {
		return Config{}, fmt.Errorf("%s: %w", EnvAccessTTL, err)
	}
	if cfg.RefreshTTL, err = parseDuration(getenv(EnvRefreshTTL), defaultRefreshTTL); err != nil {
		return Config{}, fmt.Errorf("%s: %w", EnvRefreshTTL, err)
	}

	if cfg.OIDC, err = parseOIDC(getenv); err != nil {
		return Config{}, err
	}
	if cfg.SMTP, err = parseSMTP(getenv); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// parseSMTP reads the optional email-OTP transport config. It is enabled only
// when host, port, and from are all present; a partial set is a hard error.
// Username/password are optional (some relays authenticate by IP).
func parseSMTP(getenv func(string) string) (*SMTPConfig, error) {
	host := strings.TrimSpace(getenv(EnvSMTPHost))
	port := strings.TrimSpace(getenv(EnvSMTPPort))
	from := strings.TrimSpace(getenv(EnvSMTPFrom))
	if host == "" && port == "" && from == "" {
		return nil, nil // email login disabled
	}
	if host == "" || port == "" || from == "" {
		return nil, fmt.Errorf("config: email login needs %s, %s and %s", EnvSMTPHost, EnvSMTPPort, EnvSMTPFrom)
	}
	return &SMTPConfig{
		Host:     host,
		Port:     port,
		From:     from,
		Username: strings.TrimSpace(getenv(EnvSMTPUsername)),
		Password: getenv(EnvSMTPPassword),
	}, nil
}

// parseOIDC reads the optional federated-login config. A provider is only
// enabled when its full credential set is present; a partial set is a hard
// error (a half-configured provider would silently never work). RedirectBase is
// required once any provider is enabled.
func parseOIDC(getenv func(string) string) (OIDCConfig, error) {
	var oc OIDCConfig
	oc.RedirectBase = strings.TrimRight(strings.TrimSpace(getenv(EnvOIDCRedirectBase)), "/")

	gID := strings.TrimSpace(getenv(EnvGoogleClientID))
	gSecret := strings.TrimSpace(getenv(EnvGoogleClientSecret))
	if gID != "" || gSecret != "" {
		if gID == "" || gSecret == "" {
			return OIDCConfig{}, fmt.Errorf("config: google oidc needs both %s and %s", EnvGoogleClientID, EnvGoogleClientSecret)
		}
		oc.Google = &GoogleOIDC{ClientID: gID, ClientSecret: gSecret}
	}

	aID := strings.TrimSpace(getenv(EnvAppleClientID))
	aTeam := strings.TrimSpace(getenv(EnvAppleTeamID))
	aKey := strings.TrimSpace(getenv(EnvAppleKeyID))
	aPriv := strings.TrimSpace(getenv(EnvApplePrivateKeyB64))
	if aID != "" || aTeam != "" || aKey != "" || aPriv != "" {
		if aID == "" || aTeam == "" || aKey == "" || aPriv == "" {
			return OIDCConfig{}, fmt.Errorf("config: apple oidc needs %s, %s, %s and %s", EnvAppleClientID, EnvAppleTeamID, EnvAppleKeyID, EnvApplePrivateKeyB64)
		}
		pem, err := base64.StdEncoding.DecodeString(aPriv)
		if err != nil {
			return OIDCConfig{}, fmt.Errorf("%s: not valid base64: %w", EnvApplePrivateKeyB64, err)
		}
		oc.Apple = &AppleOIDC{ClientID: aID, TeamID: aTeam, KeyID: aKey, PrivateKey: pem}
	}

	if oc.Enabled() && oc.RedirectBase == "" {
		return OIDCConfig{}, fmt.Errorf("config: %s is required when an OIDC provider is configured", EnvOIDCRedirectBase)
	}
	return oc, nil
}

// parseSigningKey accepts a base64-encoded Ed25519 seed (32 bytes) or full
// private key (64 bytes).
func parseSigningKey(s string) (ed25519.PrivateKey, error) {
	if s == "" {
		return nil, missing(EnvSigningKey)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("%s: not valid base64: %w", EnvSigningKey, err)
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	default:
		return nil, fmt.Errorf("%s: expected a 32-byte seed or 64-byte key, got %d bytes", EnvSigningKey, len(raw))
	}
}

// parseVerifyKeys parses "kid:base64pub,kid2:base64pub". Empty is allowed (the
// signer's own key is added by Load).
func parseVerifyKeys(s string) (map[string]ed25519.PublicKey, error) {
	keys := map[string]ed25519.PublicKey{}
	s = strings.TrimSpace(s)
	if s == "" {
		return keys, nil
	}
	for _, pair := range strings.Split(s, ",") {
		kid, b64, ok := strings.Cut(strings.TrimSpace(pair), ":")
		if !ok || kid == "" {
			return nil, fmt.Errorf("%s: malformed entry %q (want kid:base64)", EnvVerifyKeys, pair)
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
		if err != nil {
			return nil, fmt.Errorf("%s: kid %q not valid base64: %w", EnvVerifyKeys, kid, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%s: kid %q public key must be %d bytes, got %d", EnvVerifyKeys, kid, ed25519.PublicKeySize, len(raw))
		}
		keys[kid] = ed25519.PublicKey(raw)
	}
	return keys, nil
}

func parseDuration(s string, def time.Duration) (time.Duration, error) {
	if strings.TrimSpace(s) == "" {
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, errors.New("must be positive")
	}
	return d, nil
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func missing(name string) error { return fmt.Errorf("config: %s is required", name) }
