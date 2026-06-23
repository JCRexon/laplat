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
	return cfg, nil
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
