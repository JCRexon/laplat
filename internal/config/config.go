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
	"strconv"
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

	// Per-client rate limiting (requests/sec and burst). Defaults apply when unset.
	EnvRateLimitRPS   = "LAPLAT_RATE_LIMIT_RPS"
	EnvRateLimitBurst = "LAPLAT_RATE_LIMIT_BURST"

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

	// Phone-OTP login + phone_verified tier (optional). Enabled when a provider
	// is selected via LAPLAT_SMS_PROVIDER (generic|twilio|vonage).
	EnvSMSProvider        = "LAPLAT_SMS_PROVIDER"
	EnvSMSFrom            = "LAPLAT_SMS_FROM"
	EnvSMSGatewayURL      = "LAPLAT_SMS_GATEWAY_URL"   // generic
	EnvSMSGatewayToken    = "LAPLAT_SMS_GATEWAY_TOKEN" // generic (optional bearer)
	EnvSMSTwilioSID       = "LAPLAT_SMS_TWILIO_ACCOUNT_SID"
	EnvSMSTwilioAuthToken = "LAPLAT_SMS_TWILIO_AUTH_TOKEN"
	EnvSMSVonageKey       = "LAPLAT_SMS_VONAGE_API_KEY"
	EnvSMSVonageSecret    = "LAPLAT_SMS_VONAGE_API_SECRET"

	// Live sessions / LiveKit (optional). Enabled when all three are present.
	EnvLiveKitAPIKey    = "LAPLAT_LIVEKIT_API_KEY"
	EnvLiveKitAPISecret = "LAPLAT_LIVEKIT_API_SECRET"
	EnvLiveKitURL       = "LAPLAT_LIVEKIT_URL" // wss://... media server

	// VN eKYC vendor (optional). Enables the 'verified' tier for region VN when
	// the vendor URL and webhook secret are present.
	EnvEKYCVendorURL     = "LAPLAT_EKYC_VENDOR_URL"
	EnvEKYCVendorToken   = "LAPLAT_EKYC_VENDOR_TOKEN"
	EnvEKYCWebhookSecret = "LAPLAT_EKYC_WEBHOOK_SECRET"
)

// Defaults.
const (
	defaultHTTPAddr       = ":8080"
	defaultAccessTTL      = 15 * time.Minute
	defaultRefreshTTL     = 30 * 24 * time.Hour
	defaultRateLimitRPS   = 20
	defaultRateLimitBurst = 40
)

// Config is the resolved, validated runtime configuration.
type Config struct {
	HTTPAddr       string
	DBDSN          string
	Kid            string
	SigningKey     ed25519.PrivateKey
	VerifyKeys     map[string]ed25519.PublicKey
	AccessTTL      time.Duration
	RefreshTTL     time.Duration
	RateLimitRPS   float64
	RateLimitBurst int
	OIDC           OIDCConfig
	SMTP           *SMTPConfig    // nil unless email-OTP login is configured
	SMS            *SMSConfig     // nil unless phone-OTP login is configured
	LiveKit        *LiveKitConfig // nil unless live sessions are configured
	EKYC           *EKYCConfig    // nil unless the VN eKYC vendor is configured
}

// EKYCConfig is the (optional) VN adult-verification vendor configuration.
type EKYCConfig struct {
	VendorURL     string
	VendorToken   string
	WebhookSecret string
}

// LiveKitConfig is the (optional) live-session media configuration.
type LiveKitConfig struct {
	APIKey    string
	APISecret string
	URL       string
}

// SMTPConfig is the (optional) email-OTP transport configuration.
type SMTPConfig struct {
	Host     string
	Port     string
	From     string
	Username string
	Password string
}

// SMSConfig is the (optional) phone-OTP gateway configuration. Provider selects
// the transport; the relevant fields are validated for that provider.
type SMSConfig struct {
	Provider string // "generic" | "twilio" | "vonage"
	From     string

	// generic
	GatewayURL   string
	GatewayToken string

	// twilio
	TwilioSID       string
	TwilioAuthToken string

	// vonage
	VonageKey    string
	VonageSecret string
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

	if cfg.RateLimitRPS, err = parsePositiveFloat(getenv(EnvRateLimitRPS), defaultRateLimitRPS); err != nil {
		return Config{}, fmt.Errorf("%s: %w", EnvRateLimitRPS, err)
	}
	if cfg.RateLimitBurst, err = parsePositiveInt(getenv(EnvRateLimitBurst), defaultRateLimitBurst); err != nil {
		return Config{}, fmt.Errorf("%s: %w", EnvRateLimitBurst, err)
	}

	if cfg.OIDC, err = parseOIDC(getenv); err != nil {
		return Config{}, err
	}
	if cfg.SMTP, err = parseSMTP(getenv); err != nil {
		return Config{}, err
	}
	if cfg.SMS, err = parseSMS(getenv); err != nil {
		return Config{}, err
	}
	if cfg.LiveKit, err = parseLiveKit(getenv); err != nil {
		return Config{}, err
	}
	if cfg.EKYC, err = parseEKYC(getenv); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// parseEKYC reads the optional VN eKYC vendor config. Enabled when the vendor
// URL or webhook secret is set; both are then required (the token is optional).
func parseEKYC(getenv func(string) string) (*EKYCConfig, error) {
	url := strings.TrimSpace(getenv(EnvEKYCVendorURL))
	secret := strings.TrimSpace(getenv(EnvEKYCWebhookSecret))
	if url == "" && secret == "" {
		return nil, nil // eKYC disabled
	}
	if url == "" || secret == "" {
		return nil, fmt.Errorf("config: eKYC needs both %s and %s", EnvEKYCVendorURL, EnvEKYCWebhookSecret)
	}
	return &EKYCConfig{
		VendorURL:     url,
		VendorToken:   strings.TrimSpace(getenv(EnvEKYCVendorToken)),
		WebhookSecret: secret,
	}, nil
}

// parseLiveKit reads the optional live-session config. Enabled when any of the
// three vars is set; all three are then required.
func parseLiveKit(getenv func(string) string) (*LiveKitConfig, error) {
	key := strings.TrimSpace(getenv(EnvLiveKitAPIKey))
	secret := strings.TrimSpace(getenv(EnvLiveKitAPISecret))
	url := strings.TrimSpace(getenv(EnvLiveKitURL))
	if key == "" && secret == "" && url == "" {
		return nil, nil // live sessions disabled
	}
	if key == "" || secret == "" || url == "" {
		return nil, fmt.Errorf("config: live sessions need %s, %s and %s", EnvLiveKitAPIKey, EnvLiveKitAPISecret, EnvLiveKitURL)
	}
	return &LiveKitConfig{APIKey: key, APISecret: secret, URL: url}, nil
}

// parseSMS reads the optional phone-OTP config. Enabled when LAPLAT_SMS_PROVIDER
// is set; the selected provider's required fields are then validated.
func parseSMS(getenv func(string) string) (*SMSConfig, error) {
	provider := strings.TrimSpace(getenv(EnvSMSProvider))
	if provider == "" {
		return nil, nil // phone login disabled
	}
	sc := &SMSConfig{Provider: provider, From: strings.TrimSpace(getenv(EnvSMSFrom))}
	switch provider {
	case "generic":
		sc.GatewayURL = strings.TrimSpace(getenv(EnvSMSGatewayURL))
		sc.GatewayToken = getenv(EnvSMSGatewayToken)
		if sc.GatewayURL == "" {
			return nil, fmt.Errorf("config: sms provider generic needs %s", EnvSMSGatewayURL)
		}
	case "twilio":
		sc.TwilioSID = strings.TrimSpace(getenv(EnvSMSTwilioSID))
		sc.TwilioAuthToken = strings.TrimSpace(getenv(EnvSMSTwilioAuthToken))
		if sc.TwilioSID == "" || sc.TwilioAuthToken == "" || sc.From == "" {
			return nil, fmt.Errorf("config: sms provider twilio needs %s, %s and %s", EnvSMSTwilioSID, EnvSMSTwilioAuthToken, EnvSMSFrom)
		}
	case "vonage":
		sc.VonageKey = strings.TrimSpace(getenv(EnvSMSVonageKey))
		sc.VonageSecret = strings.TrimSpace(getenv(EnvSMSVonageSecret))
		if sc.VonageKey == "" || sc.VonageSecret == "" || sc.From == "" {
			return nil, fmt.Errorf("config: sms provider vonage needs %s, %s and %s", EnvSMSVonageKey, EnvSMSVonageSecret, EnvSMSFrom)
		}
	default:
		return nil, fmt.Errorf("config: unknown %s %q (want generic|twilio|vonage)", EnvSMSProvider, provider)
	}
	return sc, nil
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

func parsePositiveFloat(s string, def float64) (float64, error) {
	if strings.TrimSpace(s) == "" {
		return def, nil
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, err
	}
	if v <= 0 {
		return 0, errors.New("must be positive")
	}
	return v, nil
}

func parsePositiveInt(s string, def int) (int, error) {
	if strings.TrimSpace(s) == "" {
		return def, nil
	}
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, err
	}
	if v <= 0 {
		return 0, errors.New("must be positive")
	}
	return v, nil
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func missing(name string) error { return fmt.Errorf("config: %s is required", name) }
