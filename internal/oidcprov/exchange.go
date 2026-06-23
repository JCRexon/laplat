// Package oidcprov holds the production network adapters for federated login:
// concrete token-endpoint Exchangers for Google and Apple. They satisfy
// auth.Exchanger structurally (Exchange(ctx, code, redirectURI) (string, error))
// so the auth package never imports a provider SDK or HTTP client. Google uses a
// static client secret; Apple's "secret" is a short-lived ES256 JWT we sign from
// the team's .p8 key.
package oidcprov

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Well-known token endpoints.
const (
	GoogleTokenURL = "https://oauth2.googleapis.com/token"
	AppleTokenURL  = "https://appleid.apple.com/auth/token"
	appleAudience  = "https://appleid.apple.com"
)

var b64 = base64.RawURLEncoding

// TokenExchanger exchanges an authorization code for an ID token at one
// provider's token endpoint.
type TokenExchanger struct {
	tokenURL string
	clientID string
	secret   func() (string, error) // resolved per exchange (Apple's rotates)
	client   *http.Client
}

func httpClient(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// NewGoogle builds the Google exchanger with a static client secret.
func NewGoogle(clientID, clientSecret string, client *http.Client) *TokenExchanger {
	return &TokenExchanger{
		tokenURL: GoogleTokenURL,
		clientID: clientID,
		secret:   func() (string, error) { return clientSecret, nil },
		client:   httpClient(client),
	}
}

// AppleConfig is the material needed to mint Apple client-secret JWTs.
type AppleConfig struct {
	ClientID   string // services id / bundle id (the OAuth client id, == aud at verify)
	TeamID     string // Apple developer team id (iss)
	KeyID      string // the .p8 key id (JWT header kid)
	PrivateKey []byte // the .p8 PEM (PKCS#8 EC P-256)
}

// NewApple builds the Apple exchanger. It parses the .p8 key up front and signs
// (and caches) the client-secret JWT on demand.
func NewApple(cfg AppleConfig, client *http.Client) (*TokenExchanger, error) {
	if cfg.ClientID == "" || cfg.TeamID == "" || cfg.KeyID == "" || len(cfg.PrivateKey) == 0 {
		return nil, errors.New("oidcprov: apple config requires client id, team id, key id, and private key")
	}
	key, err := parseECPrivateKey(cfg.PrivateKey)
	if err != nil {
		return nil, err
	}
	s := &appleSecret{cfg: cfg, key: key}
	return &TokenExchanger{
		tokenURL: AppleTokenURL,
		clientID: cfg.ClientID,
		secret:   s.get,
		client:   httpClient(client),
	}, nil
}

// Exchange posts the authorization code and returns the raw id_token.
func (e *TokenExchanger) Exchange(ctx context.Context, code, redirectURI string) (string, error) {
	secret, err := e.secret()
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {e.clientID},
		"client_secret": {secret},
		"redirect_uri":  {redirectURI},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("oidcprov: token exchange: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		// Provider error bodies can carry the client secret context; don't echo.
		return "", fmt.Errorf("oidcprov: token exchange: status %d", resp.StatusCode)
	}
	var tr struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("oidcprov: decode token response: %w", err)
	}
	if tr.IDToken == "" {
		return "", errors.New("oidcprov: token response missing id_token")
	}
	return tr.IDToken, nil
}

// --- Apple client-secret JWT -------------------------------------------------

// appleSecret signs and caches the short-lived client-secret JWT.
type appleSecret struct {
	cfg AppleConfig
	key *ecdsa.PrivateKey

	mu     sync.Mutex
	cached string
	expiry time.Time
}

const appleSecretTTL = 50 * time.Minute // well under Apple's 6-month ceiling

func (a *appleSecret) get() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if a.cached != "" && now.Add(time.Minute).Before(a.expiry) {
		return a.cached, nil
	}
	exp := now.Add(appleSecretTTL)
	jwt, err := signAppleJWT(a.cfg, a.key, now, exp)
	if err != nil {
		return "", err
	}
	a.cached, a.expiry = jwt, exp
	return jwt, nil
}

func signAppleJWT(cfg AppleConfig, key *ecdsa.PrivateKey, iat, exp time.Time) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": cfg.KeyID, "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iss": cfg.TeamID,
		"iat": iat.Unix(),
		"exp": exp.Unix(),
		"aud": appleAudience,
		"sub": cfg.ClientID,
	})
	signingInput := b64.EncodeToString(header) + "." + b64.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	// JOSE ES256 signature is fixed-width r||s, 32 bytes each.
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + b64.EncodeToString(sig), nil
}

func parseECPrivateKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("oidcprov: apple private key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("oidcprov: parse apple key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("oidcprov: apple private key is not an EC key")
	}
	return key, nil
}
