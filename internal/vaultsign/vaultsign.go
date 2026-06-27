// Package vaultsign implements signing.KeySigner against HashiCorp Vault's
// Transit secrets engine. The Ed25519 private key lives in Vault and never
// enters this process; signing is a Transit API call. This satisfies the A-1
// "key in KMS/HSM, not env" requirement with a self-hostable backend (Vault runs
// on your own infrastructure — no cloud dependency).
//
// It uses only net/http + stdlib, not the Vault SDK, to keep the dependency
// surface minimal (the Transit sign API is a single JSON POST).
package vaultsign

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Config is the Vault Transit signer configuration.
type Config struct {
	Address string // Vault base URL, e.g. https://127.0.0.1:8200
	Token   string // Vault token with update on transit/sign/<key>
	Mount   string // transit mount path, e.g. "transit"
	KeyName string // ed25519 transit key name
	// KeyID is the value stamped into the JWT/audit `kid`. It must match the
	// public key the operator publishes in LAPLAT_TOKEN_VERIFY_KEYS, so verifiers
	// can resolve it.
	KeyID string
}

// Signer signs messages via Vault Transit. It satisfies signing.KeySigner.
type Signer struct {
	cfg    Config
	client *http.Client
}

// New validates the config and returns a Transit-backed signer. An optional
// http.Client may be supplied (e.g. in tests); nil uses a sane default.
func New(cfg Config, client *http.Client) (*Signer, error) {
	if cfg.Address == "" {
		return nil, errors.New("vaultsign: address required")
	}
	if cfg.Token == "" {
		return nil, errors.New("vaultsign: token required")
	}
	if cfg.KeyName == "" {
		return nil, errors.New("vaultsign: transit key name required")
	}
	if cfg.KeyID == "" {
		return nil, errors.New("vaultsign: key id required")
	}
	if cfg.Mount == "" {
		cfg.Mount = "transit"
	}
	cfg.Address = strings.TrimRight(cfg.Address, "/")
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &Signer{cfg: cfg, client: client}, nil
}

// KeyID returns the configured key id.
func (s *Signer) KeyID() string { return s.cfg.KeyID }

type signRequest struct {
	Input string `json:"input"` // base64 std of the message
}

type signResponse struct {
	Data struct {
		Signature string `json:"signature"` // "vault:v<n>:<base64 std signature>"
	} `json:"data"`
}

// SignRaw asks Vault Transit to sign the message with the configured Ed25519 key
// and returns the raw signature bytes.
func (s *Signer) SignRaw(message []byte) ([]byte, error) {
	body, err := json.Marshal(signRequest{Input: base64.StdEncoding.EncodeToString(message)})
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/v1/%s/sign/%s", s.cfg.Address, s.cfg.Mount, s.cfg.KeyName)

	// Bound the call independently of any caller context so a hung Vault cannot
	// wedge token minting indefinitely.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", s.cfg.Token)
	req.Header.Set("Content-Type", "application/json")

	res, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vaultsign: request failed: %w", err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vaultsign: vault returned %d: %s", res.StatusCode, strings.TrimSpace(string(raw)))
	}

	var sr signResponse
	if err := json.Unmarshal(raw, &sr); err != nil {
		return nil, fmt.Errorf("vaultsign: bad response: %w", err)
	}
	return parseTransitSignature(sr.Data.Signature)
}

type keyReadResponse struct {
	Data struct {
		LatestVersion int `json:"latest_version"`
		Keys          map[string]struct {
			PublicKey string `json:"public_key"`
		} `json:"keys"`
	} `json:"data"`
}

// PublicKey fetches the Ed25519 public key of the configured Transit key's latest
// version. This lets the service self-publish its verify key — the operator need
// not export it manually. Vault returns the public key as either raw base64 or a
// PEM/DER SPKI depending on version, so both are handled.
func (s *Signer) PublicKey(ctx context.Context) (ed25519.PublicKey, error) {
	url := fmt.Sprintf("%s/v1/%s/keys/%s", s.cfg.Address, s.cfg.Mount, s.cfg.KeyName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", s.cfg.Token)

	res, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vaultsign: read key failed: %w", err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vaultsign: vault returned %d reading key: %s", res.StatusCode, strings.TrimSpace(string(raw)))
	}

	var kr keyReadResponse
	if err := json.Unmarshal(raw, &kr); err != nil {
		return nil, fmt.Errorf("vaultsign: bad key response: %w", err)
	}
	entry, ok := kr.Data.Keys[strconv.Itoa(kr.Data.LatestVersion)]
	if !ok || entry.PublicKey == "" {
		return nil, fmt.Errorf("vaultsign: no public key for version %d", kr.Data.LatestVersion)
	}
	return parseEd25519PublicKey(entry.PublicKey)
}

// parseEd25519PublicKey accepts the public key in any of the forms Vault Transit
// may return it: raw 32-byte base64, a PEM-wrapped SPKI, or a base64 DER SPKI.
func parseEd25519PublicKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "-----BEGIN") {
		block, _ := pem.Decode([]byte(s))
		if block == nil {
			return nil, errors.New("vaultsign: invalid PEM public key")
		}
		return ed25519FromPKIX(block.Bytes)
	}
	dec, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("vaultsign: public key not base64 or PEM: %w", err)
	}
	if len(dec) == ed25519.PublicKeySize {
		return ed25519.PublicKey(dec), nil
	}
	return ed25519FromPKIX(dec)
}

func ed25519FromPKIX(der []byte) (ed25519.PublicKey, error) {
	pk, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("vaultsign: parse public key: %w", err)
	}
	ed, ok := pk.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("vaultsign: transit key is not ed25519")
	}
	return ed, nil
}

// parseTransitSignature strips the "vault:v<n>:" prefix and base64-decodes the
// signature.
func parseTransitSignature(sig string) ([]byte, error) {
	if sig == "" {
		return nil, errors.New("vaultsign: empty signature in response")
	}
	// Format: vault:v<version>:<base64>. Take the segment after the last colon.
	i := strings.LastIndex(sig, ":")
	if i < 0 || i == len(sig)-1 {
		return nil, fmt.Errorf("vaultsign: malformed signature %q", sig)
	}
	out, err := base64.StdEncoding.DecodeString(sig[i+1:])
	if err != nil {
		return nil, fmt.Errorf("vaultsign: signature not valid base64: %w", err)
	}
	return out, nil
}
