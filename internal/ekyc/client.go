package ekyc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// HTTPClient is a generic HTTP eKYC vendor client: it POSTs
// {"correlationId": …} to the vendor's create-session endpoint (Bearer auth)
// and reads {"reference","redirectUrl"}. Real vendors vary; this covers the
// common JSON shape and is the place a vendor-specific client would slot in.
type HTTPClient struct {
	url    string
	token  string
	client *http.Client
}

// HTTPConfig is the vendor connection material.
type HTTPConfig struct {
	URL   string
	Token string
}

// NewHTTPClient validates config and builds the client.
func NewHTTPClient(cfg HTTPConfig, client *http.Client) (*HTTPClient, error) {
	if cfg.URL == "" {
		return nil, errors.New("ekyc: vendor URL is required")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &HTTPClient{url: cfg.URL, token: cfg.Token, client: client}, nil
}

// CreateVerification implements Client.
func (c *HTTPClient) CreateVerification(ctx context.Context, correlationID string) (string, string, error) {
	body, _ := json.Marshal(map[string]string{"correlationId": correlationID})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("ekyc: create verification: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("ekyc: vendor status %d", resp.StatusCode)
	}
	var out struct {
		Reference   string `json:"reference"`
		RedirectURL string `json:"redirectUrl"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", "", fmt.Errorf("ekyc: decode vendor response: %w", err)
	}
	if out.Reference == "" {
		return "", "", errors.New("ekyc: vendor response missing reference")
	}
	return out.Reference, out.RedirectURL, nil
}
