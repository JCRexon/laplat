// Package smssend holds the production transport for login SMS: a generic
// HTTP-gateway sender. It posts JSON {"to","message"} with a Bearer token to a
// configured endpoint — the shape most SMS providers (Twilio-compatible APIs,
// VN gateways) accept or can adapt to. It satisfies auth.SMSSender structurally,
// keeping the auth package free of any provider dependency.
package smssend

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

// HTTPSender posts login codes to an SMS gateway's HTTP endpoint.
type HTTPSender struct {
	url    string
	token  string
	client *http.Client
}

// Config is the gateway connection material.
type Config struct {
	URL   string // gateway endpoint
	Token string // bearer token / API key (optional)
}

// New validates config and builds a sender.
func New(cfg Config, client *http.Client) (*HTTPSender, error) {
	if cfg.URL == "" {
		return nil, errors.New("smssend: gateway URL is required")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &HTTPSender{url: cfg.URL, token: cfg.Token, client: client}, nil
}

// SendLoginCode delivers the one-time code. The code is the sole sensitive
// content and is not logged here.
func (s *HTTPSender) SendLoginCode(ctx context.Context, phone, code string) error {
	body, _ := json.Marshal(map[string]string{
		"to":      phone,
		"message": fmt.Sprintf("Your laplat sign-in code is %s. It expires in 10 minutes.", code),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("smssend: send: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("smssend: gateway status %d", resp.StatusCode)
	}
	return nil
}
