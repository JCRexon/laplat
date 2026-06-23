// Package smssend holds production transports for login SMS, all satisfying
// auth.SMSSender structurally so the auth package stays provider-agnostic:
//
//   - Generic: a config-driven sender (field names, encoding, headers) covering
//     the common "simple REST" gateways (Bearer / API-key + JSON/form) without
//     per-provider code.
//   - Twilio / Vonage: thin adapters for schemes a generic config can't express
//     (Twilio's Basic-auth form API; Vonage's per-message status response).
//
// The transport is selected by configuration; nothing here is hard-wired to one
// provider.
package smssend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultMessageTemplate = "Your laplat sign-in code is {code}. It expires in 10 minutes."

func httpClient(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// drainClose reads/discards and closes a response body (connection reuse).
func drainClose(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	resp.Body.Close()
}

// Generic is a config-driven SMS sender. The recipient and message map to
// configurable field names and are encoded as JSON or form values (so values
// are escaped by the encoder — no string-template injection). Extra static
// fields (e.g. from, api_key) and headers (e.g. auth) are passed through.
type Generic struct {
	cfg    GenericConfig
	client *http.Client
}

// GenericConfig configures the Generic sender. URL is required; the rest have
// sensible defaults (POST, JSON, "to"/"message").
type GenericConfig struct {
	URL             string
	Method          string            // default POST
	Encoding        string            // "json" (default) | "form"
	ToField         string            // default "to"
	MessageField    string            // default "message"
	MessageTemplate string            // default standard text; "{code}" is substituted
	Fields          map[string]string // extra static body fields (from, api_key, ...)
	Headers         map[string]string // extra headers (auth, etc.)
}

// NewGeneric validates config and builds the sender.
func NewGeneric(cfg GenericConfig, client *http.Client) (*Generic, error) {
	if cfg.URL == "" {
		return nil, errors.New("smssend: generic sender requires a URL")
	}
	if cfg.Method == "" {
		cfg.Method = http.MethodPost
	}
	if cfg.Encoding == "" {
		cfg.Encoding = "json"
	}
	if cfg.ToField == "" {
		cfg.ToField = "to"
	}
	if cfg.MessageField == "" {
		cfg.MessageField = "message"
	}
	if cfg.MessageTemplate == "" {
		cfg.MessageTemplate = defaultMessageTemplate
	}
	return &Generic{cfg: cfg, client: httpClient(client)}, nil
}

// SendLoginCode implements auth.SMSSender.
func (g *Generic) SendLoginCode(ctx context.Context, phone, code string) error {
	fields := map[string]string{
		g.cfg.ToField:      phone,
		g.cfg.MessageField: strings.ReplaceAll(g.cfg.MessageTemplate, "{code}", code),
	}
	for k, v := range g.cfg.Fields {
		fields[k] = v
	}

	var body io.Reader
	var contentType string
	switch g.cfg.Encoding {
	case "form":
		vals := url.Values{}
		for k, v := range fields {
			vals.Set(k, v)
		}
		body, contentType = strings.NewReader(vals.Encode()), "application/x-www-form-urlencoded"
	default: // json
		b, _ := json.Marshal(fields)
		body, contentType = bytes.NewReader(b), "application/json"
	}

	req, err := http.NewRequestWithContext(ctx, g.cfg.Method, g.cfg.URL, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	for k, v := range g.cfg.Headers {
		req.Header.Set(k, v)
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("smssend: send: %w", err)
	}
	defer drainClose(resp)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("smssend: gateway status %d", resp.StatusCode)
	}
	return nil
}
