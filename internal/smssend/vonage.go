package smssend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Vonage sends via the Vonage (Nexmo) SMS API. It needs its own adapter because
// Vonage returns HTTP 200 even on logical failures — success is carried in a
// per-message status field, which must be parsed.
type Vonage struct {
	cfg      VonageConfig
	endpoint string // overridable in tests
	client   *http.Client
}

// VonageConfig is the Vonage credentials and sender id.
type VonageConfig struct {
	APIKey    string
	APISecret string
	From      string // alphanumeric sender id or number
}

// NewVonage validates config and builds the adapter.
func NewVonage(cfg VonageConfig, client *http.Client) (*Vonage, error) {
	if cfg.APIKey == "" || cfg.APISecret == "" || cfg.From == "" {
		return nil, errors.New("smssend: vonage requires api key, api secret, and from")
	}
	return &Vonage{
		cfg:      cfg,
		endpoint: "https://rest.nexmo.com/sms/json",
		client:   httpClient(client),
	}, nil
}

// SendLoginCode implements auth.SMSSender.
func (v *Vonage) SendLoginCode(ctx context.Context, phone, code string) error {
	form := url.Values{
		"api_key":    {v.cfg.APIKey},
		"api_secret": {v.cfg.APISecret},
		"to":         {strings.TrimPrefix(phone, "+")}, // Vonage wants no leading '+'
		"from":       {v.cfg.From},
		"text":       {strings.ReplaceAll(defaultMessageTemplate, "{code}", code)},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("smssend: vonage send: %w", err)
	}
	defer drainClose(resp)
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("smssend: vonage status %d", resp.StatusCode)
	}

	// Success is per-message: status "0" means delivered to the carrier.
	var parsed struct {
		Messages []struct {
			Status    string `json:"status"`
			ErrorText string `json:"error-text"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("smssend: vonage decode: %w", err)
	}
	if len(parsed.Messages) == 0 {
		return errors.New("smssend: vonage returned no message status")
	}
	if parsed.Messages[0].Status != "0" {
		return fmt.Errorf("smssend: vonage rejected (status %s): %s",
			parsed.Messages[0].Status, parsed.Messages[0].ErrorText)
	}
	return nil
}
