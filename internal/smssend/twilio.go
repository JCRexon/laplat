package smssend

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Twilio sends via Twilio's Messages API: form-encoded POST with HTTP Basic auth
// (AccountSID:AuthToken) — a scheme the Generic sender can't express.
type Twilio struct {
	cfg     TwilioConfig
	baseURL string // overridable in tests
	client  *http.Client
}

// TwilioConfig is the Twilio credentials and sender id.
type TwilioConfig struct {
	AccountSID string
	AuthToken  string
	From       string // E.164 sender number or messaging service sid
}

// NewTwilio validates config and builds the adapter.
func NewTwilio(cfg TwilioConfig, client *http.Client) (*Twilio, error) {
	if cfg.AccountSID == "" || cfg.AuthToken == "" || cfg.From == "" {
		return nil, errors.New("smssend: twilio requires account sid, auth token, and from")
	}
	return &Twilio{
		cfg:     cfg,
		baseURL: "https://api.twilio.com",
		client:  httpClient(client),
	}, nil
}

// SendLoginCode implements auth.SMSSender.
func (t *Twilio) SendLoginCode(ctx context.Context, phone, code string) error {
	endpoint := fmt.Sprintf("%s/2010-04-01/Accounts/%s/Messages.json", t.baseURL, t.cfg.AccountSID)
	form := url.Values{
		"To":   {phone},
		"From": {t.cfg.From},
		"Body": {strings.ReplaceAll(defaultMessageTemplate, "{code}", code)},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(t.cfg.AccountSID, t.cfg.AuthToken)

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("smssend: twilio send: %w", err)
	}
	defer drainClose(resp)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("smssend: twilio status %d", resp.StatusCode)
	}
	return nil
}
