package main

import (
	"fmt"

	"github.com/jcrexon/laplat/internal/auth"
	"github.com/jcrexon/laplat/internal/config"
	"github.com/jcrexon/laplat/internal/smssend"
)

// buildSMSSender constructs the configured SMS transport. All implementations
// satisfy auth.SMSSender, so the phone factor is provider-agnostic.
func buildSMSSender(cfg *config.SMSConfig) (auth.SMSSender, error) {
	switch cfg.Provider {
	case "twilio":
		return smssend.NewTwilio(smssend.TwilioConfig{
			AccountSID: cfg.TwilioSID, AuthToken: cfg.TwilioAuthToken, From: cfg.From,
		}, nil)
	case "vonage":
		return smssend.NewVonage(smssend.VonageConfig{
			APIKey: cfg.VonageKey, APISecret: cfg.VonageSecret, From: cfg.From,
		}, nil)
	case "generic":
		headers := map[string]string{}
		if cfg.GatewayToken != "" {
			headers["Authorization"] = "Bearer " + cfg.GatewayToken
		}
		fields := map[string]string{}
		if cfg.From != "" {
			fields["from"] = cfg.From
		}
		return smssend.NewGeneric(smssend.GenericConfig{
			URL: cfg.GatewayURL, Headers: headers, Fields: fields,
		}, nil)
	default:
		return nil, fmt.Errorf("authd: unknown sms provider %q", cfg.Provider)
	}
}
