// Package otpconsole provides a DEV-ONLY OTP transport that logs the code
// instead of delivering it, so the email/phone login loop can be exercised
// locally without an SMTP or SMS vendor. NEVER enable it in production: anyone
// who can read the logs can complete a login.
package otpconsole

import (
	"context"
	"log/slog"
)

// Sender writes the one-time code to the application log. It satisfies both
// auth.CodeSender (email) and auth.SMSSender (phone) — both are
// SendLoginCode(ctx, dest, code).
type Sender struct {
	log     *slog.Logger
	channel string // "email" | "sms"
}

// New builds a console sender for a channel ("email" or "sms").
func New(log *slog.Logger, channel string) *Sender {
	return &Sender{log: log, channel: channel}
}

// SendLoginCode logs the code at Warn level (visible, and a standing signal that
// a non-delivering sender is in use). The code attribute has a stable name so a
// local/E2E harness can parse it.
func (s *Sender) SendLoginCode(_ context.Context, dest, code string) error {
	s.log.Warn("DEV OTP issued via console sender — never use in production",
		"channel", s.channel, "dest", dest, "code", code)
	return nil
}
