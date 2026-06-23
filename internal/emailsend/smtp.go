// Package emailsend holds the production transport for login emails: an SMTP
// sender built on the standard library (net/smtp), keeping the auth package
// free of any mail dependency. It satisfies auth.CodeSender structurally.
package emailsend

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
)

// SMTPSender sends login codes over authenticated SMTP (STARTTLS via the
// standard library's smtp.SendMail, which negotiates TLS when the server
// advertises it).
type SMTPSender struct {
	addr string // host:port
	host string
	from string
	auth smtp.Auth
}

// SMTPConfig is the connection/auth material for the sender.
type SMTPConfig struct {
	Host     string
	Port     string
	From     string
	Username string
	Password string
}

// NewSMTPSender validates config and builds a sender.
func NewSMTPSender(cfg SMTPConfig) (*SMTPSender, error) {
	if cfg.Host == "" || cfg.Port == "" || cfg.From == "" {
		return nil, errors.New("emailsend: smtp host, port, and from are required")
	}
	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}
	return &SMTPSender{
		addr: net.JoinHostPort(cfg.Host, cfg.Port),
		host: cfg.Host,
		from: cfg.From,
		auth: auth,
	}, nil
}

// SendLoginCode delivers the one-time code. The message is plain text; the code
// is the sole sensitive content and is not logged here.
func (s *SMTPSender) SendLoginCode(_ context.Context, email, code string) error {
	msg := buildMessage(s.from, email, code)
	if err := smtp.SendMail(s.addr, s.auth, s.from, []string{email}, msg); err != nil {
		return fmt.Errorf("emailsend: send: %w", err)
	}
	return nil
}

func buildMessage(from, to, code string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	b.WriteString("Subject: Your laplat sign-in code\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")
	fmt.Fprintf(&b, "Your sign-in code is %s. It expires in 10 minutes.\r\n", code)
	b.WriteString("If you did not request this, you can ignore this email.\r\n")
	return []byte(b.String())
}
