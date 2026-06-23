//go:build integration

package auth_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jcrexon/laplat/internal/auth"
	"github.com/jcrexon/laplat/internal/dbtest"
	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/pkg/contracts"
	"github.com/jcrexon/laplat/pkg/token"
)

// captureSender records the last code it was asked to send.
type captureSender struct {
	mu    sync.Mutex
	email string
	code  string
	sends int
}

func (c *captureSender) SendLoginCode(_ context.Context, email, code string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.email, c.code, c.sends = email, code, c.sends+1
	return nil
}

func (c *captureSender) last() (string, string, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.email, c.code, c.sends
}

type emailHarness struct {
	el     *auth.EmailLogin
	sender *captureSender
	st     *store.Store
	ctx    context.Context
}

func newEmailHarness(t *testing.T) emailHarness {
	t.Helper()
	pg := dbtest.New(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pg.ConnString())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	st := store.New(pool)

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := token.NewSigner("kid-1", priv)
	minter, _ := auth.NewMinter(signer, contracts.TokenIssuer, 15*time.Minute)
	_ = token.NewValidator(token.NewVerifier(map[string]ed25519.PublicKey{"kid-1": pub}), st)
	svc, _ := auth.NewService(minter, st, 720*time.Hour)

	sender := &captureSender{}
	el, err := auth.NewEmailLogin(st, svc, sender)
	if err != nil {
		t.Fatal(err)
	}
	return emailHarness{el: el, sender: sender, st: st, ctx: ctx}
}

// Request -> verify with the delivered code creates a pending user, links the
// email, and issues a session with no caps and idv none.
func TestEmailLogin_RequestThenVerify(t *testing.T) {
	h := newEmailHarness(t)

	if err := h.el.RequestCode(h.ctx, "Alice@Example.com"); err != nil {
		t.Fatalf("request: %v", err)
	}
	gotEmail, code, sends := h.sender.last()
	if sends != 1 || gotEmail != "alice@example.com" { // normalized lowercase
		t.Fatalf("send=%d email=%q", sends, gotEmail)
	}
	if len(code) != 6 {
		t.Fatalf("code = %q, want 6 digits", code)
	}

	sess, err := h.el.VerifyCode(h.ctx, "alice@example.com", code)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	userID := sess.AccessClaims.Subject
	u, _ := h.st.GetUser(h.ctx, userID)
	if u.Status != "pending" {
		t.Fatalf("status = %q, want pending", u.Status)
	}
	if len(sess.AccessClaims.Capabilities) != 0 {
		t.Fatalf("expected no caps, got %v", sess.AccessClaims.Capabilities)
	}
	if sess.AccessClaims.IdentityVerification != contracts.IdentityNone {
		t.Fatalf("idv = %q, want none", sess.AccessClaims.IdentityVerification)
	}
	link, err := h.st.GetEmailIdentity(h.ctx, "alice@example.com")
	if err != nil || link.UserID != userID {
		t.Fatalf("email link: %v / %q", err, link.UserID)
	}
}

// A wrong code is rejected, increments attempts, and after maxCodeAttempts the
// challenge is locked even if the right code is then presented.
func TestEmailLogin_WrongCodeLocksOut(t *testing.T) {
	h := newEmailHarness(t)
	if err := h.el.RequestCode(h.ctx, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	_, realCode, _ := h.sender.last()
	wrongCode := "000000"
	if realCode == wrongCode {
		wrongCode = "111111"
	}

	for i := 0; i < 5; i++ {
		if _, err := h.el.VerifyCode(h.ctx, "bob@example.com", wrongCode); err != auth.ErrInvalidCode {
			t.Fatalf("attempt %d: err = %v, want ErrInvalidCode", i, err)
		}
	}
	// Now locked: even the correct code fails.
	if _, err := h.el.VerifyCode(h.ctx, "bob@example.com", realCode); err != auth.ErrInvalidCode {
		t.Fatalf("after lockout, correct code err = %v, want ErrInvalidCode", err)
	}
	// No account was ever created.
	if _, err := h.st.GetEmailIdentity(h.ctx, "bob@example.com"); err == nil {
		t.Fatal("no email identity should exist after failed logins")
	}
}

// A consumed code cannot be reused.
func TestEmailLogin_CodeIsSingleUse(t *testing.T) {
	h := newEmailHarness(t)
	if err := h.el.RequestCode(h.ctx, "carol@example.com"); err != nil {
		t.Fatal(err)
	}
	_, code, _ := h.sender.last()
	if _, err := h.el.VerifyCode(h.ctx, "carol@example.com", code); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if _, err := h.el.VerifyCode(h.ctx, "carol@example.com", code); err != auth.ErrInvalidCode {
		t.Fatalf("reuse err = %v, want ErrInvalidCode", err)
	}
}

// A fresh outstanding challenge suppresses a resend (anti-spam), but the call
// still succeeds.
func TestEmailLogin_ResendSuppressedWithinCooldown(t *testing.T) {
	h := newEmailHarness(t)
	if err := h.el.RequestCode(h.ctx, "dave@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := h.el.RequestCode(h.ctx, "dave@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, _, sends := h.sender.last(); sends != 1 {
		t.Fatalf("expected 1 send within cooldown, got %d", sends)
	}
}

// A malformed address is rejected distinctly (so the HTTP layer can 400 it),
// without revealing anything about account existence.
func TestEmailLogin_RejectsMalformedAddress(t *testing.T) {
	h := newEmailHarness(t)
	if err := h.el.RequestCode(h.ctx, "not-an-email"); err == nil {
		t.Fatal("expected error for malformed email")
	}
}
