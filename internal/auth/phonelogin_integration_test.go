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
	"github.com/jcrexon/laplat/internal/identity"
	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/pkg/contracts"
	"github.com/jcrexon/laplat/pkg/token"
)

type captureSMS struct {
	mu    sync.Mutex
	phone string
	code  string
	sends int
}

func (c *captureSMS) SendLoginCode(_ context.Context, phone, code string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.phone, c.code, c.sends = phone, code, c.sends+1
	return nil
}
func (c *captureSMS) last() (string, string, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.phone, c.code, c.sends
}

type phoneHarness struct {
	pl    *auth.PhoneLogin
	svc   *auth.Service
	idSvc *identity.Service
	sms   *captureSMS
	st    *store.Store
	ctx   context.Context
}

func newPhoneHarness(t *testing.T) phoneHarness {
	t.Helper()
	pg := dbtest.New(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pg.ConnString())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	st := store.New(pool)

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := token.NewSigner("kid-1", priv)
	minter, _ := auth.NewMinter(signer, contracts.TokenIssuer, 15*time.Minute)
	svc, _ := auth.NewService(minter, st, 720*time.Hour)
	idSvc, _ := identity.NewService(st, map[string]identity.Verifier{"default": identity.ManualVerifier{}})

	sms := &captureSMS{}
	pl, err := auth.NewPhoneLogin(st, svc, sms)
	if err != nil {
		t.Fatal(err)
	}
	return phoneHarness{pl: pl, svc: svc, idSvc: idSvc, sms: sms, st: st, ctx: ctx}
}

// Phone-first login creates a pending user; with no adult attestation the tier
// stays none. After self-attesting 18+, a fresh token reaches phone_verified.
func TestPhoneLogin_LoginThenTier(t *testing.T) {
	h := newPhoneHarness(t)

	if err := h.pl.RequestCode(h.ctx, "+84 90 123 4567"); err != nil {
		t.Fatalf("request: %v", err)
	}
	gotPhone, code, sends := h.sms.last()
	if sends != 1 || gotPhone != "+84901234567" { // normalized E.164
		t.Fatalf("send=%d phone=%q", sends, gotPhone)
	}

	sess, err := h.pl.VerifyCode(h.ctx, "+84901234567", code, "") // anonymous login
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	uid := sess.AccessClaims.Subject
	// Phone bound, but no adult attestation yet -> tier none (phone != adulthood).
	if sess.AccessClaims.IdentityVerification != contracts.IdentityNone {
		t.Fatalf("pre-attest idv = %q, want none", sess.AccessClaims.IdentityVerification)
	}
	if ok, _ := h.st.HasVerifiedPhone(h.ctx, uid); !ok {
		t.Fatal("user should have a verified phone")
	}

	// Self-attest 18+, then a fresh token is phone_verified.
	if err := h.idSvc.AcceptToS(h.ctx, uid, contracts.CurrentToSVersion, true); err != nil {
		t.Fatalf("attest: %v", err)
	}
	next, err := h.svc.IssueSession(h.ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	if next.AccessClaims.IdentityVerification != contracts.IdentityPhoneVerified {
		t.Fatalf("post-attest idv = %q, want phone_verified", next.AccessClaims.IdentityVerification)
	}
	if !next.AccessClaims.MeetsPhoneVerification() {
		t.Fatal("should meet phone verification")
	}
}

// An authenticated user binding a new phone keeps the SAME account (upgrade),
// rather than creating a second one.
func TestPhoneLogin_AuthenticatedUpgradeKeepsAccount(t *testing.T) {
	h := newPhoneHarness(t)
	const uid = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	if _, err := h.st.CreateUser(h.ctx, store.NewUser{ID: uid, Handle: "existing", DisplayName: "E"}); err != nil {
		t.Fatal(err)
	}
	if err := h.st.CreateIdentityRecord(h.ctx, uid); err != nil {
		t.Fatal(err)
	}

	if err := h.pl.RequestCode(h.ctx, "+84905550001"); err != nil {
		t.Fatal(err)
	}
	_, code, _ := h.sms.last()
	sess, err := h.pl.VerifyCode(h.ctx, "+84905550001", code, uid) // authenticated
	if err != nil {
		t.Fatalf("verify (upgrade): %v", err)
	}
	if sess.AccessClaims.Subject != uid {
		t.Fatalf("upgrade created a new user %q, want %q", sess.AccessClaims.Subject, uid)
	}
	link, _ := h.st.GetPhoneIdentity(h.ctx, "+84905550001")
	if link.UserID != uid {
		t.Fatalf("phone linked to %q, want %q", link.UserID, uid)
	}
}

// Binding a phone already owned by another account is refused.
func TestPhoneLogin_ConflictRejected(t *testing.T) {
	h := newPhoneHarness(t)
	// First user claims the phone via anonymous login.
	if err := h.pl.RequestCode(h.ctx, "+84907770002"); err != nil {
		t.Fatal(err)
	}
	_, code, _ := h.sms.last()
	first, err := h.pl.VerifyCode(h.ctx, "+84907770002", code, "")
	if err != nil {
		t.Fatal(err)
	}

	// A different logged-in user tries to bind the same phone.
	const other = "01ARZ3NDEKTSV4RRFFQ69G5FBW"
	if _, err := h.st.CreateUser(h.ctx, store.NewUser{ID: other, Handle: "other", DisplayName: "O"}); err != nil {
		t.Fatal(err)
	}
	if err := h.pl.RequestCode(h.ctx, "+84907770002"); err != nil {
		t.Fatal(err)
	}
	_, code2, _ := h.sms.last()
	if _, err := h.pl.VerifyCode(h.ctx, "+84907770002", code2, other); err != auth.ErrPhoneConflict {
		t.Fatalf("conflict err = %v, want ErrPhoneConflict", err)
	}
	if first.AccessClaims.Subject == other {
		t.Fatal("sanity: users should differ")
	}
}

// Wrong code is rejected and bad phone numbers are refused.
func TestPhoneLogin_WrongCodeAndBadPhone(t *testing.T) {
	h := newPhoneHarness(t)
	if err := h.pl.RequestCode(h.ctx, "+84908880003"); err != nil {
		t.Fatal(err)
	}
	_, realCode, _ := h.sms.last()
	wrong := "000000"
	if realCode == wrong {
		wrong = "111111"
	}
	if _, err := h.pl.VerifyCode(h.ctx, "+84908880003", wrong, ""); err != auth.ErrInvalidCode {
		t.Fatalf("wrong code err = %v, want ErrInvalidCode", err)
	}
	if err := h.pl.RequestCode(h.ctx, "not-a-phone"); err == nil {
		t.Fatal("malformed phone should be rejected")
	}
}
