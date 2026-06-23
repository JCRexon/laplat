package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/mail"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jcrexon/laplat/internal/store"
)

// Email-OTP tuning.
const (
	codeTTL         = 10 * time.Minute
	maxCodeAttempts = 5
	resendCooldown  = 60 * time.Second
	codeDigits      = 6
)

// ErrInvalidCode is returned for any failed verification (wrong/expired/used/
// too-many-attempts). It is deliberately uniform — no oracle about which.
var ErrInvalidCode = errors.New("auth: invalid or expired code")

// errBadEmail is a syntactically invalid address (distinct from account
// existence, which the flow never reveals).
var errBadEmail = errors.New("auth: invalid email address")

// CodeSender delivers a login code to an email address. It is a port so the
// transport (SMTP/provider API) lives behind a boundary and tests use a fake.
type CodeSender interface {
	SendLoginCode(ctx context.Context, email, code string) error
}

// EmailStore is the persistence the email-OTP flow needs (*store.Store fits).
type EmailStore interface {
	FederationStore // reuses CreateUser/CreateIdentityRecord for first login
	GetEmailIdentity(ctx context.Context, email string) (store.EmailIdentity, error)
	LinkEmailIdentity(ctx context.Context, email, userID string) error
	TouchEmailLogin(ctx context.Context, email string) error
	CreateLoginChallenge(ctx context.Context, id, email string, codeHash []byte, expiresAt time.Time) error
	GetActiveLoginChallenge(ctx context.Context, email string) (store.LoginChallenge, error)
	IncrementLoginChallengeAttempts(ctx context.Context, id string) error
	ConsumeLoginChallenge(ctx context.Context, id string) error
}

// EmailLogin issues sessions from an email one-time code. A first-time login
// creates a PENDING user (no caps, idv "none") — proving control of an email is
// not adult verification; eKYC still gates activation. Linkage is by normalized
// email, which is safe here because this factor itself proves mailbox control
// (contrast OIDC, which must never trust an IdP-asserted email).
type EmailLogin struct {
	store    EmailStore
	sessions *Service
	sender   CodeSender

	Now       func() time.Time
	NewID     func() string // challenge id
	NewCode   func() string // 6-digit code
	NewUserID func() string
	NewHandle func() string
}

// NewEmailLogin wires the email-OTP service.
func NewEmailLogin(st EmailStore, sessions *Service, sender CodeSender) (*EmailLogin, error) {
	if st == nil || sessions == nil || sender == nil {
		return nil, errors.New("auth: email login requires store, sessions, and sender")
	}
	return &EmailLogin{
		store:     st,
		sessions:  sessions,
		sender:    sender,
		Now:       time.Now,
		NewID:     newOpaqueID,
		NewCode:   newNumericCode,
		NewUserID: newOpaqueID,
		NewHandle: newHandle,
	}, nil
}

// RequestCode generates and sends a login code for the email. The response to
// the caller is uniform whether or not the email already has an account (no
// enumeration). A recent unconsumed challenge suppresses a resend (anti-spam),
// but the caller is told nothing different.
func (e *EmailLogin) RequestCode(ctx context.Context, rawEmail string) error {
	email, err := normalizeEmail(rawEmail)
	if err != nil {
		return err
	}

	// Suppress a resend if a fresh challenge is already outstanding.
	if active, err := e.store.GetActiveLoginChallenge(ctx, email); err == nil {
		if e.Now().Sub(active.CreatedAt) < resendCooldown {
			return nil
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}

	code := e.NewCode()
	if err := e.store.CreateLoginChallenge(ctx, e.NewID(), email, hashSecret(code), e.Now().Add(codeTTL)); err != nil {
		return err
	}
	return e.sender.SendLoginCode(ctx, email, code)
}

// VerifyCode checks a code and, on success, resolves/creates the user and issues
// a session. Every failure mode returns ErrInvalidCode.
func (e *EmailLogin) VerifyCode(ctx context.Context, rawEmail, code string) (Session, error) {
	email, err := normalizeEmail(rawEmail)
	if err != nil {
		return Session{}, ErrInvalidCode
	}

	ch, err := e.store.GetActiveLoginChallenge(ctx, email)
	if err != nil {
		return Session{}, ErrInvalidCode // none active (or expired/consumed)
	}
	if ch.Attempts >= maxCodeAttempts {
		return Session{}, ErrInvalidCode // locked: too many guesses
	}
	if subtle.ConstantTimeCompare(ch.CodeHash, hashSecret(code)) != 1 {
		// Count the failed guess; ignore the (non-fatal) bookkeeping error.
		_ = e.store.IncrementLoginChallengeAttempts(ctx, ch.ID)
		return Session{}, ErrInvalidCode
	}

	// Correct: burn the challenge before issuing anything (single-use).
	if err := e.store.ConsumeLoginChallenge(ctx, ch.ID); err != nil {
		return Session{}, err
	}
	userID, err := e.resolveUser(ctx, email)
	if err != nil {
		return Session{}, err
	}
	return e.sessions.IssueSession(ctx, userID)
}

// resolveUser finds the user linked to the email or creates a new pending one.
func (e *EmailLogin) resolveUser(ctx context.Context, email string) (string, error) {
	id, err := e.store.GetEmailIdentity(ctx, email)
	if err == nil {
		_ = e.store.TouchEmailLogin(ctx, email)
		return id.UserID, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}

	userID := e.NewUserID()
	if _, err := e.store.CreateUser(ctx, store.NewUser{
		ID: userID, Handle: e.NewHandle(), DisplayName: "New User",
	}); err != nil {
		return "", err
	}
	if err := e.store.CreateIdentityRecord(ctx, userID); err != nil {
		return "", err
	}
	if err := e.store.LinkEmailIdentity(ctx, email, userID); err != nil {
		return "", err
	}
	return userID, nil
}

// normalizeEmail validates and lowercases an email for stable linkage.
func normalizeEmail(raw string) (string, error) {
	addr, err := mail.ParseAddress(strings.TrimSpace(raw))
	if err != nil {
		return "", errBadEmail
	}
	return strings.ToLower(addr.Address), nil
}

// newNumericCode returns a uniform 6-digit code. Each digit uses rejection
// sampling (discarding bytes >= 250, the largest multiple of 10 within a byte)
// so there is no modulo bias toward the low digits.
func newNumericCode() string {
	out := make([]byte, codeDigits)
	for i := range out {
		var b [1]byte
		for {
			mustRand(b[:])
			if b[0] < 250 {
				break
			}
		}
		out[i] = '0' + (b[0] % 10)
	}
	return string(out)
}
