package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jcrexon/laplat/internal/store"
)

// ErrPhoneConflict means the verified phone is already bound to a different
// account than the authenticated caller (prevents silently merging accounts).
var ErrPhoneConflict = errors.New("auth: phone already linked to another account")

// errBadPhone is a syntactically invalid phone number.
var errBadPhone = errors.New("auth: invalid phone number")

// SMSSender delivers a login code to a phone number. A port so the transport
// (an SMS gateway) lives behind a boundary and tests use a fake.
type SMSSender interface {
	SendLoginCode(ctx context.Context, phone, code string) error
}

// PhoneStore is the persistence the phone-OTP flow needs (*store.Store fits).
type PhoneStore interface {
	FederationStore // reuses CreateUser/CreateIdentityRecord for phone-first signup
	GetPhoneIdentity(ctx context.Context, phone string) (store.PhoneIdentity, error)
	LinkPhoneIdentity(ctx context.Context, phone, userID string) error
	TouchPhoneLogin(ctx context.Context, phone string) error
	CreatePhoneChallenge(ctx context.Context, id, phone string, codeHash []byte, expiresAt time.Time) error
	GetActivePhoneChallenge(ctx context.Context, phone string) (store.PhoneChallenge, error)
	IncrementPhoneChallengeAttempts(ctx context.Context, id string) error
	ConsumePhoneChallenge(ctx context.Context, id string) error
}

// PhoneLogin is the phone one-time-code factor. It is both a login factor
// (phone-first sign-in creates/links a pending user and issues a session) and
// the basis of the 'phone_verified' assurance tier — a verified phone is the
// Decree 147 interaction floor. Reaching the phone_verified tier also requires
// the 18+ self-attestation; the token mapping enforces that.
type PhoneLogin struct {
	store  PhoneStore
	authn  *Authenticator
	sender SMSSender

	Now     func() time.Time
	NewID   func() string
	NewCode func() string
}

// NewPhoneLogin wires the phone-OTP service. Linkage and session issuance go
// through the Authenticator (the phone LinkResolver is registered here), so this
// flow owns only the OTP transport.
func NewPhoneLogin(st PhoneStore, sessions *Service, sender SMSSender) (*PhoneLogin, error) {
	if st == nil || sessions == nil || sender == nil {
		return nil, errors.New("auth: phone login requires store, sessions, and sender")
	}
	authn, err := NewAuthenticator(sessions)
	if err != nil {
		return nil, err
	}
	authn.Register(PrincipalPhone, NewPhoneResolver(st))
	return &PhoneLogin{
		store:   st,
		authn:   authn,
		sender:  sender,
		Now:     time.Now,
		NewID:   newOpaqueID,
		NewCode: newNumericCode,
	}, nil
}

// RequestCode generates and sends a login code for the phone. Uniform response
// regardless of account existence; a fresh outstanding challenge suppresses a
// resend.
func (p *PhoneLogin) RequestCode(ctx context.Context, rawPhone string) error {
	phone, err := normalizeE164(rawPhone)
	if err != nil {
		return err
	}
	if active, err := p.store.GetActivePhoneChallenge(ctx, phone); err == nil {
		if p.Now().Sub(active.CreatedAt) < resendCooldown {
			return nil
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}

	code := p.NewCode()
	if err := p.store.CreatePhoneChallenge(ctx, p.NewID(), phone, hashSecret(code), p.Now().Add(codeTTL)); err != nil {
		return err
	}
	return p.sender.SendLoginCode(ctx, phone, code)
}

// VerifyCode checks a code and, on success, resolves the user and issues a
// session. currentUserID, when non-empty, is the already-authenticated caller:
// the phone is linked to THAT account (an assurance upgrade) rather than logging
// in / creating a new one. Binding a phone already owned by a different account
// is refused (ErrPhoneConflict). Failed verification returns ErrInvalidCode.
func (p *PhoneLogin) VerifyCode(ctx context.Context, rawPhone, code, currentUserID string) (Session, error) {
	phone, err := normalizeE164(rawPhone)
	if err != nil {
		return Session{}, ErrInvalidCode
	}
	ch, err := p.store.GetActivePhoneChallenge(ctx, phone)
	if err != nil {
		return Session{}, ErrInvalidCode
	}
	if ch.Attempts >= maxCodeAttempts {
		return Session{}, ErrInvalidCode
	}
	if subtle.ConstantTimeCompare(ch.CodeHash, hashSecret(code)) != 1 {
		_ = p.store.IncrementPhoneChallengeAttempts(ctx, ch.ID)
		return Session{}, ErrInvalidCode
	}
	if err := p.store.ConsumePhoneChallenge(ctx, ch.ID); err != nil {
		return Session{}, err
	}

	return p.authn.Authenticate(ctx, Principal{Kind: PrincipalPhone, Subject: phone}, currentUserID)
}

// normalizeE164 validates a phone into E.164 ("+" then 8–15 digits), stripping
// common separators. This is a minimal stdlib check (no libphonenumber): it
// guarantees a canonical, comparable key, not that the number is dialable.
func normalizeE164(raw string) (string, error) {
	var b strings.Builder
	for i, r := range strings.TrimSpace(raw) {
		switch {
		case r == '+' && i == 0:
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '(' || r == ')':
			// separators: drop
		default:
			return "", errBadPhone
		}
	}
	s := b.String()
	if !strings.HasPrefix(s, "+") {
		return "", errBadPhone
	}
	if d := len(s) - 1; d < 8 || d > 15 {
		return "", errBadPhone
	}
	return s, nil
}
