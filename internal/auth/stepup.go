package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jcrexon/laplat/internal/store"
)

// stepUpTTL is how long a step-up grant stays valid after re-verification. Kept
// short: it gates a one-off sensitive view, not an ongoing session.
const stepUpTTL = 5 * time.Minute

// ErrStepUpUnavailable means the account has no factor we can re-challenge (no
// phone or email, or no sender configured for the factor it does have). Federated-
// only accounts hit this until a phone/email is added.
var ErrStepUpUnavailable = errors.New("auth: step-up verification unavailable for this account")

// StepUpStore is the persistence the step-up flow and the protected export need
// (*store.Store satisfies it).
type StepUpStore interface {
	GetIdentityFactors(ctx context.Context, userID string) (store.IdentityFactors, error)

	CreatePhoneChallenge(ctx context.Context, id, phone string, codeHash []byte, expiresAt time.Time) error
	GetActivePhoneChallenge(ctx context.Context, phone string) (store.PhoneChallenge, error)
	IncrementPhoneChallengeAttempts(ctx context.Context, id string) error
	ConsumePhoneChallenge(ctx context.Context, id string) error

	CreateLoginChallenge(ctx context.Context, id, email string, codeHash []byte, expiresAt time.Time) error
	GetActiveLoginChallenge(ctx context.Context, email string) (store.LoginChallenge, error)
	IncrementLoginChallengeAttempts(ctx context.Context, id string) error
	ConsumeLoginChallenge(ctx context.Context, id string) error

	CreateStepUpGrant(ctx context.Context, id, userID string, tokenHash []byte, expiresAt time.Time) error
	StepUpGrantValid(ctx context.Context, userID string, tokenHash []byte) (bool, error)

	// Export reads.
	GetUser(ctx context.Context, id string) (store.User, error)
	GetIdentity(ctx context.Context, userID string) (store.Identity, error)
	EnrolledClassesWithDetails(ctx context.Context, userID string) ([]store.Class, error)
	ListToSAcceptances(ctx context.Context, userID string) ([]store.ToSEntry, error)
	ListSessionHistory(ctx context.Context, userID string) ([]store.SessionEntry, error)
	ListConsentHistory(ctx context.Context, userID string) ([]store.ConsentEntry, error)
}

// StepUp re-verifies a signed-in user via a fresh OTP and, once verified, serves
// the consolidated data export (PDPL right-of-access). It reuses the existing OTP
// challenge tables and senders — the natural step-up for a passwordless platform
// is to re-prove control of the registered factor.
type StepUp struct {
	store StepUpStore
	sms   SMSSender  // may be nil if no SMS sender configured
	email CodeSender // may be nil if no email sender configured

	Now      func() time.Time
	NewID    func() string
	NewCode  func() string
	NewToken func() string
}

// NewStepUp wires the step-up service. At least one sender must be usable for the
// flow to function, but a nil sender is tolerated (the other channel is used).
func NewStepUp(st StepUpStore, sms SMSSender, email CodeSender) (*StepUp, error) {
	if st == nil {
		return nil, errors.New("auth: step-up requires a store")
	}
	return &StepUp{
		store:    st,
		sms:      sms,
		email:    email,
		Now:      time.Now,
		NewID:    newOpaqueID,
		NewCode:  newNumericCode,
		NewToken: newRefreshSecret,
	}, nil
}

// channel picks the factor to re-challenge: phone first (the Decree 147 floor),
// then email. Only a factor with a configured sender is eligible.
type channel struct {
	kind   string // "phone" | "email"
	target string // the phone number or email address
}

func (s *StepUp) pickChannel(f store.IdentityFactors) (channel, bool) {
	if f.Phone != nil && *f.Phone != "" && s.sms != nil {
		return channel{kind: "phone", target: *f.Phone}, true
	}
	if f.Email != nil && *f.Email != "" && s.email != nil {
		return channel{kind: "email", target: *f.Email}, true
	}
	return channel{}, false
}

// RequestResult tells the caller which channel a code went to, with a masked hint
// for display.
type RequestResult struct {
	Channel string // "phone" | "email"
	Hint    string // masked target, e.g. "+84•••789" or "a•••@gmail.com"
}

// RequestCode sends a step-up OTP to the user's registered factor. A fresh
// outstanding challenge within the cooldown suppresses a resend.
func (s *StepUp) RequestCode(ctx context.Context, userID string) (RequestResult, error) {
	factors, err := s.store.GetIdentityFactors(ctx, userID)
	if err != nil {
		return RequestResult{}, err
	}
	ch, ok := s.pickChannel(factors)
	if !ok {
		return RequestResult{}, ErrStepUpUnavailable
	}

	code := s.NewCode()
	switch ch.kind {
	case "phone":
		if active, err := s.store.GetActivePhoneChallenge(ctx, ch.target); err == nil {
			if s.Now().Sub(active.CreatedAt) < resendCooldown {
				return RequestResult{Channel: ch.kind, Hint: maskPhone(ch.target)}, nil
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return RequestResult{}, err
		}
		if err := s.store.CreatePhoneChallenge(ctx, s.NewID(), ch.target, hashSecret(code), s.Now().Add(codeTTL)); err != nil {
			return RequestResult{}, err
		}
		if err := s.sms.SendLoginCode(ctx, ch.target, code); err != nil {
			return RequestResult{}, err
		}
		return RequestResult{Channel: ch.kind, Hint: maskPhone(ch.target)}, nil
	default: // email
		if active, err := s.store.GetActiveLoginChallenge(ctx, ch.target); err == nil {
			if s.Now().Sub(active.CreatedAt) < resendCooldown {
				return RequestResult{Channel: ch.kind, Hint: maskEmail(ch.target)}, nil
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return RequestResult{}, err
		}
		if err := s.store.CreateLoginChallenge(ctx, s.NewID(), ch.target, hashSecret(code), s.Now().Add(codeTTL)); err != nil {
			return RequestResult{}, err
		}
		if err := s.email.SendLoginCode(ctx, ch.target, code); err != nil {
			return RequestResult{}, err
		}
		return RequestResult{Channel: ch.kind, Hint: maskEmail(ch.target)}, nil
	}
}

// Verify checks the step-up code and, on success, mints a short-lived grant. The
// raw grant token is returned exactly once (only its hash is stored).
func (s *StepUp) Verify(ctx context.Context, userID, code string) (token string, expiresAt time.Time, err error) {
	factors, err := s.store.GetIdentityFactors(ctx, userID)
	if err != nil {
		return "", time.Time{}, err
	}
	ch, ok := s.pickChannel(factors)
	if !ok {
		return "", time.Time{}, ErrStepUpUnavailable
	}

	switch ch.kind {
	case "phone":
		c, err := s.store.GetActivePhoneChallenge(ctx, ch.target)
		if err != nil || c.Attempts >= maxCodeAttempts {
			return "", time.Time{}, ErrInvalidCode
		}
		if subtle.ConstantTimeCompare(c.CodeHash, hashSecret(code)) != 1 {
			_ = s.store.IncrementPhoneChallengeAttempts(ctx, c.ID)
			return "", time.Time{}, ErrInvalidCode
		}
		if err := s.store.ConsumePhoneChallenge(ctx, c.ID); err != nil {
			return "", time.Time{}, err
		}
	default: // email
		c, err := s.store.GetActiveLoginChallenge(ctx, ch.target)
		if err != nil || c.Attempts >= maxCodeAttempts {
			return "", time.Time{}, ErrInvalidCode
		}
		if subtle.ConstantTimeCompare(c.CodeHash, hashSecret(code)) != 1 {
			_ = s.store.IncrementLoginChallengeAttempts(ctx, c.ID)
			return "", time.Time{}, ErrInvalidCode
		}
		if err := s.store.ConsumeLoginChallenge(ctx, c.ID); err != nil {
			return "", time.Time{}, err
		}
	}

	raw := s.NewToken()
	exp := s.Now().Add(stepUpTTL)
	if err := s.store.CreateStepUpGrant(ctx, s.NewID(), userID, hashSecret(raw), exp); err != nil {
		return "", time.Time{}, err
	}
	return raw, exp, nil
}

// ValidGrant reports whether the presented raw step-up token is a live grant for
// the user.
func (s *StepUp) ValidGrant(ctx context.Context, userID, rawToken string) (bool, error) {
	if rawToken == "" {
		return false, nil
	}
	return s.store.StepUpGrantValid(ctx, userID, hashSecret(rawToken))
}

// --- consolidated data export (PDPL right-of-access) -------------------------

// Export is the full set of data the platform holds on a user, assembled for the
// right-of-access view. Encrypted identity-vault fields (name, DOB, email-on-file)
// are NOT decrypted here — there is no decryption layer yet and they are only
// ever populated by the (not-yet-wired) eKYC ingestion path; the export reports
// their presence, never their value.
type Export struct {
	Profile  exportProfile  `json:"profile"`
	Identity exportIdentity `json:"identity"`
	Logins   exportFactors  `json:"loginMethods"`
	Enrolled []exportClass  `json:"enrolledClasses"`
	ToS      []exportToS    `json:"tosAcceptances"`
	Activity exportActivity `json:"activity"`
}

type exportProfile struct {
	UserID      string `json:"userId"`
	Handle      string `json:"handle"`
	DisplayName string `json:"displayName"`
	Bio         string `json:"bio"`
	Locale      string `json:"locale"`
	Status      string `json:"status"`
	CreatedAt   string `json:"createdAt"`
}

type exportIdentity struct {
	VerificationStatus string  `json:"verificationStatus"`
	IsAdult            bool    `json:"isAdult"`
	VerifiedAt         *string `json:"verifiedAt"`
	RetainUntil        *string `json:"retainUntil"`
	FullNameOnFile     bool    `json:"fullNameOnFile"`
	DobOnFile          bool    `json:"dobOnFile"`
	EmailOnFile        bool    `json:"emailOnFile"`
}

type exportFactors struct {
	Email     *string  `json:"email"`
	Phone     *string  `json:"phone"`
	Federated []string `json:"federated"`
}

type exportClass struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"`
}

type exportToS struct {
	Version       string `json:"version"`
	AdultAttested bool   `json:"adultAttested"`
	AcceptedAt    string `json:"acceptedAt"`
}

type exportActivity struct {
	SessionCount int `json:"sessionCount"`
	ConsentCount int `json:"consentCount"`
}

// Export assembles everything the platform holds on the user. The caller is
// responsible for having validated a step-up grant first.
func (s *StepUp) Export(ctx context.Context, userID string) (Export, error) {
	user, err := s.store.GetUser(ctx, userID)
	if err != nil {
		return Export{}, err
	}
	id, err := s.store.GetIdentity(ctx, userID)
	if err != nil {
		return Export{}, err
	}
	factors, err := s.store.GetIdentityFactors(ctx, userID)
	if err != nil {
		return Export{}, err
	}
	enrolled, err := s.store.EnrolledClassesWithDetails(ctx, userID)
	if err != nil {
		return Export{}, err
	}
	tos, err := s.store.ListToSAcceptances(ctx, userID)
	if err != nil {
		return Export{}, err
	}
	sessions, err := s.store.ListSessionHistory(ctx, userID)
	if err != nil {
		return Export{}, err
	}
	consents, err := s.store.ListConsentHistory(ctx, userID)
	if err != nil {
		return Export{}, err
	}

	bio := ""
	if user.Bio != nil {
		bio = *user.Bio
	}
	exp := Export{
		Profile: exportProfile{
			UserID:      user.ID,
			Handle:      user.Handle,
			DisplayName: user.DisplayName,
			Bio:         bio,
			Locale:      user.Locale,
			Status:      user.Status,
			CreatedAt:   user.CreatedAt.UTC().Format(time.RFC3339),
		},
		Identity: exportIdentity{
			VerificationStatus: id.VerificationStatus,
			IsAdult:            id.IsAdult,
			VerifiedAt:         formatPtr(id.VerifiedAt),
			RetainUntil:        formatPtr(id.RetainUntil),
			FullNameOnFile:     len(id.FullNameEnc) > 0,
			DobOnFile:          len(id.DobEnc) > 0,
			EmailOnFile:        len(id.EmailEnc) > 0,
		},
		Logins: exportFactors{
			Email:     factors.Email,
			Phone:     factors.Phone,
			Federated: factors.Federated,
		},
		Enrolled: make([]exportClass, 0, len(enrolled)),
		ToS:      make([]exportToS, 0, len(tos)),
		Activity: exportActivity{SessionCount: len(sessions), ConsentCount: len(consents)},
	}
	for _, c := range enrolled {
		exp.Enrolled = append(exp.Enrolled, exportClass{ID: c.ID, Title: c.Title, Status: c.Status})
	}
	for _, t := range tos {
		exp.ToS = append(exp.ToS, exportToS{
			Version:       t.Version,
			AdultAttested: t.AdultAttested,
			AcceptedAt:    t.AcceptedAt.UTC().Format(time.RFC3339),
		})
	}
	return exp, nil
}

func formatPtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format(time.RFC3339)
	return &s
}

// maskPhone shows only the country/leading "+" and the last three digits.
func maskPhone(p string) string {
	if len(p) <= 4 {
		return "•••"
	}
	return p[:1] + "•••" + p[len(p)-3:]
}

// maskEmail shows the first character of the local part and the full domain.
func maskEmail(e string) string {
	at := -1
	for i, r := range e {
		if r == '@' {
			at = i
			break
		}
	}
	if at <= 0 {
		return "•••"
	}
	return e[:1] + "•••" + e[at:]
}
