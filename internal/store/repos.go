package store

import (
	"context"
	"time"

	"github.com/jcrexon/laplat/internal/store/sqlcdb"
)

// Read models are re-exported from the generated package so callers depend on
// store, not sqlcdb. They are plain data — no behaviour.
type (
	User               = sqlcdb.User
	Identity           = sqlcdb.IdentityVault
	Session            = sqlcdb.Session
	SessionParticipant = sqlcdb.SessionParticipant
)

// --- users -------------------------------------------------------------------

// NewUser is the input to account creation. The id is an opaque ULID minted by
// the caller; no PII is accepted here (it belongs in the identity vault).
type NewUser struct {
	ID          string
	Handle      string
	DisplayName string
	Locale      string
	CanInstruct bool
}

// CreateUser inserts a pending account and returns the stored row.
func (s *Store) CreateUser(ctx context.Context, u NewUser) (User, error) {
	locale := u.Locale
	if locale == "" {
		locale = "vi"
	}
	return s.q.CreateUser(ctx, sqlcdb.CreateUserParams{
		ID:          u.ID,
		Handle:      u.Handle,
		DisplayName: u.DisplayName,
		Locale:      locale,
		CanInstruct: u.CanInstruct,
	})
}

// GetUser fetches a user by id.
func (s *Store) GetUser(ctx context.Context, id string) (User, error) {
	return s.q.GetUser(ctx, id)
}

// UserExists reports whether a user id is present.
func (s *Store) UserExists(ctx context.Context, id string) (bool, error) {
	return s.q.UserExists(ctx, id)
}

// PromoteToModerator grants the platform-moderator capability. Operator-only.
func (s *Store) PromoteToModerator(ctx context.Context, id string) error {
	return s.q.PromoteToModerator(ctx, id)
}

// GetUserByHandle fetches a live (non-deleted) user by case-insensitive handle.
func (s *Store) GetUserByHandle(ctx context.Context, handle string) (User, error) {
	return s.q.GetUserByHandle(ctx, handle)
}

// ActivateUser flips a user to active. The DB rejects this unless a verified
// adult identity exists (trg_enforce_adult_activation), so a caller cannot
// activate an unverified or under-age account even by mistake.
func (s *Store) ActivateUser(ctx context.Context, id string) error {
	return s.q.ActivateUser(ctx, id)
}

// SuspendUser disables an account.
func (s *Store) SuspendUser(ctx context.Context, id string) error {
	return s.q.SuspendUser(ctx, id)
}

// SoftDeleteUser marks an account deleted, preserving the row for referential
// integrity and retention.
func (s *Store) SoftDeleteUser(ctx context.Context, id string) error {
	return s.q.SoftDeleteUser(ctx, id)
}

// --- identity vault ----------------------------------------------------------

// CreateIdentityRecord establishes the (unverified, non-adult) vault row.
func (s *Store) CreateIdentityRecord(ctx context.Context, userID string) error {
	return s.q.CreateIdentityRecord(ctx, userID)
}

// SetIdentityVerificationPending marks an eKYC session as in-flight.
func (s *Store) SetIdentityVerificationPending(ctx context.Context, userID string) error {
	return s.q.SetIdentityVerificationPending(ctx, userID)
}

// VerifyAdultIdentity records a successful eKYC: a verified adult, retained
// until retainUntil (Decree 147). This is what unlocks activation.
func (s *Store) VerifyAdultIdentity(ctx context.Context, userID, providerRef string, retainUntil time.Time) error {
	return s.q.VerifyAdultIdentity(ctx, sqlcdb.VerifyAdultIdentityParams{
		UserID:      userID,
		ProviderRef: &providerRef,
		RetainUntil: &retainUntil,
	})
}

// RevokeIdentityVerification reverses verification. A trigger demotes any
// currently-active user as a side effect (defence in depth).
func (s *Store) RevokeIdentityVerification(ctx context.Context, userID string) error {
	return s.q.RevokeIdentityVerification(ctx, userID)
}

// GetIdentity fetches the vault row for a user.
func (s *Store) GetIdentity(ctx context.Context, userID string) (Identity, error) {
	return s.q.GetIdentity(ctx, userID)
}

// --- federated (OIDC) identities ---------------------------------------------

// FederatedIdentity is the link between an external (provider, subject) and a
// local user. Login factor only — never adult verification.
type FederatedIdentity = sqlcdb.FederatedIdentity

// GetFederatedIdentity looks up the link for a provider+subject. Returns
// pgx.ErrNoRows when absent.
func (s *Store) GetFederatedIdentity(ctx context.Context, provider, subject string) (FederatedIdentity, error) {
	return s.q.GetFederatedIdentity(ctx, sqlcdb.GetFederatedIdentityParams{Provider: provider, Subject: subject})
}

// LinkFederatedIdentity records a new (provider, subject) -> user link.
func (s *Store) LinkFederatedIdentity(ctx context.Context, provider, subject, userID string) error {
	return s.q.LinkFederatedIdentity(ctx, sqlcdb.LinkFederatedIdentityParams{Provider: provider, Subject: subject, UserID: userID})
}

// TouchFederatedLogin updates last_login for an existing link.
func (s *Store) TouchFederatedLogin(ctx context.Context, provider, subject string) error {
	return s.q.TouchFederatedLogin(ctx, sqlcdb.TouchFederatedLoginParams{Provider: provider, Subject: subject})
}

// --- sessions ----------------------------------------------------------------

// NewSession describes a session to create. For kind="direct", ClassID must be
// nil; for kind="class" it must be set (enforced by a CHECK constraint).
type NewSession struct {
	ID             string
	Kind           string
	ClassID        *string
	LivekitRoom    string
	ScheduledStart *time.Time
}

// CreateSession inserts a session and returns the stored row.
func (s *Store) CreateSession(ctx context.Context, sess NewSession) (Session, error) {
	return s.q.CreateSession(ctx, sqlcdb.CreateSessionParams{
		ID:             sess.ID,
		Kind:           sess.Kind,
		ClassID:        sess.ClassID,
		LivekitRoom:    sess.LivekitRoom,
		ScheduledStart: sess.ScheduledStart,
	})
}

// GetSession fetches a session by id.
func (s *Store) GetSession(ctx context.Context, id string) (Session, error) {
	return s.q.GetSession(ctx, id)
}

// StartSession marks a session live.
func (s *Store) StartSession(ctx context.Context, id string) error {
	return s.q.StartSession(ctx, id)
}

// EndSession marks a session ended.
func (s *Store) EndSession(ctx context.Context, id string) error {
	return s.q.EndSession(ctx, id)
}

// AddParticipant admits a user to a session. For direct sessions the DB caps
// concurrent participants at two (trg_enforce_direct_session_cap).
func (s *Store) AddParticipant(ctx context.Context, sessionID, userID, role string) error {
	return s.q.AddParticipant(ctx, sqlcdb.AddParticipantParams{
		SessionID: sessionID,
		UserID:    userID,
		Role:      role,
	})
}

// RemoveParticipant marks a participant as having left (sets left_at).
func (s *Store) RemoveParticipant(ctx context.Context, sessionID, userID string) error {
	return s.q.RemoveParticipant(ctx, sqlcdb.RemoveParticipantParams{
		SessionID: sessionID,
		UserID:    userID,
	})
}

// ListActiveParticipants returns the currently-present participants.
func (s *Store) ListActiveParticipants(ctx context.Context, sessionID string) ([]SessionParticipant, error) {
	return s.q.ListActiveParticipants(ctx, sessionID)
}
