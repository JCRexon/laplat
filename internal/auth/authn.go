package auth

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/jcrexon/laplat/internal/store"
)

// PrincipalKind names the linkage axis a login method authenticates on. It is an
// open set: a new method introduces a new kind and registers a resolver for it.
type PrincipalKind string

const (
	PrincipalEmail     PrincipalKind = "email"
	PrincipalPhone     PrincipalKind = "phone"
	PrincipalFederated PrincipalKind = "federated"
)

// Principal is the proven external identity a login method produces: the stable
// pair linkage keys on. A method's job ends when it returns a Principal;
// Authenticate turns it into a local session. Provider is set only for the
// federated kind (linkage there is by (provider, subject)).
type Principal struct {
	Kind     PrincipalKind
	Provider string
	Subject  string
}

// ErrUnknownAuthMethod means no resolver is registered for a principal's kind.
var ErrUnknownAuthMethod = errors.New("auth: no resolver for principal kind")

// LinkResolver resolves a proven Principal to the local user that owns it,
// creating and linking a pending user on first sight. currentUserID, when
// non-empty, is an already-authenticated caller binding the principal to their
// account (an upgrade); resolvers that don't support upgrades ignore it.
//
// This is the seam: a new login method implements a LinkResolver and registers
// it, and the terminal step (Authenticate -> IssueSession) is reused unchanged.
// Methods stay decoupled — each depends only on this narrow contract and on the
// Principal type, never on each other or on a shared request shape. See
// AUTH-EXTENSIBILITY.md (Brick 1).
type LinkResolver interface {
	Resolve(ctx context.Context, p Principal, currentUserID string) (userID string, err error)
}

// Authenticator turns a proven Principal into a session: it routes to the
// resolver registered for the principal's kind, then issues the session. It is
// the single place the session-issuance dependency lives.
type Authenticator struct {
	sessions  *Service
	resolvers map[PrincipalKind]LinkResolver
}

// NewAuthenticator builds an Authenticator over the session service.
func NewAuthenticator(sessions *Service) (*Authenticator, error) {
	if sessions == nil {
		return nil, errors.New("auth: authenticator requires a session service")
	}
	return &Authenticator{sessions: sessions, resolvers: map[PrincipalKind]LinkResolver{}}, nil
}

// Register wires a resolver for a principal kind. This is the snap-in point.
func (a *Authenticator) Register(kind PrincipalKind, r LinkResolver) {
	a.resolvers[kind] = r
}

// Authenticate resolves the principal to a user and issues a session.
func (a *Authenticator) Authenticate(ctx context.Context, p Principal, currentUserID string) (Session, error) {
	r, ok := a.resolvers[p.Kind]
	if !ok {
		return Session{}, ErrUnknownAuthMethod
	}
	userID, err := r.Resolve(ctx, p, currentUserID)
	if err != nil {
		return Session{}, err
	}
	return a.sessions.IssueSession(ctx, userID)
}

// pendingUserStore is the minimal surface for creating a pending account on
// first login (shared by every resolver).
type pendingUserStore interface {
	CreateUser(ctx context.Context, u store.NewUser) (store.User, error)
	CreateIdentityRecord(ctx context.Context, userID string) error
}

// newPendingUser creates a pending user with a placeholder handle and its
// identity record. A federated/phone/email first login proves account control,
// not adulthood, so the account starts at identity "none" and climbs the tiers
// later. This dedupes the create-and-record dance the three flows shared.
func newPendingUser(ctx context.Context, st pendingUserStore, newID, newHandle func() string) (string, error) {
	userID := newID()
	if _, err := st.CreateUser(ctx, store.NewUser{
		ID: userID, Handle: newHandle(), DisplayName: "New User",
	}); err != nil {
		return "", err
	}
	if err := st.CreateIdentityRecord(ctx, userID); err != nil {
		return "", err
	}
	return userID, nil
}

// --- resolvers (linkage per kind, extracted from the flows) ------------------

type emailResolver struct {
	store     EmailStore
	newID     func() string
	newHandle func() string
}

// NewEmailResolver resolves an email principal: link by normalized email.
func NewEmailResolver(st EmailStore) LinkResolver {
	return &emailResolver{store: st, newID: newOpaqueID, newHandle: newHandle}
}

func (r *emailResolver) Resolve(ctx context.Context, p Principal, _ string) (string, error) {
	id, err := r.store.GetEmailIdentity(ctx, p.Subject)
	if err == nil {
		_ = r.store.TouchEmailLogin(ctx, p.Subject)
		return id.UserID, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	userID, err := newPendingUser(ctx, r.store, r.newID, r.newHandle)
	if err != nil {
		return "", err
	}
	if err := r.store.LinkEmailIdentity(ctx, p.Subject, userID); err != nil {
		return "", err
	}
	return userID, nil
}

type phoneResolver struct {
	store     PhoneStore
	newID     func() string
	newHandle func() string
}

// NewPhoneResolver resolves a phone principal: link by E.164, supporting the
// authenticated-upgrade case (bind a phone to the caller's account).
func NewPhoneResolver(st PhoneStore) LinkResolver {
	return &phoneResolver{store: st, newID: newOpaqueID, newHandle: newHandle}
}

func (r *phoneResolver) Resolve(ctx context.Context, p Principal, currentUserID string) (string, error) {
	existing, err := r.store.GetPhoneIdentity(ctx, p.Subject)
	switch {
	case err == nil:
		// Phone already bound. If a different user is logged in, refuse.
		if currentUserID != "" && currentUserID != existing.UserID {
			return "", ErrPhoneConflict
		}
		_ = r.store.TouchPhoneLogin(ctx, p.Subject)
		return existing.UserID, nil
	case !errors.Is(err, pgx.ErrNoRows):
		return "", err
	}
	// Phone not yet bound.
	if currentUserID != "" {
		// Authenticated upgrade: attach the phone to the caller's account.
		if err := r.store.LinkPhoneIdentity(ctx, p.Subject, currentUserID); err != nil {
			return "", err
		}
		return currentUserID, nil
	}
	// Phone-first signup: new pending user.
	userID, err := newPendingUser(ctx, r.store, r.newID, r.newHandle)
	if err != nil {
		return "", err
	}
	if err := r.store.LinkPhoneIdentity(ctx, p.Subject, userID); err != nil {
		return "", err
	}
	return userID, nil
}

type federatedResolver struct {
	store     FederationStore
	newID     func() string
	newHandle func() string
}

// NewFederatedResolver resolves a federated principal: link by (provider,
// subject), never by email.
func NewFederatedResolver(st FederationStore) LinkResolver {
	return &federatedResolver{store: st, newID: newOpaqueID, newHandle: newHandle}
}

func (r *federatedResolver) Resolve(ctx context.Context, p Principal, _ string) (string, error) {
	fed, err := r.store.GetFederatedIdentity(ctx, p.Provider, p.Subject)
	if err == nil {
		_ = r.store.TouchFederatedLogin(ctx, p.Provider, p.Subject)
		return fed.UserID, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	userID, err := newPendingUser(ctx, r.store, r.newID, r.newHandle)
	if err != nil {
		return "", err
	}
	if err := r.store.LinkFederatedIdentity(ctx, p.Provider, p.Subject, userID); err != nil {
		return "", err
	}
	return userID, nil
}
