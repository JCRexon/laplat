package auth

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/jcrexon/laplat/internal/oidc"
	"github.com/jcrexon/laplat/internal/store"
)

// ErrUnknownProvider means the requested OIDC provider is not configured.
var ErrUnknownProvider = errors.New("auth: unknown oidc provider")

// Exchanger swaps an authorization code for a raw ID token at the provider's
// token endpoint. It is an interface so the network call (and provider client
// secrets — Apple's is a signed JWT) lives behind a boundary and tests use a
// fake. Production implementations call the provider over HTTPS.
type Exchanger interface {
	Exchange(ctx context.Context, code, redirectURI string) (rawIDToken string, err error)
}

// OIDCProvider is one configured login provider (google/apple): how to start
// the auth request, how to exchange the code, and how to verify the ID token.
type OIDCProvider struct {
	Verifier    *oidc.Provider
	Exchanger   Exchanger
	AuthURL     string // provider authorization endpoint
	ClientID    string
	RedirectURL string
	Scopes      []string
}

// FederationStore is the persistence the login flow needs (*store.Store fits).
type FederationStore interface {
	GetFederatedIdentity(ctx context.Context, provider, subject string) (store.FederatedIdentity, error)
	CreateUser(ctx context.Context, u store.NewUser) (store.User, error)
	CreateIdentityRecord(ctx context.Context, userID string) error
	LinkFederatedIdentity(ctx context.Context, provider, subject, userID string) error
	TouchFederatedLogin(ctx context.Context, provider, subject string) error
}

// Federation turns a verified OIDC login into a local session. A first-time
// login creates a PENDING local user (no capabilities, identity "none") — OIDC
// proves account control, not adulthood, so the user must still pass eKYC to
// become active. Linkage is strictly by (provider, subject); never by email.
type Federation struct {
	providers map[string]*OIDCProvider
	store     FederationStore
	sessions  *Service

	NewUserID func() string
	NewHandle func() string
}

// NewFederation validates and wires the providers. Keys must be "google" or
// "apple" (matching the federated_identities CHECK).
func NewFederation(st FederationStore, sessions *Service, providers map[string]*OIDCProvider) (*Federation, error) {
	if st == nil || sessions == nil {
		return nil, errors.New("auth: federation requires store and sessions")
	}
	for name, p := range providers {
		if name != "google" && name != "apple" {
			return nil, errors.New("auth: federation provider must be google or apple, got " + name)
		}
		if p.Verifier == nil || p.Exchanger == nil {
			return nil, errors.New("auth: federation provider " + name + " missing verifier/exchanger")
		}
	}
	return &Federation{
		providers: providers,
		store:     st,
		sessions:  sessions,
		NewUserID: newOpaqueID,
		NewHandle: newHandle,
	}, nil
}

// AuthorizeURL builds the provider authorization redirect for the start step,
// binding state (CSRF) and nonce (replay) into the request.
func (f *Federation) AuthorizeURL(provider, state, nonce string) (string, error) {
	p, ok := f.providers[provider]
	if !ok {
		return "", ErrUnknownProvider
	}
	u, err := url.Parse(p.AuthURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("client_id", p.ClientID)
	q.Set("redirect_uri", p.RedirectURL)
	q.Set("response_type", "code")
	q.Set("scope", strings.Join(p.Scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Complete exchanges the code, verifies the ID token (binding expectedNonce),
// resolves or creates the local user, and issues a session. All verification
// failures collapse to ErrUnauthenticated (no oracle).
func (f *Federation) Complete(ctx context.Context, provider, code, expectedNonce string) (Session, error) {
	p, ok := f.providers[provider]
	if !ok {
		return Session{}, ErrUnknownProvider
	}
	raw, err := p.Exchanger.Exchange(ctx, code, p.RedirectURL)
	if err != nil {
		return Session{}, ErrUnauthenticated
	}
	claims, err := p.Verifier.Verify(ctx, raw, expectedNonce)
	if err != nil {
		return Session{}, ErrUnauthenticated
	}
	userID, err := f.resolveUser(ctx, provider, claims.Subject)
	if err != nil {
		return Session{}, err
	}
	return f.sessions.IssueSession(ctx, userID)
}

// resolveUser finds the user linked to (provider, subject) or creates a new
// pending one and links it.
func (f *Federation) resolveUser(ctx context.Context, provider, subject string) (string, error) {
	fed, err := f.store.GetFederatedIdentity(ctx, provider, subject)
	if err == nil {
		_ = f.store.TouchFederatedLogin(ctx, provider, subject)
		return fed.UserID, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}

	userID := f.NewUserID()
	if _, err := f.store.CreateUser(ctx, store.NewUser{
		ID: userID, Handle: f.NewHandle(), DisplayName: "New User",
	}); err != nil {
		return "", err
	}
	if err := f.store.CreateIdentityRecord(ctx, userID); err != nil {
		return "", err
	}
	if err := f.store.LinkFederatedIdentity(ctx, provider, subject, userID); err != nil {
		return "", err
	}
	return userID, nil
}

// newHandle returns a random, unique-by-construction handle satisfying the
// [a-z0-9_] handle rules. Federated users get a placeholder handle; profile
// completion (choosing a real handle) is a later step.
func newHandle() string {
	const alpha = "abcdefghijklmnopqrstuvwxyz0123456789"
	var b [12]byte
	mustRand(b[:])
	for i := range b {
		b[i] = alpha[int(b[i])%len(alpha)]
	}
	return "u" + string(b[:])
}
