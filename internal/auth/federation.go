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

// ErrUnknownProvider means the requested federated provider is not configured.
var ErrUnknownProvider = errors.New("auth: unknown federated provider")

// allowedProviders matches the federated_identities provider CHECK constraint.
var allowedProviders = map[string]bool{"google": true, "apple": true, "zalo": true}

// BindingKind tells the HTTP layer how to derive the authorize-request
// challenge from the per-login secret it stores in a cookie.
type BindingKind int

const (
	// BindingNonce (OIDC): the challenge sent to the provider IS the secret (an
	// opaque nonce), echoed back inside the signed id_token and checked there.
	BindingNonce BindingKind = iota
	// BindingPKCE (OAuth2): the challenge is the S256 hash of the secret (the
	// code_verifier); the verifier itself is presented at token exchange.
	BindingPKCE
)

// Connector is the mechanics of one federated-login provider. OIDC providers
// (Google/Apple) verify a signed id_token; OAuth2 providers (Zalo) exchange the
// code for an access token and read a userinfo endpoint. Both resolve a stable
// external subject used for (provider, subject) linkage.
type Connector interface {
	// Authorize builds the provider's authorization-redirect URL, binding state
	// (CSRF) and challenge (nonce or PKCE code_challenge).
	Authorize(state, challenge string) (string, error)
	// Resolve exchanges the callback code for a verified external subject.
	// secret is the cleartext binding from the callback cookie: the nonce (OIDC)
	// or the PKCE code_verifier (OAuth2).
	Resolve(ctx context.Context, code, secret string) (subject string, err error)
	// Binding reports the binding kind (so the HTTP layer derives the challenge).
	Binding() BindingKind
}

// Exchanger swaps an authorization code for a raw ID token at an OIDC provider's
// token endpoint (Google/Apple). A boundary so the network call and client
// secret (Apple's is a signed JWT) live behind a fake in tests.
type Exchanger interface {
	Exchange(ctx context.Context, code, redirectURI string) (rawIDToken string, err error)
}

// PKCEExchanger swaps a code (+ PKCE code_verifier) for an OAuth2 access token.
type PKCEExchanger interface {
	Exchange(ctx context.Context, code, redirectURI, codeVerifier string) (accessToken string, err error)
}

// UserInfoFetcher resolves an OAuth2 access token to a stable provider subject.
type UserInfoFetcher interface {
	Subject(ctx context.Context, accessToken string) (string, error)
}

// --- OIDC connector (Google / Apple) -----------------------------------------

type oidcConnector struct {
	verifier    *oidc.Provider
	exchanger   Exchanger
	authURL     string
	clientID    string
	redirectURL string
	scopes      []string
}

// NewOIDCConnector builds a Google/Apple connector (verify a signed id_token).
func NewOIDCConnector(verifier *oidc.Provider, exchanger Exchanger, authURL, clientID, redirectURL string, scopes []string) (Connector, error) {
	if verifier == nil || exchanger == nil {
		return nil, errors.New("auth: oidc connector requires verifier and exchanger")
	}
	return &oidcConnector{verifier, exchanger, authURL, clientID, redirectURL, scopes}, nil
}

func (c *oidcConnector) Binding() BindingKind { return BindingNonce }

func (c *oidcConnector) Authorize(state, nonce string) (string, error) {
	u, err := url.Parse(c.authURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("client_id", c.clientID)
	q.Set("redirect_uri", c.redirectURL)
	q.Set("response_type", "code")
	q.Set("scope", strings.Join(c.scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (c *oidcConnector) Resolve(ctx context.Context, code, nonce string) (string, error) {
	raw, err := c.exchanger.Exchange(ctx, code, c.redirectURL)
	if err != nil {
		return "", err
	}
	claims, err := c.verifier.Verify(ctx, raw, nonce)
	if err != nil {
		return "", err
	}
	return claims.Subject, nil
}

// --- Zalo connector (OAuth2 + userinfo) --------------------------------------

type zaloConnector struct {
	exchanger   PKCEExchanger
	userinfo    UserInfoFetcher
	authURL     string
	appID       string
	redirectURL string
}

// NewZaloConnector builds the Zalo connector. Zalo Login is OAuth 2.0 with PKCE
// (no id_token): the code is exchanged for an access token, then a userinfo
// call yields the stable Zalo user id used as the subject.
func NewZaloConnector(exchanger PKCEExchanger, userinfo UserInfoFetcher, authURL, appID, redirectURL string) (Connector, error) {
	if exchanger == nil || userinfo == nil {
		return nil, errors.New("auth: zalo connector requires exchanger and userinfo")
	}
	return &zaloConnector{exchanger, userinfo, authURL, appID, redirectURL}, nil
}

func (c *zaloConnector) Binding() BindingKind { return BindingPKCE }

func (c *zaloConnector) Authorize(state, codeChallenge string) (string, error) {
	u, err := url.Parse(c.authURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("app_id", c.appID)
	q.Set("redirect_uri", c.redirectURL)
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (c *zaloConnector) Resolve(ctx context.Context, code, codeVerifier string) (string, error) {
	accessToken, err := c.exchanger.Exchange(ctx, code, c.redirectURL, codeVerifier)
	if err != nil {
		return "", err
	}
	return c.userinfo.Subject(ctx, accessToken)
}

// --- federation --------------------------------------------------------------

// FederationStore is the persistence the login flow needs (*store.Store fits).
type FederationStore interface {
	GetFederatedIdentity(ctx context.Context, provider, subject string) (store.FederatedIdentity, error)
	CreateUser(ctx context.Context, u store.NewUser) (store.User, error)
	CreateIdentityRecord(ctx context.Context, userID string) error
	LinkFederatedIdentity(ctx context.Context, provider, subject, userID string) error
	TouchFederatedLogin(ctx context.Context, provider, subject string) error
}

// Federation turns a verified federated login into a local session. A first-time
// login creates a PENDING local user (no capabilities, identity "none") — a
// federated login proves account control, not adulthood, so the user must still
// pass the phone/eKYC tiers. Linkage is strictly by (provider, subject); never
// by email.
type Federation struct {
	connectors map[string]Connector
	store      FederationStore
	sessions   *Service

	NewUserID func() string
	NewHandle func() string
}

// NewFederation validates and wires the connectors. Provider keys must be in the
// federated_identities CHECK set (google/apple/zalo).
func NewFederation(st FederationStore, sessions *Service, connectors map[string]Connector) (*Federation, error) {
	if st == nil || sessions == nil {
		return nil, errors.New("auth: federation requires store and sessions")
	}
	for name, c := range connectors {
		if !allowedProviders[name] {
			return nil, errors.New("auth: federation provider not allowed: " + name)
		}
		if c == nil {
			return nil, errors.New("auth: federation connector nil for " + name)
		}
	}
	return &Federation{
		connectors: connectors,
		store:      st,
		sessions:   sessions,
		NewUserID:  newOpaqueID,
		NewHandle:  newHandle,
	}, nil
}

// Binding returns the provider's binding kind (and whether it is configured),
// so the HTTP layer derives the right authorize challenge.
func (f *Federation) Binding(provider string) (BindingKind, bool) {
	c, ok := f.connectors[provider]
	if !ok {
		return 0, false
	}
	return c.Binding(), true
}

// Authorize builds the provider authorization redirect for the start step.
func (f *Federation) Authorize(provider, state, challenge string) (string, error) {
	c, ok := f.connectors[provider]
	if !ok {
		return "", ErrUnknownProvider
	}
	return c.Authorize(state, challenge)
}

// Complete resolves the callback to a verified subject, resolves or creates the
// local user, and issues a session. All verification failures collapse to
// ErrUnauthenticated (no oracle).
func (f *Federation) Complete(ctx context.Context, provider, code, secret string) (Session, error) {
	c, ok := f.connectors[provider]
	if !ok {
		return Session{}, ErrUnknownProvider
	}
	subject, err := c.Resolve(ctx, code, secret)
	if err != nil || subject == "" {
		return Session{}, ErrUnauthenticated
	}
	userID, err := f.resolveUser(ctx, provider, subject)
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
// completion (choosing a real handle, PATCH /v1/me) is a later step.
func newHandle() string {
	const alpha = "abcdefghijklmnopqrstuvwxyz0123456789"
	var b [12]byte
	mustRand(b[:])
	for i := range b {
		b[i] = alpha[int(b[i])%len(alpha)]
	}
	return "u" + string(b[:])
}
