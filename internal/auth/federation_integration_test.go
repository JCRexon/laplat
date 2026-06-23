//go:build integration

package auth_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jcrexon/laplat/internal/auth"
	"github.com/jcrexon/laplat/internal/dbtest"
	"github.com/jcrexon/laplat/internal/oidc"
	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/pkg/contracts"
	"github.com/jcrexon/laplat/pkg/token"
)

var b64u = base64.RawURLEncoding

// fakeExchanger returns a preset raw ID token regardless of the code.
type fakeExchanger struct{ token string }

func (f *fakeExchanger) Exchange(_ context.Context, _, _ string) (string, error) {
	return f.token, nil
}

// rsaIDToken builds and signs a Google-style RS256 ID token, and a JWKS doc for
// the matching public key.
func rsaIDToken(t *testing.T, sub, nonce string) (idToken string, jwks []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims := map[string]any{
		"iss": "https://accounts.google.com", "sub": sub, "aud": "client-abc",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Add(-time.Minute).Unix(),
		"nonce": nonce, "email": sub + "@example.com", "email_verified": true,
	}
	hb, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "r1"})
	cb, _ := json.Marshal(claims)
	signingInput := b64u.EncodeToString(hb) + "." + b64u.EncodeToString(cb)
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}
	idToken = signingInput + "." + b64u.EncodeToString(sig)

	doc, _ := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": "r1", "alg": "RS256",
		"n": b64u.EncodeToString(key.N.Bytes()),
		"e": b64u.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}}})
	return idToken, doc
}

// fedHarness wires a store-backed auth stack with a Google OIDC provider whose
// token endpoint is the fake exchanger and whose JWKS is the local test key.
type fedHarness struct {
	srv *httptest.Server
	st  *store.Store
	fed *auth.Federation
	ctx context.Context
}

func newFedHarness(t *testing.T, idToken string, jwks []byte) fedHarness {
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
	validator := token.NewValidator(token.NewVerifier(map[string]ed25519.PublicKey{"kid-1": pub}), st)
	svc, _ := auth.NewService(minter, st, 720*time.Hour)

	keys, err := oidc.ParseJWKS(jwks)
	if err != nil {
		t.Fatal(err)
	}
	provider := &auth.OIDCProvider{
		Verifier:    &oidc.Provider{Name: "google", Issuer: "https://accounts.google.com", Audience: "client-abc", Keys: keys},
		Exchanger:   &fakeExchanger{token: idToken},
		AuthURL:     "https://accounts.google.com/o/oauth2/v2/auth",
		ClientID:    "client-abc",
		RedirectURL: "https://laplat.test/v1/auth/oidc/google/callback",
		Scopes:      []string{"openid", "email"},
	}
	fed, err := auth.NewFederation(st, svc, map[string]*auth.OIDCProvider{"google": provider})
	if err != nil {
		t.Fatal(err)
	}
	h := auth.NewHandler(svc, validator)
	h.RegisterOIDC(fed)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return fedHarness{srv: srv, st: st, fed: fed, ctx: ctx}
}

// First login creates a pending local user, links it, and issues a session;
// the second login with the same subject reuses that user.
func TestFederation_Complete_CreatesAndLinks(t *testing.T) {
	idTok, jwks := rsaIDToken(t, "google-sub-1", "")
	h := newFedHarness(t, idTok, jwks)

	sess, err := h.fed.Complete(h.ctx, "google", "any-code", "")
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	userID := sess.AccessClaims.Subject
	if userID == "" {
		t.Fatal("no subject in issued token")
	}
	// New user is pending, no caps, identity "none" (OIDC != eKYC).
	u, _ := h.st.GetUser(h.ctx, userID)
	if u.Status != "pending" {
		t.Fatalf("federated user status = %q, want pending", u.Status)
	}
	if len(sess.AccessClaims.Capabilities) != 0 {
		t.Fatalf("federated user should have no caps, got %v", sess.AccessClaims.Capabilities)
	}
	if sess.AccessClaims.IdentityVerification != contracts.IdentityNone {
		t.Fatalf("idv = %q, want none", sess.AccessClaims.IdentityVerification)
	}
	fed, err := h.st.GetFederatedIdentity(h.ctx, "google", "google-sub-1")
	if err != nil || fed.UserID != userID {
		t.Fatalf("federated link not stored: %v / %q", err, fed.UserID)
	}

	// Second login, same subject -> same user (no duplicate).
	sess2, err := h.fed.Complete(h.ctx, "google", "any-code", "")
	if err != nil {
		t.Fatal(err)
	}
	if sess2.AccessClaims.Subject != userID {
		t.Fatalf("second login created a new user %q, want %q", sess2.AccessClaims.Subject, userID)
	}
}

// Full HTTP flow: start sets state+nonce cookies and redirects; the callback
// (with a token whose nonce matches the cookie) returns a session.
func TestHTTP_OIDC_StartThenCallback(t *testing.T) {
	// Start first with no token so we can read the generated nonce, then build a
	// token bound to it.
	h := newFedHarness(t, "", mustJWKSForStart(t))

	// Don't follow redirects; capture cookies.
	client := h.srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	resp, err := client.Get(h.srv.URL + "/v1/auth/oidc/google/start")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start status = %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "client_id=client-abc") || !strings.Contains(loc, "state=") {
		t.Fatalf("authorize URL missing params: %s", loc)
	}
	var state, nonce string
	for _, c := range resp.Cookies() {
		switch c.Name {
		case "laplat_oidc_state":
			state = c.Value
		case "laplat_oidc_nonce":
			nonce = c.Value
		}
	}
	if state == "" || nonce == "" {
		t.Fatal("start did not set state/nonce cookies")
	}

	// Build a token bound to the issued nonce and point the exchanger at it.
	idTok, jwks := rsaIDToken(t, "google-sub-http", nonce)
	keys, _ := oidc.ParseJWKS(jwks)
	// Reconfigure the provider's verifier+exchanger with the matching key/token.
	h.fed = nil // not used past here
	srv2 := startCallbackServer(t, idTok, keys)
	defer srv2.Close()

	// Mismatched state -> 401.
	req, _ := http.NewRequest("GET", srv2.URL+"/v1/auth/oidc/google/callback?code=x&state=WRONG", nil)
	req.AddCookie(&http.Cookie{Name: "laplat_oidc_state", Value: "RIGHT"})
	bad, _ := srv2.Client().Do(req)
	if bad.StatusCode != http.StatusUnauthorized {
		t.Fatalf("state mismatch status = %d, want 401", bad.StatusCode)
	}
	bad.Body.Close()

	// Matching state but NO nonce cookie -> 401. The nonce binding is mandatory
	// and must not be skippable by dropping the cookie.
	reqNoNonce, _ := http.NewRequest("GET", srv2.URL+"/v1/auth/oidc/google/callback?code=x&state=S", nil)
	reqNoNonce.AddCookie(&http.Cookie{Name: "laplat_oidc_state", Value: "S"})
	noNonce, _ := srv2.Client().Do(reqNoNonce)
	if noNonce.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing nonce status = %d, want 401", noNonce.StatusCode)
	}
	noNonce.Body.Close()

	// Matching state + nonce -> 200 with a session.
	req2, _ := http.NewRequest("GET", srv2.URL+"/v1/auth/oidc/google/callback?code=x&state=S", nil)
	req2.AddCookie(&http.Cookie{Name: "laplat_oidc_state", Value: "S"})
	req2.AddCookie(&http.Cookie{Name: "laplat_oidc_nonce", Value: nonce})
	ok, err := srv2.Client().Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("callback status = %d, want 200", ok.StatusCode)
	}
	var body map[string]any
	_ = json.NewDecoder(ok.Body).Decode(&body)
	if body["accessToken"] == nil || body["refreshToken"] == nil {
		t.Fatalf("callback did not return a session: %v", body)
	}
}

// startCallbackServer builds a fresh store-backed server whose google provider
// uses the given token + keys (so the callback's nonce check can pass).
func startCallbackServer(t *testing.T, idToken string, keys oidc.KeySet) *httptest.Server {
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
	validator := token.NewValidator(token.NewVerifier(map[string]ed25519.PublicKey{"kid-1": pub}), st)
	svc, _ := auth.NewService(minter, st, 720*time.Hour)
	provider := &auth.OIDCProvider{
		Verifier:    &oidc.Provider{Name: "google", Issuer: "https://accounts.google.com", Audience: "client-abc", Keys: keys},
		Exchanger:   &fakeExchanger{token: idToken},
		AuthURL:     "https://accounts.google.com/o/oauth2/v2/auth",
		ClientID:    "client-abc",
		RedirectURL: "https://laplat.test/cb",
		Scopes:      []string{"openid", "email"},
	}
	fed, _ := auth.NewFederation(st, svc, map[string]*auth.OIDCProvider{"google": provider})
	h := auth.NewHandler(svc, validator)
	h.RegisterOIDC(fed)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// mustJWKSForStart returns a throwaway JWKS so the start harness can construct a
// provider (the start step doesn't verify tokens).
func mustJWKSForStart(t *testing.T) []byte {
	_, jwks := rsaIDToken(t, "unused", "")
	return jwks
}
