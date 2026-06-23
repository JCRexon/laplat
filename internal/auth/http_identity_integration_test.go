//go:build integration

package auth_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
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

// A pending user who self-attests 18+ via the ToS endpoint reaches the
// 'declared' tier: the account activates without eKYC, and a freshly issued
// token carries idv "declared" (not "verified").
func TestHTTP_ToSAccept_GrantsDeclaredTier(t *testing.T) {
	pg := dbtest.New(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pg.ConnString())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	st := store.New(pool)

	const uid = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	if _, err := st.CreateUser(ctx, store.NewUser{ID: uid, Handle: "newbie", DisplayName: "N"}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateIdentityRecord(ctx, uid); err != nil {
		t.Fatal(err)
	}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := token.NewSigner("kid-1", priv)
	minter, _ := auth.NewMinter(signer, contracts.TokenIssuer, 15*time.Minute)
	validator := token.NewValidator(token.NewVerifier(map[string]ed25519.PublicKey{"kid-1": pub}), st)
	svc, _ := auth.NewService(minter, st, 720*time.Hour)
	idSvc, _ := identity.NewService(st, map[string]identity.Verifier{"default": identity.ManualVerifier{}})

	h := auth.NewHandler(svc, validator)
	h.RegisterIdentity(idSvc)

	// A pending user can hold a session (idv none) before declaring.
	sess, err := svc.IssueSession(ctx, uid)
	if err != nil {
		t.Fatalf("issue pending session: %v", err)
	}
	if sess.AccessClaims.IdentityVerification != contracts.IdentityNone {
		t.Fatalf("pre-declare idv = %q, want none", sess.AccessClaims.IdentityVerification)
	}

	// Self-attest 18+ through the endpoint.
	body, _ := json.Marshal(map[string]bool{"adultAttested": true})
	req, _ := http.NewRequest("POST", "/v1/identity/tos-accept", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+sess.AccessToken)
	rec := newRecorder()
	h.ServeHTTP(rec, req)
	if rec.status != http.StatusNoContent {
		t.Fatalf("tos-accept status = %d, want 204", rec.status)
	}

	// The account is now active, and a new token carries the declared tier.
	if u, _ := st.GetUser(ctx, uid); u.Status != "active" {
		t.Fatalf("status after attestation = %q, want active", u.Status)
	}
	next, err := svc.IssueSession(ctx, uid)
	if err != nil {
		t.Fatalf("issue post-declare session: %v", err)
	}
	if next.AccessClaims.IdentityVerification != contracts.IdentityDeclared {
		t.Fatalf("post-declare idv = %q, want declared", next.AccessClaims.IdentityVerification)
	}
	if next.AccessClaims.IsVerifiedAdult() {
		t.Fatal("declared tier must not report verified-adult")
	}
}

// minimal ResponseWriter recorder (avoids importing httptest just for status).
type recorder struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func newRecorder() *recorder { return &recorder{header: http.Header{}, status: http.StatusOK} }

func (r *recorder) Header() http.Header         { return r.header }
func (r *recorder) Write(b []byte) (int, error) { return r.body.Write(b) }
func (r *recorder) WriteHeader(code int)        { r.status = code }
