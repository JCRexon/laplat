//go:build integration

package auth_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jcrexon/laplat/internal/auth"
	"github.com/jcrexon/laplat/internal/dbtest"
	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/pkg/contracts"
	"github.com/jcrexon/laplat/pkg/token"
)

const testUser = "01ARZ3NDEKTSV4RRFFQ69G5FAV"

type harness struct {
	srv *httptest.Server
	st  *store.Store
	svc *auth.Service
	ctx context.Context
}

// setup boots Postgres, seeds an active verified-adult instructor, and wires the
// full auth stack (minter + store-backed validator + service + HTTP handler).
func setup(t *testing.T) harness {
	t.Helper()
	pg := dbtest.New(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pg.ConnString())
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	st := store.New(pool)

	if _, err := st.CreateUser(ctx, store.NewUser{ID: testUser, Handle: "teacher", DisplayName: "T", CanInstruct: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateIdentityRecord(ctx, testUser); err != nil {
		t.Fatal(err)
	}
	if err := st.VerifyAdultIdentity(ctx, testUser, "ekyc-ref", time.Now().Add(24*30*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := st.ActivateUser(ctx, testUser); err != nil {
		t.Fatal(err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := token.NewSigner("kid-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	minter, err := auth.NewMinter(signer, contracts.TokenIssuer, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	validator := token.NewValidator(token.NewVerifier(map[string]ed25519.PublicKey{"kid-1": pub}), st)
	svc, err := auth.NewService(minter, st, 720*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(auth.NewHandler(svc, validator))
	t.Cleanup(srv.Close)
	return harness{srv: srv, st: st, svc: svc, ctx: ctx}
}

// do issues a request and returns the status and decoded JSON body (if any).
func (h harness) do(t *testing.T, method, path, bearer string, body any) (int, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequest(method, h.srv.URL+path, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestHTTP_RefreshRotationAndReuse(t *testing.T) {
	h := setup(t)
	sess, err := h.svc.IssueSession(h.ctx, testUser)
	if err != nil {
		t.Fatalf("bootstrap issue: %v", err)
	}

	// /me with the access token returns the subject and capabilities.
	status, body := h.do(t, "GET", "/v1/me", sess.AccessToken, nil)
	if status != http.StatusOK {
		t.Fatalf("/me status = %d, body %v", status, body)
	}
	if body["userId"] != testUser {
		t.Fatalf("/me userId = %v, want %v", body["userId"], testUser)
	}

	// Refresh rotates into a new pair.
	status, body = h.do(t, "POST", "/v1/token/refresh", "", map[string]string{"refreshToken": sess.RefreshToken})
	if status != http.StatusOK {
		t.Fatalf("refresh status = %d, body %v", status, body)
	}
	rotated, _ := body["refreshToken"].(string)
	if rotated == "" || rotated == sess.RefreshToken {
		t.Fatalf("refresh did not rotate the token: %q", rotated)
	}

	// Reusing the original (now rotated) refresh token is rejected (A-5)...
	status, _ = h.do(t, "POST", "/v1/token/refresh", "", map[string]string{"refreshToken": sess.RefreshToken})
	if status != http.StatusUnauthorized {
		t.Fatalf("reuse status = %d, want 401", status)
	}
	// ...and poisons the family, so the otherwise-valid rotated token also dies.
	status, _ = h.do(t, "POST", "/v1/token/refresh", "", map[string]string{"refreshToken": rotated})
	if status != http.StatusUnauthorized {
		t.Fatalf("post-reuse rotated status = %d, want 401", status)
	}
}

func TestHTTP_Logout(t *testing.T) {
	h := setup(t)
	sess, err := h.svc.IssueSession(h.ctx, testUser)
	if err != nil {
		t.Fatal(err)
	}

	status, _ := h.do(t, "POST", "/v1/token/logout", sess.AccessToken, map[string]string{"refreshToken": sess.RefreshToken})
	if status != http.StatusNoContent {
		t.Fatalf("logout status = %d, want 204", status)
	}
	// Refresh token is dead.
	status, _ = h.do(t, "POST", "/v1/token/refresh", "", map[string]string{"refreshToken": sess.RefreshToken})
	if status != http.StatusUnauthorized {
		t.Fatalf("refresh after logout = %d, want 401", status)
	}
	// Access token's jti is denylisted, so protected routes reject it.
	status, _ = h.do(t, "GET", "/v1/me", sess.AccessToken, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("/me after logout = %d, want 401", status)
	}
}

func TestHTTP_UnauthorizedAndMalformed(t *testing.T) {
	h := setup(t)

	if status, _ := h.do(t, "GET", "/v1/me", "", nil); status != http.StatusUnauthorized {
		t.Fatalf("/me without token = %d, want 401", status)
	}
	if status, _ := h.do(t, "GET", "/v1/me", "not-a-real-token", nil); status != http.StatusUnauthorized {
		t.Fatalf("/me with garbage token = %d, want 401", status)
	}
	if status, _ := h.do(t, "POST", "/v1/token/refresh", "", map[string]string{"refreshToken": ""}); status != http.StatusBadRequest {
		t.Fatalf("empty refresh = %d, want 400", status)
	}
}

// A suspended account cannot mint a new session even with a valid refresh token
// — status is re-checked from the DB on every refresh.
func TestHTTP_SuspendedAccountCannotRefresh(t *testing.T) {
	h := setup(t)
	sess, err := h.svc.IssueSession(h.ctx, testUser)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.st.SuspendUser(h.ctx, testUser); err != nil {
		t.Fatal(err)
	}
	status, _ := h.do(t, "POST", "/v1/token/refresh", "", map[string]string{"refreshToken": sess.RefreshToken})
	if status != http.StatusForbidden {
		t.Fatalf("suspended refresh = %d, want 403", status)
	}
}
