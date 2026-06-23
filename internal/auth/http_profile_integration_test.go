//go:build integration

package auth_test

import (
	"net/http"
	"testing"

	"github.com/jcrexon/laplat/internal/store"
)

// A user can set a real handle/display name/bio; a taken handle is 409 and a
// malformed handle is 400.
func TestHTTP_UpdateProfile(t *testing.T) {
	h := setup(t)
	sess, err := h.svc.IssueSession(h.ctx, testUser)
	if err != nil {
		t.Fatal(err)
	}

	// Another account already holds "taken".
	if _, err := h.st.CreateUser(h.ctx, store.NewUser{
		ID: "01ARZ3NDEKTSV4RRFFQ69G5FB0", Handle: "taken", DisplayName: "T",
	}); err != nil {
		t.Fatal(err)
	}

	// Valid update.
	status, _ := h.do(t, "PATCH", "/v1/me", sess.AccessToken, map[string]string{
		"handle": "real_handle", "displayName": "Real Name", "bio": "hello",
	})
	if status != http.StatusNoContent {
		t.Fatalf("update status = %d, want 204", status)
	}
	u, _ := h.st.GetUser(h.ctx, testUser)
	if u.Handle != "real_handle" || u.DisplayName != "Real Name" {
		t.Fatalf("profile not updated: handle=%q name=%q", u.Handle, u.DisplayName)
	}

	// Taken handle -> 409.
	status, _ = h.do(t, "PATCH", "/v1/me", sess.AccessToken, map[string]string{
		"handle": "taken", "displayName": "X",
	})
	if status != http.StatusConflict {
		t.Fatalf("taken handle status = %d, want 409", status)
	}

	// Malformed handle -> 400.
	status, _ = h.do(t, "PATCH", "/v1/me", sess.AccessToken, map[string]string{
		"handle": "Bad Handle!", "displayName": "X",
	})
	if status != http.StatusBadRequest {
		t.Fatalf("bad handle status = %d, want 400", status)
	}

	// Unauthenticated -> 401.
	status, _ = h.do(t, "PATCH", "/v1/me", "", map[string]string{"handle": "x", "displayName": "y"})
	if status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", status)
	}
}

// Logout-everywhere revokes all of a user's sessions: existing access tokens
// stop validating and refresh tokens can no longer rotate (but the account
// stays active and can log in again).
func TestHTTP_LogoutEverywhere(t *testing.T) {
	h := setup(t)
	a, _ := h.svc.IssueSession(h.ctx, testUser)
	b, _ := h.svc.IssueSession(h.ctx, testUser) // a second device

	if status, _ := h.do(t, "POST", "/v1/token/logout-all", a.AccessToken, nil); status != http.StatusNoContent {
		t.Fatalf("logout-all status = %d, want 204", status)
	}

	// Both devices' access tokens are now revoked.
	for _, tok := range []string{a.AccessToken, b.AccessToken} {
		if status, _ := h.do(t, "GET", "/v1/me", tok, nil); status != http.StatusUnauthorized {
			t.Fatalf("post-logout-all /me = %d, want 401", status)
		}
	}
	// And neither refresh token can rotate.
	if status, _ := h.do(t, "POST", "/v1/token/refresh", "", map[string]string{"refreshToken": b.RefreshToken}); status == http.StatusOK {
		t.Fatal("refresh after logout-all should fail")
	}
	// The account itself is still active.
	if u, _ := h.st.GetUser(h.ctx, testUser); u.Status != "active" {
		t.Fatalf("status = %q, want active (logout-all must not delete)", u.Status)
	}
}

// Closing an account soft-deletes it and revokes outstanding tokens immediately.
func TestHTTP_CloseAccount(t *testing.T) {
	h := setup(t)
	sess, err := h.svc.IssueSession(h.ctx, testUser)
	if err != nil {
		t.Fatal(err)
	}

	// The access token works before closing.
	if status, _ := h.do(t, "GET", "/v1/me", sess.AccessToken, nil); status != http.StatusOK {
		t.Fatalf("pre-close /me = %d, want 200", status)
	}

	if status, _ := h.do(t, "DELETE", "/v1/me", sess.AccessToken, nil); status != http.StatusNoContent {
		t.Fatalf("close status = %d, want 204", status)
	}

	// Soft-deleted in the DB.
	if u, _ := h.st.GetUser(h.ctx, testUser); u.Status != "deleted" {
		t.Fatalf("status after close = %q, want deleted", u.Status)
	}
	// The same access token is now revoked (token_version bumped).
	if status, _ := h.do(t, "GET", "/v1/me", sess.AccessToken, nil); status != http.StatusUnauthorized {
		t.Fatalf("post-close /me = %d, want 401 (revoked)", status)
	}
	// And refresh is refused.
	if status, _ := h.do(t, "POST", "/v1/token/refresh", "", map[string]string{"refreshToken": sess.RefreshToken}); status == http.StatusOK {
		t.Fatal("refresh after close should fail")
	}
}
