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
