//go:build integration

package auth_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/pkg/contracts"
)

// A verified (eKYC) user can self-grant the instructor capability; a fresh token
// then carries can_instruct. A merely phone-verified user cannot.
func TestHTTP_BecomeInstructor(t *testing.T) {
	h := setup(t)

	// A verified-adult, active user who is NOT yet an instructor.
	const uid = "01ARZ3NDEKTSV4RRFFQ69G5FB2"
	if _, err := h.st.CreateUser(h.ctx, store.NewUser{ID: uid, Handle: "applicant", DisplayName: "A"}); err != nil {
		t.Fatal(err)
	}
	if err := h.st.CreateIdentityRecord(h.ctx, uid); err != nil {
		t.Fatal(err)
	}
	if err := h.st.VerifyAdultIdentity(h.ctx, uid, "ref", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := h.st.ActivateUser(h.ctx, uid); err != nil {
		t.Fatal(err)
	}

	sess, err := h.svc.IssueSession(h.ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	if !sess.AccessClaims.IsVerifiedAdult() {
		t.Fatalf("precondition: should be verified, idv=%q", sess.AccessClaims.IdentityVerification)
	}
	if sess.AccessClaims.HasCapability(contracts.CapCanInstruct) {
		t.Fatal("precondition: should not yet be an instructor")
	}

	if status, _ := h.do(t, "POST", "/v1/instructor/apply", sess.AccessToken, nil); status != http.StatusNoContent {
		t.Fatalf("apply status = %d, want 204", status)
	}

	// A fresh token now carries can_instruct.
	next, _ := h.svc.IssueSession(h.ctx, uid)
	if !next.AccessClaims.HasCapability(contracts.CapCanInstruct) {
		t.Fatalf("post-apply token missing can_instruct: %v", next.AccessClaims.Capabilities)
	}
}

// A non-verified (only phone-verified) user is refused.
func TestHTTP_BecomeInstructor_RequiresVerified(t *testing.T) {
	h := setup(t)

	// A separate user who is phone-verified but NOT eKYC-verified.
	const uid = "01ARZ3NDEKTSV4RRFFQ69G5FB1"
	if _, err := h.st.CreateUser(h.ctx, store.NewUser{ID: uid, Handle: "phoneonly", DisplayName: "P"}); err != nil {
		t.Fatal(err)
	}
	if err := h.st.CreateIdentityRecord(h.ctx, uid); err != nil {
		t.Fatal(err)
	}
	if err := h.st.AcceptToS(h.ctx, uid, contracts.CurrentToSVersion, true); err != nil {
		t.Fatal(err)
	}
	if err := h.st.LinkPhoneIdentity(h.ctx, "+84900000001", uid); err != nil {
		t.Fatal(err)
	}
	if err := h.st.ActivateUser(h.ctx, uid); err != nil {
		t.Fatal(err)
	}
	sess, _ := h.svc.IssueSession(h.ctx, uid)
	if sess.AccessClaims.IdentityVerification != contracts.IdentityPhoneVerified {
		t.Fatalf("precondition: want phone_verified, got %q", sess.AccessClaims.IdentityVerification)
	}

	if status, _ := h.do(t, "POST", "/v1/instructor/apply", sess.AccessToken, nil); status != http.StatusForbidden {
		t.Fatalf("phone-only apply status = %d, want 403", status)
	}
}
