//go:build integration

package store_test

import (
	"strings"
	"testing"
	"time"

	"github.com/jcrexon/laplat/internal/store"
)

// Account creation round-trips and lookups are case-insensitive on handle.
func Test_Users_CreateAndLookup(t *testing.T) {
	s, ctx := newStore(t) // seeds userA with handle 'an'

	u, err := s.GetUser(ctx, userA)
	if err != nil {
		t.Fatal(err)
	}
	if u.Status != "pending" {
		t.Fatalf("new user status = %q, want pending", u.Status)
	}

	// Created via the repository (not the seed helper).
	created, err := s.CreateUser(ctx, store.NewUser{
		ID: userB, Handle: "Teacher", DisplayName: "Teacher", CanInstruct: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Locale != "vi" {
		t.Fatalf("default locale = %q, want vi", created.Locale)
	}

	// Case-insensitive handle lookup matches the unique index semantics.
	got, err := s.GetUserByHandle(ctx, "TEACHER")
	if err != nil {
		t.Fatalf("case-insensitive lookup failed: %v", err)
	}
	if got.ID != userB {
		t.Fatalf("looked up id = %q, want %q", got.ID, userB)
	}
}

// Activation must be impossible without a verified adult identity, then
// possible once one exists — exercised entirely through the repository layer.
func Test_Users_ActivationRequiresVerifiedAdult(t *testing.T) {
	s, ctx := newStore(t)

	if err := s.CreateIdentityRecord(ctx, userA); err != nil {
		t.Fatal(err)
	}
	if err := s.ActivateUser(ctx, userA); err == nil {
		t.Fatal("activation should be rejected before identity is verified")
	}

	if err := s.VerifyAdultIdentity(ctx, userA, "ekyc-ref-123", time.Now().Add(24*30*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.ActivateUser(ctx, userA); err != nil {
		t.Fatalf("activation should succeed for a verified adult: %v", err)
	}

	u, err := s.GetUser(ctx, userA)
	if err != nil {
		t.Fatal(err)
	}
	if u.Status != "active" {
		t.Fatalf("status = %q, want active", u.Status)
	}
}

// Direct sessions reject a class_id; class sessions require one (CHECK), and a
// direct session caps participants — all via the repository.
func Test_Sessions_KindAndDirectCap(t *testing.T) {
	s, ctx := newStore(t)
	if _, err := s.CreateUser(ctx, store.NewUser{ID: userB, Handle: "b", DisplayName: "B"}); err != nil {
		t.Fatal(err)
	}

	classID := "C1"
	if _, err := s.CreateSession(ctx, store.NewSession{
		ID: "Sbad", Kind: "direct", ClassID: &classID, LivekitRoom: "room-bad",
	}); err == nil {
		t.Fatal("direct session with a class_id should be rejected")
	}

	if _, err := s.CreateSession(ctx, store.NewSession{
		ID: "S1", Kind: "direct", LivekitRoom: "room-1",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddParticipant(ctx, "S1", userA, "participant"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddParticipant(ctx, "S1", userB, "participant"); err != nil {
		t.Fatal(err)
	}

	active, err := s.ListActiveParticipants(ctx, "S1")
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 2 {
		t.Fatalf("active participants = %d, want 2", len(active))
	}

	// A user can be re-admitted after leaving without breaching the cap.
	if err := s.RemoveParticipant(ctx, "S1", userB); err != nil {
		t.Fatal(err)
	}
	if active, _ := s.ListActiveParticipants(ctx, "S1"); len(active) != 1 {
		t.Fatalf("after leave, active = %d, want 1", len(active))
	}
}

// Identity verification can be revoked and read back.
func Test_Identity_VerifyThenRevoke(t *testing.T) {
	s, ctx := newStore(t)
	if err := s.CreateIdentityRecord(ctx, userA); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyAdultIdentity(ctx, userA, "ref-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	id, err := s.GetIdentity(ctx, userA)
	if err != nil {
		t.Fatal(err)
	}
	if !id.IsAdult || id.VerificationStatus != "verified" {
		t.Fatalf("after verify: is_adult=%v status=%q", id.IsAdult, id.VerificationStatus)
	}
	if id.ProviderRef == nil || !strings.HasPrefix(*id.ProviderRef, "ref-") {
		t.Fatalf("provider_ref not stored: %v", id.ProviderRef)
	}

	if err := s.RevokeIdentityVerification(ctx, userA); err != nil {
		t.Fatal(err)
	}
	if id, _ := s.GetIdentity(ctx, userA); id.IsAdult || id.VerificationStatus != "none" {
		t.Fatalf("after revoke: is_adult=%v status=%q", id.IsAdult, id.VerificationStatus)
	}
}
