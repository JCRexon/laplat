//go:build integration

package moderation_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jcrexon/laplat/internal/dbtest"
	"github.com/jcrexon/laplat/internal/moderation"
	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/pkg/contracts"
)

func newSvc(t *testing.T) (*moderation.Service, *store.Store, context.Context) {
	t.Helper()
	pg := dbtest.New(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pg.ConnString())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	st := store.New(pool)
	svc, err := moderation.NewService(st)
	if err != nil {
		t.Fatal(err)
	}
	return svc, st, ctx
}

// mkActiveAdult creates a verified-adult, active user.
func mkActiveAdult(t *testing.T, st *store.Store, ctx context.Context, id string) {
	t.Helper()
	if _, err := st.CreateUser(ctx, store.NewUser{ID: id, Handle: id, DisplayName: id}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateIdentityRecord(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := st.VerifyAdultIdentity(ctx, id, "ref", time.Now().Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := st.ActivateUser(ctx, id); err != nil {
		t.Fatal(err)
	}
}

func modClaims(id string) *contracts.AccessTokenClaims {
	return &contracts.AccessTokenClaims{Subject: id, Capabilities: []contracts.Capability{contracts.CapPlatformModerator}}
}

// A moderator suspends a user (revoking sessions) and reinstates them; a
// non-moderator is forbidden.
func TestModeration_SuspendReinstate(t *testing.T) {
	svc, st, ctx := newSvc(t)
	mkActiveAdult(t, st, ctx, "mod")
	mkActiveAdult(t, st, ctx, "target")

	// Give the target a live refresh token so we can see it revoked.
	if err := st.IssueRefreshToken(ctx, "target", store.NewRefreshToken{
		ID: "rt-1", Hash: []byte("hash"), ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	// Non-moderator cannot suspend.
	if err := svc.Suspend(ctx, &contracts.AccessTokenClaims{Subject: "x"}, "target"); err != moderation.ErrForbidden {
		t.Fatalf("non-mod suspend = %v, want ErrForbidden", err)
	}

	// Moderator suspends.
	if err := svc.Suspend(ctx, modClaims("mod"), "target"); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if u, _ := st.GetUser(ctx, "target"); u.Status != "suspended" {
		t.Fatalf("status = %q, want suspended", u.Status)
	}
	// token_version bumped (sessions revoked).
	if tv, _ := st.CurrentTokenVersion(ctx, "target"); tv == 0 {
		t.Fatal("token_version should have been bumped on suspend")
	}

	// Reinstate (the user is still a verified adult, so activation passes).
	if err := svc.Reinstate(ctx, modClaims("mod"), "target"); err != nil {
		t.Fatalf("reinstate: %v", err)
	}
	if u, _ := st.GetUser(ctx, "target"); u.Status != "active" {
		t.Fatalf("status after reinstate = %q, want active", u.Status)
	}
}

// A moderator can grant and revoke the instructor capability; a non-moderator
// cannot.
func TestModeration_SetInstructor(t *testing.T) {
	svc, st, ctx := newSvc(t)
	mkActiveAdult(t, st, ctx, "mod")
	mkActiveAdult(t, st, ctx, "target")

	if err := svc.SetInstructor(ctx, &contracts.AccessTokenClaims{Subject: "x"}, "target", true); err != moderation.ErrForbidden {
		t.Fatalf("non-mod grant = %v, want ErrForbidden", err)
	}

	if err := svc.SetInstructor(ctx, modClaims("mod"), "target", true); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if u, _ := st.GetUser(ctx, "target"); !u.CanInstruct {
		t.Fatal("target should be an instructor after grant")
	}

	if err := svc.SetInstructor(ctx, modClaims("mod"), "target", false); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if u, _ := st.GetUser(ctx, "target"); u.CanInstruct {
		t.Fatal("target should not be an instructor after revoke")
	}
}
