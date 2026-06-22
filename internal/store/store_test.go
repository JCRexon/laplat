//go:build integration

package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jcrexon/laplat/internal/dbtest"
	"github.com/jcrexon/laplat/internal/store"
)

const (
	userA = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	userB = "01BRZ3NDEKTSV4RRFFQ69G5FAV"
)

// newStore boots a throwaway Postgres, opens a pgx pool against it, seeds one
// user, and returns a Store ready for use.
func newStore(t *testing.T) (*store.Store, context.Context) {
	t.Helper()
	pg := dbtest.New(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pg.ConnString())
	if err != nil {
		t.Fatalf("connect pool: %v", err)
	}
	t.Cleanup(pool.Close)
	pg.MustExec(`INSERT INTO users (id, handle, display_name) VALUES ('` + userA + `', 'an', 'An');`)
	return store.New(pool), ctx
}

func hash(s string) []byte { return []byte("hash-of-" + s) }

// CurrentTokenVersion and the revoke-all bump round-trip through Postgres.
func Test_TokenVersion_RoundTrip(t *testing.T) {
	s, ctx := newStore(t)

	v, err := s.CurrentTokenVersion(ctx, userA)
	if err != nil {
		t.Fatal(err)
	}
	if v != 1 {
		t.Fatalf("seeded token_version = %d, want 1", v)
	}

	next, err := s.RevokeAllForUser(ctx, userA)
	if err != nil {
		t.Fatal(err)
	}
	if next != 2 {
		t.Fatalf("bumped token_version = %d, want 2", next)
	}
	if v, _ := s.CurrentTokenVersion(ctx, userA); v != 2 {
		t.Fatalf("read-back token_version = %d, want 2", v)
	}
}

// The single-token denylist (A-5): a jti is not revoked until written, then is.
func Test_AccessTokenDenylist(t *testing.T) {
	s, ctx := newStore(t)

	if revoked, err := s.IsAccessTokenRevoked(ctx, "jti-1"); err != nil || revoked {
		t.Fatalf("unwritten jti reported revoked=%v err=%v", revoked, err)
	}
	if err := s.RevokeAccessToken(ctx, "jti-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if revoked, err := s.IsAccessTokenRevoked(ctx, "jti-1"); err != nil || !revoked {
		t.Fatalf("written jti reported revoked=%v err=%v", revoked, err)
	}
	// Idempotent: revoking the same jti again must not error.
	if err := s.RevokeAccessToken(ctx, "jti-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("second revoke of same jti errored: %v", err)
	}
}

// Happy-path rotation: a live token rotates once into a fresh token in the same
// family, and the old token is then dead to reuse.
func Test_RotateRefreshToken_HappyPath(t *testing.T) {
	s, ctx := newStore(t)

	if err := s.IssueRefreshToken(ctx, userA, store.NewRefreshToken{
		ID: "rt-1", Hash: hash("rt-1"), ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	rot, err := s.RotateRefreshToken(ctx, hash("rt-1"), store.NewRefreshToken{
		ID: "rt-2", Hash: hash("rt-2"), ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("rotation should succeed: %v", err)
	}
	if rot.UserID != userA {
		t.Fatalf("rotation user = %q, want %q", rot.UserID, userA)
	}
	if rot.FamilyID != "rt-1" {
		t.Fatalf("rotation family = %q, want the original token id rt-1", rot.FamilyID)
	}

	// The replacement is now the live token and rotates again.
	if _, err := s.RotateRefreshToken(ctx, hash("rt-2"), store.NewRefreshToken{
		ID: "rt-3", Hash: hash("rt-3"), ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("replacement should rotate: %v", err)
	}
}

func Test_RotateRefreshToken_NotFoundAndExpired(t *testing.T) {
	s, ctx := newStore(t)

	if _, err := s.RotateRefreshToken(ctx, hash("ghost"), store.NewRefreshToken{
		ID: "x", Hash: hash("x"), ExpiresAt: time.Now().Add(time.Hour),
	}); !errors.Is(err, store.ErrRefreshNotFound) {
		t.Fatalf("unknown token: got %v, want ErrRefreshNotFound", err)
	}

	if err := s.IssueRefreshToken(ctx, userA, store.NewRefreshToken{
		ID: "rt-old", Hash: hash("rt-old"), ExpiresAt: time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RotateRefreshToken(ctx, hash("rt-old"), store.NewRefreshToken{
		ID: "rt-new", Hash: hash("rt-new"), ExpiresAt: time.Now().Add(time.Hour),
	}); !errors.Is(err, store.ErrRefreshExpired) {
		t.Fatalf("expired token: got %v, want ErrRefreshExpired", err)
	}
}

// A-5 theft response: presenting an already-rotated token a second time is
// reuse — it must be rejected AND revoke every live token in the family, so a
// thief who replayed the stolen token cannot keep using the chain.
func TestThreat_A5_RefreshReuseRevokesFamily(t *testing.T) {
	s, ctx := newStore(t)

	if err := s.IssueRefreshToken(ctx, userA, store.NewRefreshToken{
		ID: "rt-1", Hash: hash("rt-1"), ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	// Legitimate rotation rt-1 -> rt-2.
	if _, err := s.RotateRefreshToken(ctx, hash("rt-1"), store.NewRefreshToken{
		ID: "rt-2", Hash: hash("rt-2"), ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	// Replaying the now-rotated rt-1 is reuse.
	if _, err := s.RotateRefreshToken(ctx, hash("rt-1"), store.NewRefreshToken{
		ID: "rt-evil", Hash: hash("rt-evil"), ExpiresAt: time.Now().Add(time.Hour),
	}); !errors.Is(err, store.ErrRefreshReuse) {
		t.Fatalf("replay of rotated token: got %v, want ErrRefreshReuse", err)
	}

	// The family is now poisoned: the otherwise-valid rt-2 must no longer rotate.
	if _, err := s.RotateRefreshToken(ctx, hash("rt-2"), store.NewRefreshToken{
		ID: "rt-4", Hash: hash("rt-4"), ExpiresAt: time.Now().Add(time.Hour),
	}); !errors.Is(err, store.ErrRefreshReuse) {
		t.Fatalf("live token after family revoke: got %v, want ErrRefreshReuse", err)
	}
}
