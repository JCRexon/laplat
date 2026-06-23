//go:build integration

package identity_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jcrexon/laplat/internal/dbtest"
	"github.com/jcrexon/laplat/internal/identity"
	"github.com/jcrexon/laplat/internal/store"
)

const user = "01ARZ3NDEKTSV4RRFFQ69G5FAV"

func newStore(t *testing.T) (*store.Store, context.Context) {
	t.Helper()
	pg := dbtest.New(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pg.ConnString())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	st := store.New(pool)
	if _, err := st.CreateUser(ctx, store.NewUser{ID: user, Handle: "u", DisplayName: "U"}); err != nil {
		t.Fatal(err)
	}
	return st, ctx
}

// Begin marks the vault pending; Apply(approved adult) verifies and activates.
func Test_Verification_PendingToVerifiedToActive(t *testing.T) {
	st, ctx := newStore(t)
	svc, err := identity.NewService(st, map[string]identity.Verifier{"default": identity.ManualVerifier{}})
	if err != nil {
		t.Fatal(err)
	}

	res, err := svc.Begin(ctx, user, "default")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if res.Provider != "manual" {
		t.Fatalf("provider = %q, want manual", res.Provider)
	}
	if id, _ := st.GetIdentity(ctx, user); id.VerificationStatus != "pending" {
		t.Fatalf("status after begin = %q, want pending", id.VerificationStatus)
	}
	if u, _ := st.GetUser(ctx, user); u.Status != "pending" {
		t.Fatalf("user status = %q, want pending (not yet active)", u.Status)
	}

	if err := svc.Apply(ctx, identity.Result{UserID: user, ProviderRef: res.Ref, Approved: true, IsAdult: true}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	id, _ := st.GetIdentity(ctx, user)
	if id.VerificationStatus != "verified" || !id.IsAdult {
		t.Fatalf("after apply: status=%q adult=%v", id.VerificationStatus, id.IsAdult)
	}
	if u, _ := st.GetUser(ctx, user); u.Status != "active" {
		t.Fatalf("user status after verify = %q, want active", u.Status)
	}
}

// Adults-only: an approved-but-underage result must be refused and must not
// verify or activate the account.
func Test_Verification_RefusesUnderage(t *testing.T) {
	st, ctx := newStore(t)
	svc, _ := identity.NewService(st, map[string]identity.Verifier{"default": identity.ManualVerifier{}})
	if _, err := svc.Begin(ctx, user, "default"); err != nil {
		t.Fatal(err)
	}

	err := svc.Apply(ctx, identity.Result{UserID: user, ProviderRef: "x", Approved: true, IsAdult: false})
	if !errors.Is(err, identity.ErrUnderage) {
		t.Fatalf("underage: got %v, want ErrUnderage", err)
	}
	if id, _ := st.GetIdentity(ctx, user); id.IsAdult || id.VerificationStatus == "verified" {
		t.Fatalf("underage subject must not be verified: %+v", id)
	}
	if u, _ := st.GetUser(ctx, user); u.Status == "active" {
		t.Fatal("underage subject must not be active")
	}
}

// Region routing selects the region-specific provider, falling back to default.
func Test_Verification_RegionRouting(t *testing.T) {
	st, ctx := newStore(t)
	svc, _ := identity.NewService(st, map[string]identity.Verifier{
		"default": namedVerifier{"global"},
		"VN":      namedVerifier{"vn-vendor"},
	})

	if res, _ := svc.Begin(ctx, user, "VN"); res.Provider != "vn-vendor" {
		t.Fatalf("VN routed to %q, want vn-vendor", res.Provider)
	}
	if res, _ := svc.Begin(ctx, user, "US"); res.Provider != "global" {
		t.Fatalf("US (unmatched) routed to %q, want global default", res.Provider)
	}
}

type namedVerifier struct{ name string }

func (n namedVerifier) Name() string { return n.name }
func (n namedVerifier) Begin(_ context.Context, userID string) (identity.StartResult, error) {
	return identity.StartResult{Provider: n.name, Ref: n.name + ":" + userID}, nil
}
