//go:build integration

package entitlement_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jcrexon/laplat/internal/dbtest"
	"github.com/jcrexon/laplat/internal/entitlement"
	"github.com/jcrexon/laplat/internal/store"
)

// End-to-end against Postgres: a free class needs no entitlement; a paid class is
// gated until granted; recording access inherits from the session's class; and a
// revoke re-closes the gate. Exercises the real store SQL (partial-unique index,
// expiry/revoke predicates) without needing a live media session.
func TestEntitlement_GateAndGrant(t *testing.T) {
	pg := dbtest.New(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pg.ConnString())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	st := store.New(pool)
	svc, err := entitlement.NewService(st)
	if err != nil {
		t.Fatal(err)
	}

	// Fixtures: an instructor, a learner, a free class and a paid class.
	if _, err := st.CreateUser(ctx, store.NewUser{ID: "inst", Handle: "inst", DisplayName: "Inst"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser(ctx, store.NewUser{ID: "u1", Handle: "u1", DisplayName: "U1"}); err != nil {
		t.Fatal(err)
	}
	free, err := st.CreateClass(ctx, store.NewClass{ID: "cfree", InstructorID: "inst", Title: "Free"})
	if err != nil {
		t.Fatal(err)
	}
	paid, err := st.CreateClass(ctx, store.NewClass{ID: "cpaid", InstructorID: "inst", Title: "Paid"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE classes SET price_cents = 1500 WHERE id = $1`, paid.ID); err != nil {
		t.Fatal(err)
	}

	// Free class: always accessible.
	if err := svc.EnsureClassAccess(ctx, "u1", free.ID); err != nil {
		t.Fatalf("free class should pass: %v", err)
	}

	// Paid class: gated until granted.
	if err := svc.EnsureClassAccess(ctx, "u1", paid.ID); err != entitlement.ErrPaymentRequired {
		t.Fatalf("paid class pre-grant = %v, want ErrPaymentRequired", err)
	}
	if _, err := svc.Grant(ctx, "u1", entitlement.ResourceClass, paid.ID, entitlement.SourcePurchase, 1500, nil); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if err := svc.EnsureClassAccess(ctx, "u1", paid.ID); err != nil {
		t.Fatalf("paid class post-grant should pass: %v", err)
	}

	// A duplicate active grant is rejected by the partial-unique index.
	if _, err := svc.Grant(ctx, "u1", entitlement.ResourceClass, paid.ID, entitlement.SourceGrant, 0, nil); err != entitlement.ErrExists {
		t.Fatalf("duplicate grant = %v, want ErrExists", err)
	}

	// Library lists the active entitlement.
	if ents, err := svc.List(ctx, "u1"); err != nil || len(ents) != 1 {
		t.Fatalf("list: ents=%d err=%v, want 1", len(ents), err)
	}

	// Recording access inherits from the session's class.
	if _, err := st.CreateSession(ctx, store.NewSession{ID: "spaid", Kind: "class", ClassID: &paid.ID, LivekitRoom: "rp"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateSession(ctx, store.NewSession{ID: "sdirect", Kind: "direct", LivekitRoom: "rd"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.EnsureRecordingAccess(ctx, "u1", "spaid"); err != nil {
		t.Fatalf("entitled recording access should pass: %v", err)
	}
	if err := svc.EnsureRecordingAccess(ctx, "u2-nobody", "spaid"); err != entitlement.ErrPaymentRequired {
		t.Fatalf("unentitled recording access = %v, want ErrPaymentRequired", err)
	}
	if err := svc.EnsureRecordingAccess(ctx, "u2-nobody", "sdirect"); err != nil {
		t.Fatalf("direct session should be on the free floor: %v", err)
	}

	// Revoke re-closes the gate, and a re-grant is then allowed (new active row).
	if ok, err := svc.Revoke(ctx, "u1", entitlement.ResourceClass, paid.ID); err != nil || !ok {
		t.Fatalf("revoke: ok=%v err=%v", ok, err)
	}
	if err := svc.EnsureClassAccess(ctx, "u1", paid.ID); err != entitlement.ErrPaymentRequired {
		t.Fatalf("post-revoke = %v, want ErrPaymentRequired", err)
	}
	if _, err := svc.Grant(ctx, "u1", entitlement.ResourceClass, paid.ID, entitlement.SourceGrant, 0, nil); err != nil {
		t.Fatalf("re-grant after revoke should succeed: %v", err)
	}
}
