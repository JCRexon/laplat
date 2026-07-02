//go:build integration

package class_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jcrexon/laplat/internal/class"
	"github.com/jcrexon/laplat/internal/dbtest"
	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/pkg/contracts"
)

func newSvc(t *testing.T) (*class.Service, *store.Store, context.Context) {
	t.Helper()
	pg := dbtest.New(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pg.ConnString())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	st := store.New(pool)
	svc, err := class.NewService(st)
	if err != nil {
		t.Fatal(err)
	}
	return svc, st, ctx
}

func mkUser(t *testing.T, st *store.Store, ctx context.Context, id string, idv contracts.IdentityVerificationState, instruct bool) *contracts.AccessTokenClaims {
	t.Helper()
	caps := []contracts.Capability{}
	if instruct {
		caps = append(caps, contracts.CapCanInstruct)
	}
	if _, err := st.CreateUser(ctx, store.NewUser{ID: id, Handle: id, DisplayName: id, CanInstruct: instruct}); err != nil {
		t.Fatal(err)
	}
	return &contracts.AccessTokenClaims{Subject: id, IdentityVerification: idv, Capabilities: caps}
}

// An instructor creates, lists, and publishes a class.
func TestClass_CreateListPublish(t *testing.T) {
	svc, st, ctx := newSvc(t)
	instr := mkUser(t, st, ctx, "instr", contracts.IdentityPhoneVerified, true)

	c, err := svc.Create(ctx, instr, "Intro to Go", "a course")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if c.Status != "draft" {
		t.Fatalf("status = %q, want draft", c.Status)
	}

	mine, err := svc.ListMine(ctx, instr)
	if err != nil || len(mine) != 1 || mine[0].ID != c.ID {
		t.Fatalf("list mine: %v / %v", err, mine)
	}

	if err := svc.SetStatus(ctx, instr, c.ID, "published"); err != nil {
		t.Fatalf("publish: %v", err)
	}
	got, _ := st.GetClass(ctx, c.ID)
	if got.Status != "published" {
		t.Fatalf("status after publish = %q", got.Status)
	}
}

// The public catalog lists only published classes.
func TestClass_PublishedCatalog(t *testing.T) {
	svc, st, ctx := newSvc(t)
	instr := mkUser(t, st, ctx, "cat-instr", contracts.IdentityPhoneVerified, true)
	pub, _ := svc.Create(ctx, instr, "Published", "")
	if err := svc.SetStatus(ctx, instr, pub.ID, "published"); err != nil {
		t.Fatal(err)
	}
	_, _ = svc.Create(ctx, instr, "Draft", "") // stays draft

	catalog, err := svc.ListPublished(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog) != 1 || catalog[0].ID != pub.ID {
		t.Fatalf("catalog should contain only the published class: %+v", catalog)
	}
}

// Authz: a non-instructor (or phone-unverified) user cannot create a class, and
// a user cannot change another instructor's class.
func TestClass_Authz(t *testing.T) {
	svc, st, ctx := newSvc(t)
	instr := mkUser(t, st, ctx, "owner", contracts.IdentityPhoneVerified, true)
	c, _ := svc.Create(ctx, instr, "Owned", "")

	// phone-verified but no can_instruct -> forbidden.
	noCap := mkUser(t, st, ctx, "nocap", contracts.IdentityPhoneVerified, false)
	if _, err := svc.Create(ctx, noCap, "X", ""); err != class.ErrForbidden {
		t.Fatalf("non-instructor create = %v, want ErrForbidden", err)
	}

	// can_instruct but only declared (no phone) -> forbidden.
	noPhone := mkUser(t, st, ctx, "nophone", contracts.IdentityDeclared, true)
	if _, err := svc.Create(ctx, noPhone, "X", ""); err != class.ErrForbidden {
		t.Fatalf("declared-only instructor create = %v, want ErrForbidden", err)
	}

	// A different instructor cannot publish someone else's class.
	other := mkUser(t, st, ctx, "other", contracts.IdentityPhoneVerified, true)
	if err := svc.SetStatus(ctx, other, c.ID, "published"); err != class.ErrForbidden {
		t.Fatalf("cross-owner status = %v, want ErrForbidden", err)
	}
}

// A capacity cap gates enrollment: once full, a new member is refused, but an
// already-enrolled member re-enrolling stays idempotent, raising the cap admits
// more, and capacity 0 is unlimited. Only the owner may set it.
func TestClass_Capacity(t *testing.T) {
	svc, st, ctx := newSvc(t)
	instr := mkUser(t, st, ctx, "cap-instr", contracts.IdentityPhoneVerified, true)
	c, _ := svc.Create(ctx, instr, "Small", "")
	if err := svc.SetStatus(ctx, instr, c.ID, "published"); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetCapacity(ctx, instr, c.ID, 1); err != nil {
		t.Fatalf("set capacity: %v", err)
	}

	u1 := mkUser(t, st, ctx, "cap-u1", contracts.IdentityDeclared, false)
	u2 := mkUser(t, st, ctx, "cap-u2", contracts.IdentityDeclared, false)

	if err := svc.Enroll(ctx, u1, c.ID); err != nil {
		t.Fatalf("u1 enroll: %v", err)
	}
	// Already-enrolled re-enroll is a no-op even at capacity.
	if err := svc.Enroll(ctx, u1, c.ID); err != nil {
		t.Fatalf("u1 re-enroll should be a no-op: %v", err)
	}
	// A new member is refused — full.
	if err := svc.Enroll(ctx, u2, c.ID); err != class.ErrClassFull {
		t.Fatalf("u2 enroll = %v, want ErrClassFull", err)
	}
	// Raising the cap admits u2.
	if err := svc.SetCapacity(ctx, instr, c.ID, 2); err != nil {
		t.Fatal(err)
	}
	if err := svc.Enroll(ctx, u2, c.ID); err != nil {
		t.Fatalf("u2 after raise: %v", err)
	}

	// Capacity 0 = unlimited.
	c2, _ := svc.Create(ctx, instr, "Unlimited", "")
	if err := svc.SetStatus(ctx, instr, c2.ID, "published"); err != nil {
		t.Fatal(err)
	}
	u3 := mkUser(t, st, ctx, "cap-u3", contracts.IdentityDeclared, false)
	if err := svc.Enroll(ctx, u3, c2.ID); err != nil {
		t.Fatalf("unlimited enroll: %v", err)
	}

	// Only the owner may set capacity; negative is rejected.
	other := mkUser(t, st, ctx, "cap-other", contracts.IdentityPhoneVerified, true)
	if err := svc.SetCapacity(ctx, other, c.ID, 5); err != class.ErrForbidden {
		t.Fatalf("non-owner setCapacity = %v, want ErrForbidden", err)
	}
	if err := svc.SetCapacity(ctx, instr, c.ID, -1); err != class.ErrBadCapacity {
		t.Fatalf("negative capacity = %v, want ErrBadCapacity", err)
	}
}

// Bad input is rejected.
func TestClass_BadInput(t *testing.T) {
	svc, st, ctx := newSvc(t)
	instr := mkUser(t, st, ctx, "instr2", contracts.IdentityPhoneVerified, true)
	if _, err := svc.Create(ctx, instr, "   ", ""); err != class.ErrBadTitle {
		t.Fatalf("blank title = %v, want ErrBadTitle", err)
	}
	c, _ := svc.Create(ctx, instr, "Valid", "")
	if err := svc.SetStatus(ctx, instr, c.ID, "bogus"); err != class.ErrBadStatus {
		t.Fatalf("bad status = %v, want ErrBadStatus", err)
	}
}
