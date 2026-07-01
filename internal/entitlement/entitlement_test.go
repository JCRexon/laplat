package entitlement

import (
	"context"
	"errors"
	"testing"

	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/pkg/contracts"
)

// fakeRepo is an in-memory Repo for unit-testing the gate logic without a DB.
type fakeRepo struct {
	prices     map[string]int      // classID -> price_cents (absent = class not found)
	owned      map[string]bool     // "subject|type|id" -> active entitlement
	sessions   map[string]*string  // sessionID -> classID ptr (absent = session not found)
	granted    []store.Entitlement // recorded grants
	audits     []store.AuditInput  // audit entries the store would append
	revokedHit bool
}

func key(subject, typ, id string) string { return subject + "|" + typ + "|" + id }

func (f *fakeRepo) ClassPriceCents(_ context.Context, classID string) (int, bool, error) {
	p, ok := f.prices[classID]
	return p, ok, nil
}
func (f *fakeRepo) HasActiveEntitlement(_ context.Context, s, t, id string) (bool, error) {
	return f.owned[key(s, t, id)], nil
}
func (f *fakeRepo) ClassIDForSession(_ context.Context, sessionID string) (string, bool, error) {
	c, ok := f.sessions[sessionID]
	if !ok {
		return "", false, nil
	}
	if c == nil {
		return "", true, nil
	}
	return *c, true, nil
}
func (f *fakeRepo) GrantEntitlementAudited(_ context.Context, in store.GrantEntitlementInput, audit store.AuditInput) (store.Entitlement, error) {
	e := store.Entitlement{
		ID: in.ID, SubjectID: in.SubjectID, ResourceType: in.ResourceType,
		ResourceID: in.ResourceID, Source: in.Source, PriceCents: in.PriceCents,
	}
	f.granted = append(f.granted, e)
	f.audits = append(f.audits, audit)
	f.owned[key(in.SubjectID, in.ResourceType, in.ResourceID)] = true
	return e, nil
}
func (f *fakeRepo) RevokeEntitlementAudited(_ context.Context, s, t, id string, audit store.AuditInput) (bool, error) {
	f.revokedHit = true
	if f.owned[key(s, t, id)] {
		delete(f.owned, key(s, t, id))
		f.audits = append(f.audits, audit)
		return true, nil
	}
	return false, nil
}
func (f *fakeRepo) ListEntitlements(_ context.Context, _ string) ([]store.Entitlement, error) {
	return f.granted, nil
}

func newSvc(t *testing.T, f *fakeRepo) *Service {
	t.Helper()
	svc, err := NewService(f)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestEnsureClassAccess(t *testing.T) {
	ctx := context.Background()

	t.Run("free class passes without entitlement", func(t *testing.T) {
		f := &fakeRepo{prices: map[string]int{"free": 0}, owned: map[string]bool{}}
		if err := newSvc(t, f).EnsureClassAccess(ctx, "u1", "free"); err != nil {
			t.Fatalf("free class should pass, got %v", err)
		}
	})

	t.Run("paid class without entitlement is payment-required", func(t *testing.T) {
		f := &fakeRepo{prices: map[string]int{"paid": 1000}, owned: map[string]bool{}}
		if err := newSvc(t, f).EnsureClassAccess(ctx, "u1", "paid"); !errors.Is(err, ErrPaymentRequired) {
			t.Fatalf("want ErrPaymentRequired, got %v", err)
		}
	})

	t.Run("paid class with entitlement passes", func(t *testing.T) {
		f := &fakeRepo{
			prices: map[string]int{"paid": 1000},
			owned:  map[string]bool{key("u1", ResourceClass, "paid"): true},
		}
		if err := newSvc(t, f).EnsureClassAccess(ctx, "u1", "paid"); err != nil {
			t.Fatalf("entitled user should pass, got %v", err)
		}
	})

	t.Run("unknown class is not found", func(t *testing.T) {
		f := &fakeRepo{prices: map[string]int{}, owned: map[string]bool{}}
		if err := newSvc(t, f).EnsureClassAccess(ctx, "u1", "nope"); !errors.Is(err, ErrClassNotFound) {
			t.Fatalf("want ErrClassNotFound, got %v", err)
		}
	})
}

func TestEnsureRecordingAccess(t *testing.T) {
	ctx := context.Background()
	paid := "paid"

	t.Run("direct (classless) session is on the free floor", func(t *testing.T) {
		f := &fakeRepo{sessions: map[string]*string{"s-direct": nil}, owned: map[string]bool{}}
		if err := newSvc(t, f).EnsureRecordingAccess(ctx, "u1", "s-direct"); err != nil {
			t.Fatalf("direct session should pass, got %v", err)
		}
	})

	t.Run("paid-class session without entitlement is payment-required", func(t *testing.T) {
		f := &fakeRepo{
			sessions: map[string]*string{"s1": &paid},
			prices:   map[string]int{"paid": 1000},
			owned:    map[string]bool{},
		}
		if err := newSvc(t, f).EnsureRecordingAccess(ctx, "u1", "s1"); !errors.Is(err, ErrPaymentRequired) {
			t.Fatalf("want ErrPaymentRequired, got %v", err)
		}
	})

	t.Run("paid-class session with entitlement passes", func(t *testing.T) {
		f := &fakeRepo{
			sessions: map[string]*string{"s1": &paid},
			prices:   map[string]int{"paid": 1000},
			owned:    map[string]bool{key("u1", ResourceClass, "paid"): true},
		}
		if err := newSvc(t, f).EnsureRecordingAccess(ctx, "u1", "s1"); err != nil {
			t.Fatalf("entitled user should pass, got %v", err)
		}
	})

	t.Run("unknown session is not found", func(t *testing.T) {
		f := &fakeRepo{sessions: map[string]*string{}, owned: map[string]bool{}}
		if err := newSvc(t, f).EnsureRecordingAccess(ctx, "u1", "ghost"); !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("want ErrSessionNotFound, got %v", err)
		}
	})
}

func TestGrantValidation(t *testing.T) {
	ctx := context.Background()
	f := &fakeRepo{owned: map[string]bool{}}
	svc := newSvc(t, f)

	bad := []struct {
		name                        string
		subject, rtype, rid, source string
		price                       int
	}{
		{"empty subject", "", ResourceClass, "c1", SourceGrant, 0},
		{"empty resource", "u1", ResourceClass, "", SourceGrant, 0},
		{"unknown resource type", "u1", "video", "c1", SourceGrant, 0},
		{"unknown source", "u1", ResourceClass, "c1", "freebie", 0},
		{"negative price", "u1", ResourceClass, "c1", SourcePurchase, -1},
	}
	for _, tc := range bad {
		if _, err := svc.Grant(ctx, "mod", contracts.AuditRoleModerator, tc.subject, tc.rtype, tc.rid, tc.source, tc.price, nil); !errors.Is(err, ErrBadInput) {
			t.Errorf("%s: want ErrBadInput, got %v", tc.name, err)
		}
	}
	if len(f.granted) != 0 {
		t.Fatalf("no invalid grant should reach the repo, got %d", len(f.granted))
	}

	// A valid grant goes through and is audited (actor = grantor; target encodes
	// grantee + resource).
	if _, err := svc.Grant(ctx, "mod", contracts.AuditRoleModerator, "u1", ResourceClass, "c1", SourcePurchase, 1500, nil); err != nil {
		t.Fatalf("valid grant failed: %v", err)
	}
	if len(f.granted) != 1 {
		t.Fatalf("want 1 grant recorded, got %d", len(f.granted))
	}
	if len(f.audits) != 1 {
		t.Fatalf("want 1 audit entry, got %d", len(f.audits))
	}
	a := f.audits[0]
	if a.ActorID != "mod" || a.Action != contracts.ActionEntitlementGranted || a.TargetID != "u1:class:c1" {
		t.Fatalf("unexpected audit entry: %+v", a)
	}
}

// Revoking an active entitlement is audited; revoking a non-existent one is not.
func TestRevokeAudits(t *testing.T) {
	ctx := context.Background()
	f := &fakeRepo{owned: map[string]bool{key("u1", ResourceClass, "c1"): true}}
	svc := newSvc(t, f)

	if ok, err := svc.Revoke(ctx, "mod", contracts.AuditRoleModerator, "u1", ResourceClass, "c1"); err != nil || !ok {
		t.Fatalf("revoke: ok=%v err=%v", ok, err)
	}
	if len(f.audits) != 1 || f.audits[0].Action != contracts.ActionEntitlementRevoked {
		t.Fatalf("revoke should audit once: %+v", f.audits)
	}
	// A no-op revoke (nothing active) writes no audit entry.
	if ok, _ := svc.Revoke(ctx, "mod", contracts.AuditRoleModerator, "u1", ResourceClass, "c1"); ok {
		t.Fatal("second revoke should report false")
	}
	if len(f.audits) != 1 {
		t.Fatalf("no-op revoke must not audit, got %d entries", len(f.audits))
	}
}
