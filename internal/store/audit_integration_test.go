//go:build integration

package store_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jcrexon/laplat/internal/audit"
	"github.com/jcrexon/laplat/internal/dbtest"
	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/pkg/contracts"
)

// newAuditStore boots Postgres, an audit-enabled store, a verifier over the same
// key, and seeds one user to act on.
func newAuditStore(t *testing.T) (*store.Store, *pgxpool.Pool, *audit.Verifier, context.Context) {
	t.Helper()
	pg := dbtest.New(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pg.ConnString())
	if err != nil {
		t.Fatalf("connect pool: %v", err)
	}
	t.Cleanup(pool.Close)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := audit.NewSigner("kid-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	v := audit.NewVerifier(map[string]ed25519.PublicKey{"kid-1": pub})
	pg.MustExec(`INSERT INTO users (id, handle, display_name) VALUES ('` + userA + `', 'an', 'An');`)
	return store.New(pool, store.WithAuditSigner(signer)), pool, v, ctx
}

// Audited actions record a chained, signed, verifiable trail; the mutation and
// its audit row commit together.
func TestAudit_RecordsAndVerifies(t *testing.T) {
	st, _, v, ctx := newAuditStore(t)
	const mod = "mod-007"

	if err := st.SetInstructorAudited(ctx, store.AuditInput{
		ActorID: mod, ActorRole: contracts.AuditRoleModerator,
		Action: contracts.ActionInstructorGranted, TargetType: "user", TargetID: userA,
	}, true); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if err := st.SuspendUserAudited(ctx, store.AuditInput{
		ActorID: mod, ActorRole: contracts.AuditRoleModerator,
		Action: contracts.ActionUserSuspended, TargetType: "user", TargetID: userA,
	}); err != nil {
		t.Fatalf("suspend: %v", err)
	}

	entries, err := st.AuditEntries(ctx)
	if err != nil {
		t.Fatalf("entries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].Action != contracts.ActionInstructorGranted || entries[1].Action != contracts.ActionUserSuspended {
		t.Fatalf("unexpected actions: %q, %q", entries[0].Action, entries[1].Action)
	}
	if entries[0].ActorID != mod || entries[1].TargetID != userA {
		t.Fatal("actor/target not recorded")
	}
	if err := v.VerifyChain(entries); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}

	// The mutation landed in the same tx as its audit row.
	u, err := st.GetUser(ctx, userA)
	if err != nil {
		t.Fatal(err)
	}
	if u.Status != "suspended" {
		t.Fatalf("status = %q, want suspended", u.Status)
	}
}

// AppendAudit records a standalone entry (no accompanying mutation) that still
// chains and verifies — the recording.played access-log case (ADR-011). Guards
// that a metadata-less audited append round-trips the signed bytes.
func TestAudit_AppendStandalone(t *testing.T) {
	st, _, v, ctx := newAuditStore(t)
	if err := st.AppendAudit(ctx, store.AuditInput{
		ActorID: userA, ActorRole: contracts.AuditRoleSelf,
		Action: contracts.ActionRecordingPlayed, TargetType: "recording", TargetID: "REC1",
	}); err != nil {
		t.Fatalf("append: %v", err)
	}
	entries, err := st.AuditEntries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Action != contracts.ActionRecordingPlayed || entries[0].TargetID != "REC1" {
		t.Fatalf("unexpected entries: %+v", entries)
	}
	if entries[0].ActorID != userA || entries[0].ActorRole != contracts.AuditRoleSelf {
		t.Fatalf("actor not recorded: %+v", entries[0])
	}
	if err := v.VerifyChain(entries); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
}

// The audit log is append-only at the database boundary: UPDATE and DELETE both
// raise, so history cannot be rewritten in place.
func TestAudit_ImmutableAtDB(t *testing.T) {
	st, pool, _, ctx := newAuditStore(t)
	if err := st.SuspendUserAudited(ctx, store.AuditInput{
		ActorID: "mod", ActorRole: contracts.AuditRoleModerator,
		Action: contracts.ActionUserSuspended, TargetType: "user", TargetID: userA,
	}); err != nil {
		t.Fatalf("suspend: %v", err)
	}

	if _, err := pool.Exec(ctx, `UPDATE audit_log SET action = 'tampered' WHERE seq = 1`); err == nil {
		t.Fatal("UPDATE on audit_log should be blocked")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM audit_log WHERE seq = 1`); err == nil {
		t.Fatal("DELETE on audit_log should be blocked")
	}
}

// Without a signer, audited methods refuse rather than silently skipping the
// trail.
func TestAudit_RequiresSigner(t *testing.T) {
	pg := dbtest.New(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pg.ConnString())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	pg.MustExec(`INSERT INTO users (id, handle, display_name) VALUES ('` + userA + `', 'an', 'An');`)

	st := store.New(pool) // no WithAuditSigner
	err = st.SuspendUserAudited(ctx, store.AuditInput{
		ActorID: "mod", ActorRole: contracts.AuditRoleModerator,
		Action: contracts.ActionUserSuspended, TargetType: "user", TargetID: userA,
	})
	if err == nil {
		t.Fatal("expected ErrNoAuditSigner, got nil")
	}
}
