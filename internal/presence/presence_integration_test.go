//go:build integration

package presence_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jcrexon/laplat/internal/audit"
	"github.com/jcrexon/laplat/internal/dbtest"
	"github.com/jcrexon/laplat/internal/presence"
	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/pkg/contracts"
)

// End-to-end: presence events are checkpointed into a signed Merkle root, every
// event then verifies via inclusion proof, checkpointing is idempotent and
// resumable, and verification fails under the wrong signing key.
func TestPresence_CheckpointAndVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pg := dbtest.New(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pg.ConnString())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	signer, err := audit.NewSigner("kid-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(pool, store.WithAuditSigner(signer))
	svc, err := presence.NewService(st, audit.NewVerifier(map[string]ed25519.PublicKey{"kid-1": pub}))
	if err != nil {
		t.Fatal(err)
	}

	// FKs.
	if _, err := st.CreateUser(ctx, store.NewUser{ID: "u1", Handle: "u1", DisplayName: "U1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateSession(ctx, store.NewSession{ID: "S1", Kind: "direct", LivekitRoom: "r1"}); err != nil {
		t.Fatal(err)
	}

	// Nothing to checkpoint yet.
	if wrote, err := svc.Checkpoint(ctx); err != nil || wrote {
		t.Fatalf("empty checkpoint: wrote=%v err=%v", wrote, err)
	}

	for i, a := range []string{"join", "join", "leave"} {
		id := []string{"pe-1", "pe-2", "pe-3"}[i]
		if err := st.AppendPresenceEvent(ctx, id, "S1", "u1", a, "participant"); err != nil {
			t.Fatal(err)
		}
	}
	all, _ := st.ListPresenceBySession(ctx, "S1")
	if len(all) != 3 {
		t.Fatalf("want 3 events, got %d", len(all))
	}

	// Before a checkpoint, an event is not yet anchored.
	if err := svc.Verify(ctx, all[0].Seq); err != presence.ErrNotCheckpointed {
		t.Fatalf("pre-checkpoint verify = %v, want ErrNotCheckpointed", err)
	}

	// Checkpoint, then every event verifies under the signed root.
	if wrote, err := svc.Checkpoint(ctx); err != nil || !wrote {
		t.Fatalf("checkpoint: wrote=%v err=%v", wrote, err)
	}
	for _, e := range all {
		if err := svc.Verify(ctx, e.Seq); err != nil {
			t.Fatalf("verify seq %d: %v", e.Seq, err)
		}
	}

	// Idempotent: nothing new to cover.
	if wrote, err := svc.Checkpoint(ctx); err != nil || wrote {
		t.Fatalf("second checkpoint should be a no-op: wrote=%v err=%v", wrote, err)
	}

	// Resumable: new events get their own checkpoint and verify.
	if err := st.AppendPresenceEvent(ctx, "pe-4", "S1", "u1", "join", "participant"); err != nil {
		t.Fatal(err)
	}
	if wrote, err := svc.Checkpoint(ctx); err != nil || !wrote {
		t.Fatalf("third checkpoint: wrote=%v err=%v", wrote, err)
	}
	all2, _ := st.ListPresenceBySession(ctx, "S1")
	for _, e := range all2 {
		if err := svc.Verify(ctx, e.Seq); err != nil {
			t.Fatalf("verify after resume, seq %d: %v", e.Seq, err)
		}
	}

	// One signed audit entry per checkpoint (two so far).
	entries, _ := st.AuditEntries(ctx)
	cps := 0
	for _, e := range entries {
		if e.Action == contracts.ActionPresenceCheckpoint {
			cps++
		}
	}
	if cps != 2 {
		t.Fatalf("want 2 checkpoint audit entries, got %d", cps)
	}

	// Verification fails under the wrong signing key (the signature leg is real).
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	badSvc, _ := presence.NewService(st, audit.NewVerifier(map[string]ed25519.PublicKey{"kid-1": otherPub}))
	if err := badSvc.Verify(ctx, all[0].Seq); err == nil {
		t.Fatal("verification under the wrong key must fail")
	}
}
