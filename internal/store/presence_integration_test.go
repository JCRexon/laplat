//go:build integration

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jcrexon/laplat/internal/dbtest"
	"github.com/jcrexon/laplat/internal/store"
)

// Presence events append and read back in seq order, and the table is immutable:
// UPDATE and DELETE are blocked by the trigger (the row is unalterable from the
// instant it lands, covering the window before a checkpoint anchors it).
func TestPresence_AppendOnlyAndOrdered(t *testing.T) {
	pg := dbtest.New(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pg.ConnString())
	if err != nil {
		t.Fatalf("connect pool: %v", err)
	}
	t.Cleanup(pool.Close)
	st := store.New(pool)

	if _, err := st.CreateUser(ctx, store.NewUser{ID: "pu", Handle: "pu", DisplayName: "Pu"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateSession(ctx, store.NewSession{ID: "PS1", Kind: "direct", LivekitRoom: "proom-1"}); err != nil {
		t.Fatal(err)
	}

	if err := st.AppendPresenceEvent(ctx, "pe-1", "PS1", "pu", "join", "participant"); err != nil {
		t.Fatalf("append join: %v", err)
	}
	if err := st.AppendPresenceEvent(ctx, "pe-2", "PS1", "pu", "leave", "participant"); err != nil {
		t.Fatalf("append leave: %v", err)
	}

	ev, err := st.ListPresenceBySession(ctx, "PS1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(ev) != 2 || ev[0].Action != "join" || ev[1].Action != "leave" || ev[0].Seq >= ev[1].Seq {
		t.Fatalf("unexpected list: %+v", ev)
	}

	// Append-only: the trigger must block in-place rewrite and deletion.
	if _, err := pool.Exec(ctx, `UPDATE presence_events SET action = 'leave' WHERE id = 'pe-1'`); err == nil {
		t.Fatal("expected UPDATE on presence_events to be blocked")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM presence_events WHERE id = 'pe-1'`); err == nil {
		t.Fatal("expected DELETE on presence_events to be blocked")
	}

	// The CHECK constraint rejects unknown actions.
	if err := st.AppendPresenceEvent(ctx, "pe-3", "PS1", "pu", "bogus", "participant"); err == nil {
		t.Fatal("expected invalid action to be rejected by CHECK")
	}
}
