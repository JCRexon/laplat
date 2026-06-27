//go:build integration

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jcrexon/laplat/internal/dbtest"
	"github.com/jcrexon/laplat/internal/store"
)

// newRecordingStore boots Postgres, a store, and a session with a host to record.
func newRecordingStore(t *testing.T) (*store.Store, context.Context) {
	t.Helper()
	pg := dbtest.New(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pg.ConnString())
	if err != nil {
		t.Fatalf("connect pool: %v", err)
	}
	t.Cleanup(pool.Close)
	st := store.New(pool)
	if _, err := st.CreateUser(ctx, store.NewUser{ID: userA, Handle: "an", DisplayName: "An"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateSession(ctx, store.NewSession{ID: "S1", Kind: "direct", LivekitRoom: "room-1"}); err != nil {
		t.Fatal(err)
	}
	return st, ctx
}

// A recording's lifecycle (create → egress accepted → completed) round-trips,
// and ActiveRecording reflects in-flight vs terminal state.
func TestRecording_Lifecycle(t *testing.T) {
	st, ctx := newRecordingStore(t)

	if err := st.CreateRecording(ctx, "rec-1", "S1", "starting"); err != nil {
		t.Fatalf("CreateRecording: %v", err)
	}
	if _, ok, _ := st.ActiveRecording(ctx, "S1"); !ok {
		t.Fatal("a starting recording should be in flight")
	}

	if err := st.SetRecordingEgress(ctx, "rec-1", "EG_1", "active"); err != nil {
		t.Fatalf("SetRecordingEgress: %v", err)
	}
	rec, ok, err := st.ActiveRecording(ctx, "S1")
	if err != nil || !ok {
		t.Fatalf("ActiveRecording: ok=%v err=%v", ok, err)
	}
	if rec.EgressID != "EG_1" || rec.Status != "active" {
		t.Fatalf("rec = %+v", rec)
	}

	uri := "s3://bucket/room-1.mp4"
	if err := st.UpdateRecordingStatus(ctx, "rec-1", "completed", true, &uri, nil); err != nil {
		t.Fatalf("UpdateRecordingStatus: %v", err)
	}
	if _, ok, _ := st.ActiveRecording(ctx, "S1"); ok {
		t.Fatal("a completed recording is not in flight")
	}
	recs, err := st.RecordingsBySession(ctx, "S1")
	if err != nil || len(recs) != 1 {
		t.Fatalf("RecordingsBySession: %d recs, err=%v", len(recs), err)
	}
	if recs[0].OutputURI != uri || recs[0].EndedAt == nil {
		t.Fatalf("terminal recording = %+v, want output + ended_at set", recs[0])
	}
}

// A terminal recording is sticky: a later (replayed or out-of-order) update to a
// non-terminal status must not reopen it. This is the race-safe guard against
// webhook replay regressing recording state.
func TestRecording_TerminalIsSticky(t *testing.T) {
	st, ctx := newRecordingStore(t)

	if err := st.CreateRecording(ctx, "rec-1", "S1", "active"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetRecordingEgress(ctx, "rec-1", "EG_1", "active"); err != nil {
		t.Fatal(err)
	}
	uri := "s3://bucket/room-1.mp4"
	if err := st.UpdateRecordingStatus(ctx, "rec-1", "completed", true, &uri, nil); err != nil {
		t.Fatalf("complete: %v", err)
	}

	// Replay an earlier "active" update. It must be a no-op (no error), leaving the
	// recording terminal with its output intact.
	if err := st.UpdateRecordingStatus(ctx, "rec-1", "active", false, nil, nil); err != nil {
		t.Fatalf("replay update should be a no-op, not an error: %v", err)
	}

	recs, err := st.RecordingsBySession(ctx, "S1")
	if err != nil || len(recs) != 1 {
		t.Fatalf("RecordingsBySession: %d recs, err=%v", len(recs), err)
	}
	if recs[0].Status != "completed" {
		t.Fatalf("status = %q, want completed (terminal must be sticky)", recs[0].Status)
	}
	if recs[0].OutputURI != uri || recs[0].EndedAt == nil {
		t.Fatalf("terminal fields lost after replay: %+v", recs[0])
	}
	if _, ok, _ := st.ActiveRecording(ctx, "S1"); ok {
		t.Fatal("replay must not put the recording back in flight")
	}
}

// The partial unique index allows only one in-flight recording per session, but
// a fresh one once the prior reaches a terminal status.
func TestRecording_OneInFlightPerSession(t *testing.T) {
	st, ctx := newRecordingStore(t)

	if err := st.CreateRecording(ctx, "rec-1", "S1", "active"); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateRecording(ctx, "rec-2", "S1", "starting"); err == nil {
		t.Fatal("a second in-flight recording should be rejected")
	}

	// Terminate the first; a new one is then allowed.
	if err := st.UpdateRecordingStatus(ctx, "rec-1", "completed", true, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateRecording(ctx, "rec-3", "S1", "starting"); err != nil {
		t.Fatalf("a new recording after completion should be allowed: %v", err)
	}
}
