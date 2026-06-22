//go:build integration

package dbtest

import "testing"

// These run only under `-tags=integration` against a real Postgres, because
// triggers and CHECK constraints cannot be exercised from Go unit tests.

const (
	userA = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	userB = "01BRZ3NDEKTSV4RRFFQ69G5FAV"
	userC = "01CRZ3NDEKTSV4RRFFQ69G5FAV"
)

// The adult-activation trigger must block status='active' until a verified
// adult identity exists, then allow it (adults-only policy, defence in depth).
func Test_AdultActivationGate(t *testing.T) {
	pg := New(t)

	pg.MustExec(`INSERT INTO users (id, handle, display_name) VALUES ('` + userA + `', 'an', 'An');`)
	pg.MustExec(`INSERT INTO identity_vault (user_id, verification_status, is_adult)
	             VALUES ('` + userA + `', 'none', false);`)

	if err := pg.Exec(`UPDATE users SET status='active' WHERE id='` + userA + `';`); err == nil {
		t.Fatal("expected activation to be blocked for an unverified non-adult")
	}

	pg.MustExec(`UPDATE identity_vault SET verification_status='verified', is_adult=true
	             WHERE user_id='` + userA + `';`)
	pg.MustExec(`UPDATE users SET status='active' WHERE id='` + userA + `';`)
}

// The direct-session participant cap must reject a third participant (C-4).
func TestThreat_C4_DirectSessionParticipantCap(t *testing.T) {
	pg := New(t)

	for _, id := range []string{userA, userB, userC} {
		pg.MustExec(`INSERT INTO users (id, handle, display_name) VALUES ('` + id + `', 'h` + id[:4] + `', 'n');`)
	}
	pg.MustExec(`INSERT INTO sessions (id, kind, livekit_room) VALUES ('S1', 'direct', 'room-1');`)

	pg.MustExec(`INSERT INTO session_participants (session_id, user_id, role) VALUES ('S1','` + userA + `','participant');`)
	pg.MustExec(`INSERT INTO session_participants (session_id, user_id, role) VALUES ('S1','` + userB + `','participant');`)
	if err := pg.Exec(`INSERT INTO session_participants (session_id, user_id, role) VALUES ('S1','` + userC + `','participant');`); err == nil {
		t.Fatal("expected the third participant on a direct session to be rejected")
	}
}

// The kind/class_id CHECK must reject incoherent rows.
func Test_SessionKindClassConstraint(t *testing.T) {
	pg := New(t)
	if err := pg.Exec(`INSERT INTO sessions (id, kind, class_id, livekit_room) VALUES ('S2','direct','C1','room-2');`); err == nil {
		t.Fatal("expected a direct session with a class_id to be rejected")
	}
	if err := pg.Exec(`INSERT INTO sessions (id, kind, livekit_room) VALUES ('S3','class','room-3');`); err == nil {
		t.Fatal("expected a class session without a class_id to be rejected")
	}
}
