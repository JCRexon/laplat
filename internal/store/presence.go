package store

import (
	"context"
	"time"
)

// PresenceEvent is one immutable join/leave record from the presence trail.
type PresenceEvent struct {
	Seq        int64
	ID         string
	SessionID  string
	UserID     string
	Action     string // "join" | "leave"
	Role       string
	OccurredAt time.Time
}

// AppendPresenceEvent records a join/leave on the append-only presence trail. The
// id is an opaque ULID-shaped value minted by the caller. This is the cheap
// hot-path write — a plain INSERT, no advisory lock and no signature; cryptographic
// tamper-evidence is added separately by the periodic checkpoint (ADR-010).
func (s *Store) AppendPresenceEvent(ctx context.Context, id, sessionID, userID, action, role string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO presence_events (id, session_id, user_id, action, role)
		 VALUES ($1, $2, $3, $4, $5)`,
		id, sessionID, userID, action, role)
	return err
}

// ListPresenceBySession returns a session's presence events in chain order — the
// forensic "who was present, and when" view.
func (s *Store) ListPresenceBySession(ctx context.Context, sessionID string) ([]PresenceEvent, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT seq, id, session_id, user_id, action, role, occurred_at
		FROM presence_events
		WHERE session_id = $1
		ORDER BY seq`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PresenceEvent
	for rows.Next() {
		var e PresenceEvent
		if err := rows.Scan(&e.Seq, &e.ID, &e.SessionID, &e.UserID, &e.Action, &e.Role, &e.OccurredAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
