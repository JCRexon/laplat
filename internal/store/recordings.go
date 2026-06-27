package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Recording is the operational state of one egress for a session. Status is a
// free string here; the recording package owns the allowed values and
// transitions (the DB CHECK constraint enforces the set).
type Recording struct {
	ID        string
	SessionID string
	EgressID  string // empty until LiveKit accepts the egress
	Status    string
	OutputURI string // empty until known (typically via webhook)
	Error     string
	StartedAt time.Time
	EndedAt   *time.Time // nil until a terminal status
}

// CreateRecording inserts a new recording in the given (non-terminal) status.
// The partial unique index rejects a second in-flight recording for the same
// session, surfacing as a normal insert error.
func (s *Store) CreateRecording(ctx context.Context, id, sessionID, status string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO recordings (id, session_id, status)
		VALUES ($1, $2, $3)`, id, sessionID, status)
	return err
}

// SetRecordingEgress records the LiveKit egress id and status once egress has
// accepted the request (the starting → active handoff).
func (s *Store) SetRecordingEgress(ctx context.Context, id, egressID, status string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE recordings SET egress_id = $2, status = $3 WHERE id = $1`,
		id, egressID, status)
	return err
}

// UpdateRecordingStatus moves a recording to a new status. When the status is
// terminal, ended_at is stamped; outputURI and errMsg are written when non-nil.
//
// Terminal states are sticky: the WHERE clause refuses to update a recording that
// is already completed/failed/aborted. This makes the transition monotonic, which
// is the authoritative, race-safe defence against a replayed or out-of-order
// egress webhook regressing a finished recording back to a live state (a single
// SQL predicate, so two concurrent webhooks cannot both pass a read-then-write
// check). A no-op update (already terminal) is not an error.
func (s *Store) UpdateRecordingStatus(ctx context.Context, id, status string, terminal bool, outputURI, errMsg *string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE recordings
		SET status = $2,
		    output_uri = COALESCE($3, output_uri),
		    error = COALESCE($4, error),
		    ended_at = CASE WHEN $5 THEN now() ELSE ended_at END
		WHERE id = $1
		  AND status NOT IN ('completed','failed','aborted')`,
		id, status, outputURI, errMsg, terminal)
	return err
}

// ActiveRecording returns the session's in-flight recording (starting / active
// / stopping), if any. ok is false when there is none.
func (s *Store) ActiveRecording(ctx context.Context, sessionID string) (Recording, bool, error) {
	r, err := s.scanRecording(s.pool.QueryRow(ctx, recordingCols+`
		FROM recordings
		WHERE session_id = $1 AND status IN ('starting','active','stopping')
		ORDER BY started_at DESC LIMIT 1`, sessionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Recording{}, false, nil
	}
	if err != nil {
		return Recording{}, false, err
	}
	return r, true, nil
}

// RecordingByEgress returns the recording with the given LiveKit egress id.
// ok is false when no recording carries that egress id (e.g. stale webhook).
func (s *Store) RecordingByEgress(ctx context.Context, egressID string) (Recording, bool, error) {
	r, err := s.scanRecording(s.pool.QueryRow(ctx, recordingCols+`
		FROM recordings WHERE egress_id = $1 LIMIT 1`, egressID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Recording{}, false, nil
	}
	if err != nil {
		return Recording{}, false, err
	}
	return r, true, nil
}

// CompletedRecordingsBySession returns completed recordings for a session, newest first.
// Used by the playback endpoint (free-tier floor; entitlement checks for paid
// recordings come once the payment system is built).
func (s *Store) CompletedRecordingsBySession(ctx context.Context, sessionID string) ([]Recording, error) {
	rows, err := s.pool.Query(ctx, recordingCols+`
		FROM recordings WHERE session_id = $1 AND status = 'completed'
		ORDER BY started_at DESC`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Recording
	for rows.Next() {
		r, err := s.scanRecording(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RecordingsBySession returns a session's recordings, newest first.
func (s *Store) RecordingsBySession(ctx context.Context, sessionID string) ([]Recording, error) {
	rows, err := s.pool.Query(ctx, recordingCols+`
		FROM recordings WHERE session_id = $1 ORDER BY started_at DESC`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Recording
	for rows.Next() {
		r, err := s.scanRecording(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

const recordingCols = `SELECT id, session_id, COALESCE(egress_id, ''), status,
	COALESCE(output_uri, ''), COALESCE(error, ''), started_at, ended_at `

// row is satisfied by both pgx.Row and pgx.Rows.
type recordingRow interface {
	Scan(dest ...any) error
}

func (s *Store) scanRecording(row recordingRow) (Recording, error) {
	var r Recording
	err := row.Scan(&r.ID, &r.SessionID, &r.EgressID, &r.Status,
		&r.OutputURI, &r.Error, &r.StartedAt, &r.EndedAt)
	return r, err
}
