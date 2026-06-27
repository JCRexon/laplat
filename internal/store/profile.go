package store

import (
	"context"
	"time"
)

// IdentityFactors holds the login methods linked to an account.
type IdentityFactors struct {
	Email     *string  // nil if no email factor linked
	Phone     *string  // nil if no phone factor linked
	Federated []string // provider names; empty slice if none
}

// SessionEntry is one participation record from the user's history.
type SessionEntry struct {
	SessionID      string
	Kind           string
	Status         string
	Role           string
	JoinedAt       time.Time
	LeftAt         *time.Time
	ClassID        *string
	ClassTitle     *string
	ScheduledStart *time.Time
}

// ConsentEntry is one record from the tamper-evident consent ledger.
type ConsentEntry struct {
	ID        string
	SessionID string
	Purpose   string
	Granted   bool
	GrantedAt time.Time
}

// LoginEvent is one authentication-activity record.
type LoginEvent struct {
	ID        string
	Method    string
	CreatedAt time.Time
}

// ToSEntry is one terms-of-service acceptance.
type ToSEntry struct {
	Version       string
	AdultAttested bool
	AcceptedAt    time.Time
}

// ClassProgress is a learner's attendance against one enrolled class.
type ClassProgress struct {
	ClassID       string
	Title         string
	TotalSessions int
	Attended      int
}

// GetIdentityFactors returns all login methods linked to a user.
func (s *Store) GetIdentityFactors(ctx context.Context, userID string) (IdentityFactors, error) {
	var email, phone *string
	row := s.pool.QueryRow(ctx, `
		SELECT
			(SELECT email FROM email_identities WHERE user_id = $1 LIMIT 1),
			(SELECT phone FROM phone_identities WHERE user_id = $1 LIMIT 1)
	`, userID)
	if err := row.Scan(&email, &phone); err != nil {
		return IdentityFactors{}, err
	}

	rows, err := s.pool.Query(ctx,
		`SELECT provider FROM federated_identities WHERE user_id = $1 ORDER BY provider`,
		userID)
	if err != nil {
		return IdentityFactors{}, err
	}
	defer rows.Close()
	fed := []string{}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return IdentityFactors{}, err
		}
		fed = append(fed, p)
	}
	return IdentityFactors{Email: email, Phone: phone, Federated: fed}, rows.Err()
}

// ListSessionHistory returns a user's participation log, newest-first, capped at 50.
func (s *Store) ListSessionHistory(ctx context.Context, userID string) ([]SessionEntry, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT
			sp.session_id,
			sp.role,
			sp.joined_at,
			sp.left_at,
			s.kind,
			s.status,
			s.class_id,
			s.scheduled_start,
			c.title
		FROM session_participants sp
		JOIN sessions s ON s.id = sp.session_id
		LEFT JOIN classes c ON c.id = s.class_id
		WHERE sp.user_id = $1
		ORDER BY sp.joined_at DESC
		LIMIT 50`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SessionEntry
	for rows.Next() {
		var e SessionEntry
		if err := rows.Scan(
			&e.SessionID, &e.Role, &e.JoinedAt, &e.LeftAt,
			&e.Kind, &e.Status, &e.ClassID, &e.ScheduledStart, &e.ClassTitle,
		); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListConsentHistory returns consent ledger entries for a user, newest-first, capped at 100.
func (s *Store) ListConsentHistory(ctx context.Context, userID string) ([]ConsentEntry, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, session_id, purpose, granted, granted_at
		FROM consent_records
		WHERE subject_id = $1
		ORDER BY seq DESC
		LIMIT 100`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ConsentEntry
	for rows.Next() {
		var e ConsentEntry
		if err := rows.Scan(&e.ID, &e.SessionID, &e.Purpose, &e.Granted, &e.GrantedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// RecordLoginEvent appends an authentication-activity row. Best-effort: callers
// log a failure rather than failing the sign-in itself.
func (s *Store) RecordLoginEvent(ctx context.Context, id, userID, method string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO login_events (id, user_id, method) VALUES ($1, $2, $3)`,
		id, userID, method)
	return err
}

// ListLoginEvents returns a user's recent sign-ins, newest-first, capped at 20.
func (s *Store) ListLoginEvents(ctx context.Context, userID string) ([]LoginEvent, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, method, created_at
		FROM login_events
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT 20`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LoginEvent
	for rows.Next() {
		var e LoginEvent
		if err := rows.Scan(&e.ID, &e.Method, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListToSAcceptances returns the user's terms-of-service acceptances.
func (s *Store) ListToSAcceptances(ctx context.Context, userID string) ([]ToSEntry, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT tos_version, adult_attested, accepted_at
		FROM tos_acceptances
		WHERE user_id = $1
		ORDER BY accepted_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ToSEntry
	for rows.Next() {
		var e ToSEntry
		if err := rows.Scan(&e.Version, &e.AdultAttested, &e.AcceptedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListClassProgress returns attendance (sessions attended / total) for each of
// the user's enrolled classes, newest enrollment first.
func (s *Store) ListClassProgress(ctx context.Context, userID string) ([]ClassProgress, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT
			c.id,
			c.title,
			(SELECT count(*) FROM sessions s WHERE s.class_id = c.id) AS total,
			(SELECT count(DISTINCT sp.session_id)
			   FROM session_participants sp
			   JOIN sessions s2 ON s2.id = sp.session_id
			   WHERE s2.class_id = c.id AND sp.user_id = $1) AS attended
		FROM classes c
		JOIN class_members m ON m.class_id = c.id
		WHERE m.user_id = $1
		ORDER BY m.enrolled_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ClassProgress
	for rows.Next() {
		var p ClassProgress
		if err := rows.Scan(&p.ClassID, &p.Title, &p.TotalSessions, &p.Attended); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
