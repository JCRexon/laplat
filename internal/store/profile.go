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
