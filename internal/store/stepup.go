package store

import (
	"context"
	"time"
)

// CreateStepUpGrant records a step-up (re-authentication) grant. The raw token
// is never stored — only its hash, supplied by the caller.
func (s *Store) CreateStepUpGrant(ctx context.Context, id, userID string, tokenHash []byte, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO stepup_grants (id, user_id, token_hash, expires_at) VALUES ($1, $2, $3, $4)`,
		id, userID, tokenHash, expiresAt)
	return err
}

// StepUpGrantValid reports whether the user holds an unexpired grant matching
// the presented token hash.
func (s *Store) StepUpGrantValid(ctx context.Context, userID string, tokenHash []byte) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM stepup_grants
			WHERE user_id = $1 AND token_hash = $2 AND expires_at > now()
		)`, userID, tokenHash).Scan(&ok)
	return ok, err
}
