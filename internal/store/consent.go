package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jcrexon/laplat/pkg/contracts"
)

// consentLockKey serialises consent-ledger appends so the hash chain has a
// single total order (distinct from the audit-log lock). Transaction-scoped.
const consentLockKey int64 = 4915208412

// ConsentInput is the semantic part of a consent record a caller supplies; the
// store assembles the chain (prev_hash, record_hash, signature) on insert.
type ConsentInput struct {
	ID        string // ULID-shaped record id
	SessionID string
	SubjectID string
	Purpose   contracts.ConsentPurpose
	Granted   bool
}

// AppendConsent writes one chained, signed consent record. Grant and withdrawal
// are both appends (a withdrawal is Granted=false); the ledger is never updated
// in place.
func (s *Store) AppendConsent(ctx context.Context, in ConsentInput) error {
	if s.auditSigner == nil {
		return ErrNoAuditSigner
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", consentLockKey); err != nil {
		return err
	}
	prev := make([]byte, contracts.AuditHashLen) // genesis: 32 zero bytes
	err = tx.QueryRow(ctx, "SELECT record_hash FROM consent_records ORDER BY seq DESC LIMIT 1").Scan(&prev)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}

	r := contracts.ConsentRecord{
		SchemaVersion: contracts.ConsentSchemaVersion,
		ID:            in.ID,
		PrevHash:      prev,
		SessionID:     in.SessionID,
		SubjectID:     in.SubjectID,
		Purpose:       in.Purpose,
		Granted:       in.Granted,
		GrantedAt:     s.auditClock().Unix(),
		SigningKeyID:  s.auditSigner.KeyID(),
	}
	if r.Signature, err = s.auditSigner.Sign(r.SignedPayload()); err != nil {
		return err
	}
	recordHash := r.Hash()

	_, err = tx.Exec(ctx, `
		INSERT INTO consent_records
			(id, session_id, subject_id, purpose, granted, granted_at,
			 prev_hash, record_hash, signing_key_id, signature)
		VALUES ($1, $2, $3, $4, $5, to_timestamp($6), $7, $8, $9, $10)`,
		r.ID, r.SessionID, r.SubjectID, string(r.Purpose), r.Granted, r.GrantedAt,
		r.PrevHash, recordHash, r.SigningKeyID, r.Signature)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// EffectiveConsent reports the latest consent decision for one subject on one
// session+purpose (false if there is no record).
func (s *Store) EffectiveConsent(ctx context.Context, subjectID, sessionID string, purpose contracts.ConsentPurpose) (bool, error) {
	var granted bool
	err := s.pool.QueryRow(ctx, `
		SELECT granted FROM consent_records
		WHERE subject_id = $1 AND session_id = $2 AND purpose = $3
		ORDER BY seq DESC LIMIT 1`,
		subjectID, sessionID, string(purpose)).Scan(&granted)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return granted, nil
}

// RecordingAllowed reports whether recording the session is permitted: every
// currently-present participant's latest session_recording consent must be
// granted. A single non-consenting (or never-consenting) active participant
// blocks it (D-2). With no active participants it is vacuously false — there is
// nothing to record.
func (s *Store) RecordingAllowed(ctx context.Context, sessionID string) (bool, error) {
	var present, consented int
	err := s.pool.QueryRow(ctx, `
		WITH active AS (
			SELECT user_id FROM session_participants
			WHERE session_id = $1 AND left_at IS NULL
		),
		latest AS (
			SELECT DISTINCT ON (subject_id) subject_id, granted
			FROM consent_records
			WHERE session_id = $1 AND purpose = $2
			ORDER BY subject_id, seq DESC
		)
		SELECT
			(SELECT count(*) FROM active),
			(SELECT count(*) FROM active a
			 JOIN latest l ON l.subject_id = a.user_id AND l.granted)`,
		sessionID, string(contracts.ConsentPurposeSessionRecording)).Scan(&present, &consented)
	if err != nil {
		return false, err
	}
	return present > 0 && present == consented, nil
}

// ConsentRecords returns the full ledger in chain order (for verification).
func (s *Store) ConsentRecords(ctx context.Context) ([]contracts.ConsentRecord, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, session_id, subject_id, purpose, granted, granted_at,
		       prev_hash, signing_key_id, signature
		FROM consent_records ORDER BY seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []contracts.ConsentRecord
	for rows.Next() {
		var (
			r         contracts.ConsentRecord
			purpose   string
			grantedAt time.Time
		)
		if err := rows.Scan(&r.ID, &r.SessionID, &r.SubjectID, &purpose, &r.Granted,
			&grantedAt, &r.PrevHash, &r.SigningKeyID, &r.Signature); err != nil {
			return nil, err
		}
		r.SchemaVersion = contracts.ConsentSchemaVersion
		r.Purpose = contracts.ConsentPurpose(purpose)
		r.GrantedAt = grantedAt.Unix()
		out = append(out, r)
	}
	return out, rows.Err()
}
