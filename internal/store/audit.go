package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jcrexon/laplat/internal/audit"
	"github.com/jcrexon/laplat/internal/store/sqlcdb"
	"github.com/jcrexon/laplat/pkg/contracts"
)

// auditLockKey serialises audit appends so the hash chain has a single total
// order. It is a transaction-scoped advisory lock: concurrent audited actions
// queue on it and release at commit. (Arbitrary fixed key.)
const auditLockKey int64 = 4915208411

// ErrNoAuditSigner is returned by an audited method when the store was built
// without an audit signer (see WithAuditSigner).
var ErrNoAuditSigner = errors.New("store: audit signer not configured")

// AuditInput is the semantic part of an audit entry a caller supplies; the
// store assembles the chain (prev_hash, entry_hash, signature) on insert.
type AuditInput struct {
	ActorID    string // authenticated subject; "" for system actions
	ActorRole  string // contracts.AuditRole*
	Action     contracts.AuditAction
	TargetType string
	TargetID   string
	Metadata   []byte // canonical JSON; defaults to "{}" when empty
}

// appendAuditTx writes one chained, signed audit entry inside an existing
// transaction, so the entry commits atomically with the action it records. The
// caller must already hold an open tx; this takes the advisory lock, reads the
// tail hash, signs, and inserts.
func (s *Store) appendAuditTx(ctx context.Context, tx pgx.Tx, in AuditInput) (int64, error) {
	if s.auditSigner == nil {
		return 0, ErrNoAuditSigner
	}
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", auditLockKey); err != nil {
		return 0, err
	}

	prev := audit.GenesisHash()
	err := tx.QueryRow(ctx, "SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1").Scan(&prev)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return 0, err
	}

	meta := in.Metadata
	if len(meta) == 0 {
		meta = []byte("{}")
	}
	e := contracts.AuditEntry{
		SchemaVersion: contracts.AuditSchemaVersion,
		OccurredAt:    s.auditClock().Unix(),
		ActorID:       in.ActorID,
		ActorRole:     in.ActorRole,
		Action:        in.Action,
		TargetType:    in.TargetType,
		TargetID:      in.TargetID,
		Metadata:      meta,
		PrevHash:      prev,
		SigningKeyID:  s.auditSigner.KeyID(),
	}
	e.EntryHash = audit.Hash(e)
	if e.Signature, err = s.auditSigner.Sign(e.EntryHash); err != nil {
		return 0, err
	}

	var seq int64
	err = tx.QueryRow(ctx, `
		INSERT INTO audit_log
			(occurred_at, actor_id, actor_role, action, target_type, target_id,
			 metadata, prev_hash, entry_hash, signing_key_id, signature)
		VALUES (to_timestamp($1), $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING seq`,
		e.OccurredAt, e.ActorID, e.ActorRole, string(e.Action), e.TargetType, e.TargetID,
		e.Metadata, e.PrevHash, e.EntryHash, e.SigningKeyID, e.Signature).Scan(&seq)
	return seq, err
}

// SuspendUserAudited suspends an account, revokes all its sessions, and records
// the action — all in one transaction, so a suspension never lands without its
// audit row (and vice versa).
func (s *Store) SuspendUserAudited(ctx context.Context, in AuditInput) error {
	return s.inAuditTx(ctx, in, func(q *sqlcdb.Queries) error {
		if err := q.SuspendUser(ctx, in.TargetID); err != nil {
			return err
		}
		if err := q.RevokeAllRefreshTokens(ctx, in.TargetID); err != nil {
			return err
		}
		_, err := q.BumpTokenVersion(ctx, in.TargetID)
		return err
	})
}

// ReinstateUserAudited activates an account and records it atomically. The
// activation still passes through the adult-activation trigger.
func (s *Store) ReinstateUserAudited(ctx context.Context, in AuditInput) error {
	return s.inAuditTx(ctx, in, func(q *sqlcdb.Queries) error {
		return q.ActivateUser(ctx, in.TargetID)
	})
}

// SetInstructorAudited grants or revokes can_instruct and records it atomically.
func (s *Store) SetInstructorAudited(ctx context.Context, in AuditInput, grant bool) error {
	return s.inAuditTx(ctx, in, func(q *sqlcdb.Queries) error {
		if grant {
			return q.GrantInstructor(ctx, in.TargetID)
		}
		return q.RevokeInstructor(ctx, in.TargetID)
	})
}

// AppendAudit records a standalone audit entry with no accompanying state
// mutation (e.g. recording.played access logging, ADR-011). It still commits
// through the chained, signed append path, so the entry is tamper-evident like
// any other.
func (s *Store) AppendAudit(ctx context.Context, in AuditInput) error {
	return s.inAuditTx(ctx, in, func(*sqlcdb.Queries) error { return nil })
}

// inAuditTx runs a mutation and its audit append in one transaction.
func (s *Store) inAuditTx(ctx context.Context, in AuditInput, mutate func(*sqlcdb.Queries) error) error {
	if s.auditSigner == nil {
		return ErrNoAuditSigner
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit; best-effort otherwise

	if err := mutate(s.q.WithTx(tx)); err != nil {
		return err
	}
	if _, err := s.appendAuditTx(ctx, tx, in); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// AuditEntries returns the audit log in seq order (oldest first), for chain
// verification and forensic review.
func (s *Store) AuditEntries(ctx context.Context) ([]contracts.AuditEntry, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT seq, occurred_at, actor_id, actor_role, action, target_type, target_id,
		       metadata, prev_hash, entry_hash, signing_key_id, signature
		FROM audit_log ORDER BY seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []contracts.AuditEntry
	for rows.Next() {
		var (
			e          contracts.AuditEntry
			occurredAt time.Time
			actorID    *string
			action     string
		)
		if err := rows.Scan(&e.Seq, &occurredAt, &actorID, &e.ActorRole, &action,
			&e.TargetType, &e.TargetID, &e.Metadata, &e.PrevHash, &e.EntryHash,
			&e.SigningKeyID, &e.Signature); err != nil {
			return nil, err
		}
		e.SchemaVersion = contracts.AuditSchemaVersion
		e.OccurredAt = occurredAt.Unix()
		if actorID != nil {
			e.ActorID = *actorID
		}
		e.Action = contracts.AuditAction(action)
		out = append(out, e)
	}
	return out, rows.Err()
}
