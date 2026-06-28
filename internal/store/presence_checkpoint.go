package store

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jcrexon/laplat/pkg/contracts"
)

// PresenceCheckpoint indexes one signed Merkle root over a contiguous range of
// presence_events (ADR-010 stage 2). The cryptographic authority is the audit_log
// entry at AuditSeq; this row is a rebuildable lookup index.
type PresenceCheckpoint struct {
	ID         string
	FromSeq    int64
	ToSeq      int64
	LeafCount  int
	MerkleRoot []byte
	AuditSeq   int64
	CreatedAt  time.Time
}

// PresenceCheckpointMeta is the signed commitment carried in the checkpoint's
// audit_log entry — the Merkle root and the range it covers — that a verifier
// cross-checks against the index row.
//
// It is encoded into the entry's target_id (a TEXT column) rather than the
// metadata (jsonb): Postgres normalises jsonb on storage (key order, whitespace),
// so a multi-key JSON object would not round-trip the exact bytes the audit
// signature covers, and verification would spuriously fail. A text target_id
// round-trips byte-for-byte. Wire form: "<base64(root)>:<fromSeq>:<toSeq>:<count>".
type PresenceCheckpointMeta struct {
	MerkleRoot []byte
	FromSeq    int64
	ToSeq      int64
	Count      int
}

// EncodeTarget renders the commitment into the audit entry's target_id.
func (m PresenceCheckpointMeta) EncodeTarget() string {
	return fmt.Sprintf("%s:%d:%d:%d",
		base64.StdEncoding.EncodeToString(m.MerkleRoot), m.FromSeq, m.ToSeq, m.Count)
}

// ParsePresenceCheckpointTarget decodes a commitment from an audit entry's
// target_id (the inverse of EncodeTarget).
func ParsePresenceCheckpointTarget(s string) (PresenceCheckpointMeta, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 4 {
		return PresenceCheckpointMeta{}, fmt.Errorf("store: malformed presence checkpoint target %q", s)
	}
	root, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return PresenceCheckpointMeta{}, fmt.Errorf("store: bad checkpoint root: %w", err)
	}
	fromSeq, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return PresenceCheckpointMeta{}, fmt.Errorf("store: bad checkpoint fromSeq: %w", err)
	}
	toSeq, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return PresenceCheckpointMeta{}, fmt.Errorf("store: bad checkpoint toSeq: %w", err)
	}
	count, err := strconv.Atoi(parts[3])
	if err != nil {
		return PresenceCheckpointMeta{}, fmt.Errorf("store: bad checkpoint count: %w", err)
	}
	return PresenceCheckpointMeta{MerkleRoot: root, FromSeq: fromSeq, ToSeq: toSeq, Count: count}, nil
}

// LatestPresenceCheckpointSeq returns the highest presence seq already covered by
// a checkpoint (0 if none) — the worker's resume point.
func (s *Store) LatestPresenceCheckpointSeq(ctx context.Context) (int64, error) {
	var v int64
	err := s.pool.QueryRow(ctx, `SELECT COALESCE(MAX(to_seq), 0) FROM presence_checkpoints`).Scan(&v)
	return v, err
}

// PresenceEventsAfter returns presence events with seq greater than afterSeq, in
// order, capped at limit — the rows a new checkpoint will cover.
func (s *Store) PresenceEventsAfter(ctx context.Context, afterSeq int64, limit int) ([]PresenceEvent, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT seq, id, session_id, user_id, action, role, occurred_at
		FROM presence_events
		WHERE seq > $1
		ORDER BY seq
		LIMIT $2`, afterSeq, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPresence(rows)
}

// PresenceEventsInRange returns the presence events in [fromSeq, toSeq] in order —
// the leaves a verifier rebuilds to recompute a checkpoint's Merkle root.
func (s *Store) PresenceEventsInRange(ctx context.Context, fromSeq, toSeq int64) ([]PresenceEvent, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT seq, id, session_id, user_id, action, role, occurred_at
		FROM presence_events
		WHERE seq >= $1 AND seq <= $2
		ORDER BY seq`, fromSeq, toSeq)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPresence(rows)
}

func scanPresence(rows pgx.Rows) ([]PresenceEvent, error) {
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

// WritePresenceCheckpoint atomically signs a Merkle root into the global audit_log
// (one Vault sign, amortising the network cost over the whole range) and records
// the checkpoint index row referencing that signing entry. Both commit together,
// so a checkpoint can never exist without its signed anchor, nor vice versa.
func (s *Store) WritePresenceCheckpoint(ctx context.Context, id string, root []byte, fromSeq, toSeq int64, count int) error {
	if s.auditSigner == nil {
		return ErrNoAuditSigner
	}
	// The signed commitment (root + covered range) goes in the TEXT target_id so it
	// round-trips byte-for-byte; metadata is left empty (defaults to "{}").
	target := PresenceCheckpointMeta{MerkleRoot: root, FromSeq: fromSeq, ToSeq: toSeq, Count: count}.EncodeTarget()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	auditSeq, err := s.appendAuditTx(ctx, tx, AuditInput{
		ActorRole:  contracts.AuditRoleSystem,
		Action:     contracts.ActionPresenceCheckpoint,
		TargetType: "presence",
		TargetID:   target,
	})
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO presence_checkpoints (id, from_seq, to_seq, leaf_count, merkle_root, audit_seq)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		id, fromSeq, toSeq, count, root, auditSeq); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// PresenceCheckpointCovering returns the checkpoint whose range contains seq.
func (s *Store) PresenceCheckpointCovering(ctx context.Context, seq int64) (PresenceCheckpoint, bool, error) {
	var c PresenceCheckpoint
	err := s.pool.QueryRow(ctx, `
		SELECT id, from_seq, to_seq, leaf_count, merkle_root, audit_seq, created_at
		FROM presence_checkpoints
		WHERE from_seq <= $1 AND to_seq >= $1
		ORDER BY to_seq DESC LIMIT 1`, seq).Scan(
		&c.ID, &c.FromSeq, &c.ToSeq, &c.LeafCount, &c.MerkleRoot, &c.AuditSeq, &c.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return PresenceCheckpoint{}, false, nil
	}
	if err != nil {
		return PresenceCheckpoint{}, false, err
	}
	return c, true, nil
}

// AuditEntryBySeq fetches a single audit entry by seq (the signing entry a
// checkpoint references).
func (s *Store) AuditEntryBySeq(ctx context.Context, seq int64) (contracts.AuditEntry, error) {
	var (
		e          contracts.AuditEntry
		occurredAt time.Time
		actorID    *string
		action     string
	)
	err := s.pool.QueryRow(ctx, `
		SELECT seq, occurred_at, actor_id, actor_role, action, target_type, target_id,
		       metadata, prev_hash, entry_hash, signing_key_id, signature
		FROM audit_log WHERE seq = $1`, seq).Scan(
		&e.Seq, &occurredAt, &actorID, &e.ActorRole, &action, &e.TargetType, &e.TargetID,
		&e.Metadata, &e.PrevHash, &e.EntryHash, &e.SigningKeyID, &e.Signature)
	if err != nil {
		return contracts.AuditEntry{}, err
	}
	e.SchemaVersion = contracts.AuditSchemaVersion
	e.OccurredAt = occurredAt.Unix()
	if actorID != nil {
		e.ActorID = *actorID
	}
	e.Action = contracts.AuditAction(action)
	return e, nil
}
