package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrEntitlementExists is returned by GrantEntitlement when the subject already
// holds an active entitlement for the resource (the partial-unique index fires).
var ErrEntitlementExists = errors.New("store: active entitlement already exists")

// Entitlement is a durable record that an account owns access to a paid resource.
// See migrations/00020 and ACCESS-MODEL.md. Operational state, not a ledger.
type Entitlement struct {
	ID           string
	SubjectID    string
	ResourceType string
	ResourceID   string
	Source       string // "purchase" | "grant"
	PriceCents   int
	GrantedAt    time.Time
	ExpiresAt    *time.Time // nil = perpetual
	RevokedAt    *time.Time // nil = active
}

// GrantEntitlementInput is the caller-supplied part of a new entitlement.
type GrantEntitlementInput struct {
	ID           string
	SubjectID    string
	ResourceType string
	ResourceID   string
	Source       string
	PriceCents   int
	ExpiresAt    *time.Time
}

// grantEntitlementTx inserts a new active entitlement within an existing tx.
func grantEntitlementTx(ctx context.Context, tx pgx.Tx, in GrantEntitlementInput) (Entitlement, error) {
	var e Entitlement
	err := tx.QueryRow(ctx, `
		INSERT INTO entitlements
			(id, subject_id, resource_type, resource_id, source, price_cents, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, subject_id, resource_type, resource_id, source, price_cents,
		          granted_at, expires_at, revoked_at`,
		in.ID, in.SubjectID, in.ResourceType, in.ResourceID, in.Source, in.PriceCents, in.ExpiresAt).Scan(
		&e.ID, &e.SubjectID, &e.ResourceType, &e.ResourceID, &e.Source, &e.PriceCents,
		&e.GrantedAt, &e.ExpiresAt, &e.RevokedAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return Entitlement{}, ErrEntitlementExists
	}
	if err != nil {
		return Entitlement{}, err
	}
	return e, nil
}

// GrantEntitlementAudited inserts a new active entitlement and records the grant
// in the audit chain, atomically — a money-path action never lands without its
// trail (and vice versa). Returns ErrEntitlementExists if the subject already
// holds a live one for the same resource.
func (s *Store) GrantEntitlementAudited(ctx context.Context, in GrantEntitlementInput, auditIn AuditInput) (Entitlement, error) {
	if s.auditSigner == nil {
		return Entitlement{}, ErrNoAuditSigner
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Entitlement{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit; best-effort otherwise

	e, err := grantEntitlementTx(ctx, tx, in)
	if err != nil {
		return Entitlement{}, err
	}
	if _, err := s.appendAuditTx(ctx, tx, auditIn); err != nil {
		return Entitlement{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Entitlement{}, err
	}
	return e, nil
}

// HasActiveEntitlement reports whether the subject currently owns the resource:
// a non-revoked row that has not expired.
func (s *Store) HasActiveEntitlement(ctx context.Context, subjectID, resourceType, resourceID string) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM entitlements
			WHERE subject_id = $1 AND resource_type = $2 AND resource_id = $3
			  AND revoked_at IS NULL
			  AND (expires_at IS NULL OR expires_at > now())
		)`, subjectID, resourceType, resourceID).Scan(&ok)
	return ok, err
}

// RevokeEntitlementAudited marks the subject's active entitlement for the
// resource as revoked (refund/chargeback/admin) and records it in the audit
// chain, atomically. Reports whether a row was revoked (false if none was
// active); when nothing is revoked, no audit entry is written.
func (s *Store) RevokeEntitlementAudited(ctx context.Context, subjectID, resourceType, resourceID string, auditIn AuditInput) (bool, error) {
	if s.auditSigner == nil {
		return false, ErrNoAuditSigner
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit; best-effort otherwise

	tag, err := tx.Exec(ctx, `
		UPDATE entitlements SET revoked_at = now()
		WHERE subject_id = $1 AND resource_type = $2 AND resource_id = $3
		  AND revoked_at IS NULL`, subjectID, resourceType, resourceID)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 0 {
		return false, nil // nothing active to revoke; no trail to write
	}
	if _, err := s.appendAuditTx(ctx, tx, auditIn); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

// ListEntitlements returns the subject's active entitlements ("my library"),
// newest first.
func (s *Store) ListEntitlements(ctx context.Context, subjectID string) ([]Entitlement, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, subject_id, resource_type, resource_id, source, price_cents,
		       granted_at, expires_at, revoked_at
		FROM entitlements
		WHERE subject_id = $1 AND revoked_at IS NULL
		ORDER BY granted_at DESC`, subjectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Entitlement
	for rows.Next() {
		var e Entitlement
		if err := rows.Scan(&e.ID, &e.SubjectID, &e.ResourceType, &e.ResourceID, &e.Source,
			&e.PriceCents, &e.GrantedAt, &e.ExpiresAt, &e.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ClassPriceCents returns a class's price in cents and whether the class exists.
// A separate one-column read so the sqlc-generated Class struct stays untouched.
func (s *Store) ClassPriceCents(ctx context.Context, classID string) (int, bool, error) {
	var cents int
	err := s.pool.QueryRow(ctx, `SELECT price_cents FROM classes WHERE id = $1`, classID).Scan(&cents)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return cents, true, nil
}

// ClassIDForSession returns the class a session belongs to, or "" for a direct
// (classless) session. The bool reports whether the session exists.
func (s *Store) ClassIDForSession(ctx context.Context, sessionID string) (string, bool, error) {
	var classID *string
	err := s.pool.QueryRow(ctx, `SELECT class_id FROM sessions WHERE id = $1`, sessionID).Scan(&classID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if classID == nil {
		return "", true, nil
	}
	return *classID, true, nil
}
