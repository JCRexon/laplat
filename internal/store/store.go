// Package store is the Postgres data-access layer. Generated type-safe query
// methods live in the sqlcdb subpackage (sqlc + pgx/v5); this package wraps
// them with the small amount of orchestration that needs a transaction or that
// adapts to a service-facing interface.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jcrexon/laplat/internal/store/sqlcdb"
	"github.com/jcrexon/laplat/pkg/token"
)

// Rotation/reuse errors (A-5).
var (
	// ErrRefreshNotFound means the presented token hash matches no row.
	ErrRefreshNotFound = errors.New("store: refresh token not found")
	// ErrRefreshExpired means the token is past its natural expiry.
	ErrRefreshExpired = errors.New("store: refresh token expired")
	// ErrRefreshReuse means an already-rotated or revoked token was presented
	// again — a theft signal. The whole family has been revoked.
	ErrRefreshReuse = errors.New("store: refresh token reuse detected; family revoked")
)

// Store is the Postgres-backed data-access layer.
type Store struct {
	pool *pgxpool.Pool
	q    *sqlcdb.Queries

	auditSigner AuditSigner
	auditClock  func() time.Time
}

// AuditSigner signs an audit entry hash; the store stamps the key id into each
// row for rotation-safe verification. *audit.Signer satisfies it.
type AuditSigner interface {
	KeyID() string
	Sign(hash []byte) []byte
}

// Option configures a Store at construction.
type Option func(*Store)

// WithAuditSigner enables the audited mutation methods by supplying the signer
// for the audit chain. Without it, audited methods return ErrNoAuditSigner.
func WithAuditSigner(s AuditSigner) Option {
	return func(st *Store) { st.auditSigner = s }
}

// New wraps a pgx pool. The caller owns the pool's lifecycle.
func New(pool *pgxpool.Pool, opts ...Option) *Store {
	st := &Store{pool: pool, q: sqlcdb.New(pool), auditClock: time.Now}
	for _, opt := range opts {
		opt(st)
	}
	return st
}

// Store satisfies the token validator's revocation dependency (A-5).
var _ token.RevocationStore = (*Store)(nil)

// IsAccessTokenRevoked reports whether a jti is on the single-token denylist.
func (s *Store) IsAccessTokenRevoked(ctx context.Context, jti string) (bool, error) {
	return s.q.IsAccessTokenRevoked(ctx, jti)
}

// CurrentTokenVersion returns the user's current revoke-all generation.
func (s *Store) CurrentTokenVersion(ctx context.Context, userID string) (int, error) {
	v, err := s.q.CurrentTokenVersion(ctx, userID)
	return int(v), err
}

// RevokeAccessToken denylists a single jti until its natural expiry.
func (s *Store) RevokeAccessToken(ctx context.Context, jti string, expiresAt time.Time) error {
	return s.q.RevokeAccessToken(ctx, sqlcdb.RevokeAccessTokenParams{Jti: jti, ExpiresAt: expiresAt})
}

// RevokeAllForUser bumps the user's token_version, superseding every
// outstanding access token. Returns the new version.
func (s *Store) RevokeAllForUser(ctx context.Context, userID string) (int, error) {
	v, err := s.q.BumpTokenVersion(ctx, userID)
	return int(v), err
}

// NewRefreshToken is the freshly minted replacement supplied by the caller.
// The caller generates the opaque token and its hash; the store never sees or
// stores the raw token.
type NewRefreshToken struct {
	ID        string
	Hash      []byte
	ExpiresAt time.Time
}

// IssueRefreshToken creates the first token in a new rotation family. By
// convention the family id is the token id, so a fresh issuance starts its own
// chain.
func (s *Store) IssueRefreshToken(ctx context.Context, userID string, tok NewRefreshToken) error {
	return s.q.IssueRefreshToken(ctx, sqlcdb.IssueRefreshTokenParams{
		ID:        tok.ID,
		UserID:    userID,
		FamilyID:  tok.ID,
		TokenHash: tok.Hash,
		ExpiresAt: tok.ExpiresAt,
	})
}

// RevokeRefreshFamilyByHash revokes every live token in the rotation family the
// presented token belongs to (logout / forced sign-out). Returns
// ErrRefreshNotFound if the hash matches no token.
func (s *Store) RevokeRefreshFamilyByHash(ctx context.Context, presentedHash []byte) error {
	family, err := s.q.GetFamilyByHash(ctx, presentedHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrRefreshNotFound
	} else if err != nil {
		return err
	}
	return s.q.RevokeRefreshFamily(ctx, family)
}

// Rotation reports the family and user a successful rotation belonged to.
type Rotation struct {
	UserID   string
	FamilyID string
}

// RotateRefreshToken performs single-use rotation with reuse detection (A-5).
//
// The presented token is looked up by hash under a row lock, so two concurrent
// presentations of the same token serialise: the first rotates, the second
// then observes the now-revoked row and trips reuse detection. On reuse — a
// token that was already rotated away or revoked being presented again — the
// entire rotation family is revoked (theft response) and ErrRefreshReuse is
// returned. On success the old token is marked replaced and the supplied
// replacement is inserted into the same family, atomically.
func (s *Store) RotateRefreshToken(ctx context.Context, presentedHash []byte, next NewRefreshToken) (Rotation, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Rotation{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit; best-effort on error paths
	q := s.q.WithTx(tx)

	cur, err := q.GetRefreshTokenByHashForUpdate(ctx, presentedHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return Rotation{}, ErrRefreshNotFound
	} else if err != nil {
		return Rotation{}, err
	}

	// Reuse: an already-rotated (replaced) or revoked token is being presented
	// again. Treat as theft and revoke the whole family, then commit that
	// revocation.
	if cur.RevokedAt != nil || cur.ReplacedByID != nil {
		if err := q.RevokeRefreshFamily(ctx, cur.FamilyID); err != nil {
			return Rotation{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return Rotation{}, err
		}
		return Rotation{}, ErrRefreshReuse
	}

	if !cur.ExpiresAt.After(time.Now()) {
		return Rotation{}, ErrRefreshExpired
	}

	if err := q.IssueRefreshToken(ctx, sqlcdb.IssueRefreshTokenParams{
		ID:        next.ID,
		UserID:    cur.UserID,
		FamilyID:  cur.FamilyID,
		TokenHash: next.Hash,
		ExpiresAt: next.ExpiresAt,
	}); err != nil {
		return Rotation{}, err
	}
	if err := q.MarkRefreshTokenReplaced(ctx, sqlcdb.MarkRefreshTokenReplacedParams{
		ID:           cur.ID,
		ReplacedByID: &next.ID,
	}); err != nil {
		return Rotation{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Rotation{}, err
	}
	return Rotation{UserID: cur.UserID, FamilyID: cur.FamilyID}, nil
}
