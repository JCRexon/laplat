// Package entitlement is the ownership-gating domain (ACCESS-MODEL "owned content
// is entitlement-gated, not tier-gated"). It answers one question — does this
// account own access to this paid resource? — and is the non-provider half of
// payments: the gate and the durable ownership record exist here; only the final
// purchase/charge step needs an external provider, which calls Grant on success.
//
// Free content (price 0) needs no entitlement and stays on the tier ladder, so
// wiring this gate in changes nothing for existing free classes/recordings.
package entitlement

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	"github.com/jcrexon/laplat/internal/store"
)

// Resource types and acquisition sources (mirror the migration CHECK sets).
const (
	ResourceClass  = "class"
	SourcePurchase = "purchase" // a completed payment
	SourceGrant    = "grant"    // a moderator comp / support grant (no charge)
)

// Errors (mapped to status codes by the HTTP layer).
var (
	// ErrPaymentRequired means the resource is paid and the caller has no active
	// entitlement — the seam where a purchase flow plugs in (HTTP 402).
	ErrPaymentRequired = errors.New("entitlement: payment required")
	ErrClassNotFound   = errors.New("entitlement: class not found")
	ErrSessionNotFound = errors.New("entitlement: session not found")
	ErrExists          = store.ErrEntitlementExists
	ErrBadInput        = errors.New("entitlement: invalid input")
)

// Repo is the persistence the service needs (*store.Store satisfies it).
type Repo interface {
	GrantEntitlement(ctx context.Context, in store.GrantEntitlementInput) (store.Entitlement, error)
	HasActiveEntitlement(ctx context.Context, subjectID, resourceType, resourceID string) (bool, error)
	RevokeEntitlement(ctx context.Context, subjectID, resourceType, resourceID string) (bool, error)
	ListEntitlements(ctx context.Context, subjectID string) ([]store.Entitlement, error)
	ClassPriceCents(ctx context.Context, classID string) (int, bool, error)
	ClassIDForSession(ctx context.Context, sessionID string) (string, bool, error)
}

// Service answers ownership questions and records grants.
type Service struct {
	repo  Repo
	newID func() string
}

// NewService wires the repo.
func NewService(repo Repo) (*Service, error) {
	if repo == nil {
		return nil, errors.New("entitlement: repo is required")
	}
	return &Service{repo: repo, newID: newID}, nil
}

// EnsureClassAccess passes if the class is free (price 0) or the subject holds an
// active entitlement for it; otherwise ErrPaymentRequired. ErrClassNotFound if
// the class does not exist.
func (s *Service) EnsureClassAccess(ctx context.Context, subjectID, classID string) error {
	price, ok, err := s.repo.ClassPriceCents(ctx, classID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrClassNotFound
	}
	if price == 0 {
		return nil // free floor
	}
	owned, err := s.repo.HasActiveEntitlement(ctx, subjectID, ResourceClass, classID)
	if err != nil {
		return err
	}
	if !owned {
		return ErrPaymentRequired
	}
	return nil
}

// EnsureRecordingAccess gates a session's recordings by the entitlement of the
// class the session belongs to. A direct (classless) session is on the free
// floor and always passes. ErrSessionNotFound if the session does not exist.
func (s *Service) EnsureRecordingAccess(ctx context.Context, subjectID, sessionID string) error {
	classID, ok, err := s.repo.ClassIDForSession(ctx, sessionID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrSessionNotFound
	}
	if classID == "" {
		return nil // direct session: free floor
	}
	return s.EnsureClassAccess(ctx, subjectID, classID)
}

// Grant records that subjectID owns resource. Source is "purchase" (a completed
// charge) or "grant" (a moderator comp). Returns ErrExists if an active
// entitlement already covers it.
func (s *Service) Grant(ctx context.Context, subjectID, resourceType, resourceID, source string, priceCents int, expiresAt *time.Time) (store.Entitlement, error) {
	if subjectID == "" || resourceID == "" {
		return store.Entitlement{}, ErrBadInput
	}
	if resourceType != ResourceClass {
		return store.Entitlement{}, ErrBadInput
	}
	if source != SourcePurchase && source != SourceGrant {
		return store.Entitlement{}, ErrBadInput
	}
	if priceCents < 0 {
		return store.Entitlement{}, ErrBadInput
	}
	return s.repo.GrantEntitlement(ctx, store.GrantEntitlementInput{
		ID:           s.newID(),
		SubjectID:    subjectID,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Source:       source,
		PriceCents:   priceCents,
		ExpiresAt:    expiresAt,
	})
}

// Revoke withdraws an active entitlement (refund/chargeback/admin). Reports
// whether one was revoked.
func (s *Service) Revoke(ctx context.Context, subjectID, resourceType, resourceID string) (bool, error) {
	return s.repo.RevokeEntitlement(ctx, subjectID, resourceType, resourceID)
}

// List returns the caller's active entitlements ("my library").
func (s *Service) List(ctx context.Context, subjectID string) ([]store.Entitlement, error) {
	return s.repo.ListEntitlements(ctx, subjectID)
}

// newID returns a 26-char Crockford-base32 opaque id (ULID-shaped, identity only).
func newID() string {
	const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var b [26]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("entitlement: crypto/rand unavailable: " + err.Error())
	}
	for i := range b {
		b[i] = crockford[int(b[i])%len(crockford)]
	}
	return string(b[:])
}
