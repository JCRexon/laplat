// Package moderation is the platform-moderator surface. It is the first
// consumer of the CapPlatformModerator capability: a moderator can suspend an
// account (revoking its sessions immediately) and reinstate it. Account-admin
// actions, distinct from the operator break-glass path (adminctl).
package moderation

import (
	"context"
	"errors"

	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/pkg/contracts"
)

// Errors (mapped to status codes by the HTTP layer).
var (
	ErrForbidden       = errors.New("moderation: requires platform_moderator")
	ErrCannotReinstate = errors.New("moderation: cannot reinstate (no verified-adult identity)")
)

// Repo is the persistence the service needs (*store.Store satisfies it). Every
// mutating method records its action to the audit log in the same transaction
// as the mutation, so a moderator action never lands without its trail.
type Repo interface {
	SuspendUserAudited(ctx context.Context, in store.AuditInput) error
	ReinstateUserAudited(ctx context.Context, in store.AuditInput) error
	SetInstructorAudited(ctx context.Context, in store.AuditInput, grant bool) error
	ListUsers(ctx context.Context, limit int) ([]store.User, error)
}

// Service performs moderator account actions.
type Service struct {
	repo Repo
}

// NewService wires the repo.
func NewService(repo Repo) (*Service, error) {
	if repo == nil {
		return nil, errors.New("moderation: repo is required")
	}
	return &Service{repo: repo}, nil
}

// Suspend disables an account and revokes all its sessions immediately. Caller
// must be a platform moderator.
func (s *Service) Suspend(ctx context.Context, claims *contracts.AccessTokenClaims, targetID string) error {
	if !claims.HasCapability(contracts.CapPlatformModerator) {
		return ErrForbidden
	}
	return s.repo.SuspendUserAudited(ctx, store.AuditInput{
		ActorID:    claims.Subject,
		ActorRole:  contracts.AuditRoleModerator,
		Action:     contracts.ActionUserSuspended,
		TargetType: "user",
		TargetID:   targetID,
	})
}

// Reinstate returns a suspended account to active. The DB still requires a
// verified-adult (or attested) identity to activate, so an account suspended
// because it lost that basis cannot be reinstated (ErrCannotReinstate).
func (s *Service) Reinstate(ctx context.Context, claims *contracts.AccessTokenClaims, targetID string) error {
	if !claims.HasCapability(contracts.CapPlatformModerator) {
		return ErrForbidden
	}
	if err := s.repo.ReinstateUserAudited(ctx, store.AuditInput{
		ActorID:    claims.Subject,
		ActorRole:  contracts.AuditRoleModerator,
		Action:     contracts.ActionUserReinstated,
		TargetType: "user",
		TargetID:   targetID,
	}); err != nil {
		return ErrCannotReinstate
	}
	return nil
}

// ListUsers returns active and suspended users for the moderation dashboard.
// Caller must be a platform moderator.
func (s *Service) ListUsers(ctx context.Context, claims *contracts.AccessTokenClaims) ([]store.User, error) {
	if !claims.HasCapability(contracts.CapPlatformModerator) {
		return nil, ErrForbidden
	}
	return s.repo.ListUsers(ctx, 0)
}

// SetInstructor grants or revokes a user's can_instruct capability. Caller must
// be a platform moderator. This is the override path (the self-serve apply,
// gated on eKYC, lives in auth); revocation lets a moderator de-list a bad
// instructor. The change takes effect on the target's next token refresh.
func (s *Service) SetInstructor(ctx context.Context, claims *contracts.AccessTokenClaims, targetID string, grant bool) error {
	if !claims.HasCapability(contracts.CapPlatformModerator) {
		return ErrForbidden
	}
	action := contracts.ActionInstructorRevoked
	if grant {
		action = contracts.ActionInstructorGranted
	}
	return s.repo.SetInstructorAudited(ctx, store.AuditInput{
		ActorID:    claims.Subject,
		ActorRole:  contracts.AuditRoleModerator,
		Action:     action,
		TargetType: "user",
		TargetID:   targetID,
	}, grant)
}
