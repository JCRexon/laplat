// Package moderation is the platform-moderator surface. It is the first
// consumer of the CapPlatformModerator capability: a moderator can suspend an
// account (revoking its sessions immediately) and reinstate it. Account-admin
// actions, distinct from the operator break-glass path (adminctl).
package moderation

import (
	"context"
	"errors"

	"github.com/jcrexon/laplat/pkg/contracts"
)

// Errors (mapped to status codes by the HTTP layer).
var (
	ErrForbidden       = errors.New("moderation: requires platform_moderator")
	ErrCannotReinstate = errors.New("moderation: cannot reinstate (no verified-adult identity)")
)

// Repo is the persistence the service needs (*store.Store satisfies it).
type Repo interface {
	SuspendUser(ctx context.Context, id string) error
	ActivateUser(ctx context.Context, id string) error
	RevokeAllSessions(ctx context.Context, id string) error
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
	if err := s.repo.SuspendUser(ctx, targetID); err != nil {
		return err
	}
	return s.repo.RevokeAllSessions(ctx, targetID)
}

// Reinstate returns a suspended account to active. The DB still requires a
// verified-adult (or attested) identity to activate, so an account suspended
// because it lost that basis cannot be reinstated (ErrCannotReinstate).
func (s *Service) Reinstate(ctx context.Context, claims *contracts.AccessTokenClaims, targetID string) error {
	if !claims.HasCapability(contracts.CapPlatformModerator) {
		return ErrForbidden
	}
	if err := s.repo.ActivateUser(ctx, targetID); err != nil {
		return ErrCannotReinstate
	}
	return nil
}
