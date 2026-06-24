package auth

import (
	"context"
	"errors"

	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/pkg/contracts"
	"github.com/jcrexon/laplat/pkg/validate"
)

const maxBioLen = 500

// ErrInvalidProfile means the requested handle/display name/bio is malformed.
var ErrInvalidProfile = errors.New("auth: invalid profile")

// ErrHandleTaken means the requested handle is already in use.
var ErrHandleTaken = store.ErrHandleTaken

// UpdateProfile validates and sets the caller's editable fields. This is how a
// federated/OTP user (who starts with a placeholder handle and "New User"
// name) sets a real profile. Handle rules are [a-z0-9_], 3–32; display name and
// bio are bounded plain text. A handle collision returns ErrHandleTaken.
func (s *Service) UpdateProfile(ctx context.Context, userID, handle, displayName, bio string) error {
	if err := validate.Handle(handle); err != nil {
		return ErrInvalidProfile
	}
	if err := validate.BoundedText(displayName, 100); err != nil {
		return ErrInvalidProfile
	}
	if bio != "" {
		if err := validate.BoundedText(bio, maxBioLen); err != nil {
			return ErrInvalidProfile
		}
	}
	return s.repo.UpdateProfile(ctx, userID, handle, displayName, bio)
}

// CloseAccount is self-service erasure: it soft-deletes the account and revokes
// all outstanding tokens. After this the caller's tokens stop validating.
func (s *Service) CloseAccount(ctx context.Context, userID string) error {
	return s.repo.CloseAccount(ctx, userID)
}

// LogoutEverywhere revokes all of a user's sessions (every refresh token and all
// outstanding access tokens), without deleting the account.
func (s *Service) LogoutEverywhere(ctx context.Context, userID string) error {
	return s.repo.RevokeAllSessions(ctx, userID)
}

// ErrNotVerified means an action requires the verified (eKYC) tier.
var ErrNotVerified = errors.New("auth: requires verified identity")

// BecomeInstructor grants the caller the can_instruct capability. It requires
// the verified (eKYC) tier — instructing is a high-trust action (live contact,
// content, payments), so a real identity check is the floor. Idempotent. The
// client must refresh to pick up the capability in a new token.
func (s *Service) BecomeInstructor(ctx context.Context, claims *contracts.AccessTokenClaims) error {
	if !claims.IsVerifiedAdult() {
		return ErrNotVerified
	}
	// Self-grant: actor and target are the same subject, recorded as a distinct
	// action (self_granted) so the trail distinguishes it from a moderator grant.
	return s.repo.SetInstructorAudited(ctx, store.AuditInput{
		ActorID:    claims.Subject,
		ActorRole:  contracts.AuditRoleSelf,
		Action:     contracts.ActionInstructorSelfGrant,
		TargetType: "user",
		TargetID:   claims.Subject,
	}, true)
}
