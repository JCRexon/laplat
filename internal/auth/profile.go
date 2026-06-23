package auth

import (
	"context"
	"errors"

	"github.com/jcrexon/laplat/internal/store"
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
