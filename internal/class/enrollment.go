package class

import (
	"context"
	"errors"

	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/pkg/contracts"
)

// Enrollment errors.
var (
	ErrClassNotFound   = errors.New("class: not found for enrollment")
	ErrAlreadyEnrolled = errors.New("class: already enrolled")
)

// Enroll adds the caller to the class roster. Requires at least the declared
// tier (adult self-attestation), which is the minimum for general features. A
// paid class additionally requires an active entitlement (you bought the course);
// free classes enroll without one.
func (s *Service) Enroll(ctx context.Context, claims *contracts.AccessTokenClaims, classID string) error {
	if !claims.MeetsAdultDeclaration() {
		return ErrForbidden
	}
	// Confirm the class exists and is published before enrolling.
	c, err := s.repo.GetClass(ctx, classID)
	if err != nil {
		return ErrClassNotFound
	}
	if c.Status != "published" {
		return ErrClassNotFound // treat non-published as not found to the caller
	}
	// Ownership gate: free classes pass; paid classes need an entitlement.
	if s.entitlements != nil {
		if err := s.entitlements.EnsureClassAccess(ctx, claims.Subject, classID); err != nil {
			return err
		}
	}
	// Capacity gate (soft cap): a new member is refused once the roster is full.
	// Skipped for an already-enrolled user so re-enrolling stays idempotent, and
	// for capacity 0 (unlimited). The count-then-insert is not atomic, so a burst
	// may overshoot slightly — acceptable for a roster cap.
	if capacity, ok, err := s.repo.ClassCapacity(ctx, classID); err != nil {
		return err
	} else if ok && capacity > 0 {
		already, err := s.repo.IsEnrolled(ctx, classID, claims.Subject)
		if err != nil {
			return err
		}
		if !already {
			n, err := s.repo.CountClassMembers(ctx, classID)
			if err != nil {
				return err
			}
			if n >= capacity {
				return ErrClassFull
			}
		}
	}
	return s.repo.EnrollClass(ctx, classID, claims.Subject)
}

// Unenroll removes the caller from the class roster. Always allowed for the
// enrolled user; a no-op if not currently enrolled.
func (s *Service) Unenroll(ctx context.Context, claims *contracts.AccessTokenClaims, classID string) error {
	return s.repo.UnenrollClass(ctx, classID, claims.Subject)
}

// ListEnrolled returns the full class details for the caller's enrolled classes.
func (s *Service) ListEnrolled(ctx context.Context, claims *contracts.AccessTokenClaims) ([]store.Class, error) {
	return s.repo.EnrolledClassesWithDetails(ctx, claims.Subject)
}

// EnrolledIDs returns the set of class IDs the caller is enrolled in.
// Lighter than ListEnrolled when only the IDs are needed for a membership check.
func (s *Service) EnrolledIDs(ctx context.Context, claims *contracts.AccessTokenClaims) ([]string, error) {
	return s.repo.EnrolledClassIDs(ctx, claims.Subject)
}
