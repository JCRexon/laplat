// Package class is the course-definition domain: an instructor creates classes
// and moves them through draft -> published -> archived. A live "class" session
// is an instance of a class (see internal/session). Creating/owning a class
// requires the can_instruct capability and the phone_verified assurance tier.
package class

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"

	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/pkg/contracts"
)

const maxTitleLen = 200

// Errors (mapped to status codes by the HTTP layer).
var (
	ErrForbidden  = errors.New("class: forbidden for this tier or capability")
	ErrNotFound   = errors.New("class: not found")
	ErrBadTitle   = errors.New("class: title is required")
	ErrBadStatus  = errors.New("class: invalid status transition")
	validStatuses = map[string]bool{"draft": true, "published": true, "archived": true}
)

// Repo is the persistence the service needs (*store.Store satisfies it).
type Repo interface {
	CreateClass(ctx context.Context, c store.NewClass) (store.Class, error)
	GetClass(ctx context.Context, id string) (store.Class, error)
	ListClassesByInstructor(ctx context.Context, instructorID string) ([]store.Class, error)
	ListPublishedClasses(ctx context.Context) ([]store.Class, error)
	UpdateClassStatus(ctx context.Context, id, status string) error

	// Enrollment.
	EnrollClass(ctx context.Context, classID, userID string) error
	UnenrollClass(ctx context.Context, classID, userID string) error
	IsEnrolled(ctx context.Context, classID, userID string) (bool, error)
	EnrolledClassesWithDetails(ctx context.Context, userID string) ([]store.Class, error)
	EnrolledClassIDs(ctx context.Context, userID string) ([]string, error)
}

// Service orchestrates class management.
type Service struct {
	repo  Repo
	NewID func() string
}

// NewService wires the repo.
func NewService(repo Repo) (*Service, error) {
	if repo == nil {
		return nil, errors.New("class: repo is required")
	}
	return &Service{repo: repo, NewID: newID}, nil
}

// Create makes a new draft class owned by the caller. Requires can_instruct and
// phone verification (the instructor floor).
func (s *Service) Create(ctx context.Context, claims *contracts.AccessTokenClaims, title, description string) (store.Class, error) {
	if !claims.MeetsPhoneVerification() || !claims.HasCapability(contracts.CapCanInstruct) {
		return store.Class{}, ErrForbidden
	}
	title = strings.TrimSpace(title)
	if title == "" || len(title) > maxTitleLen {
		return store.Class{}, ErrBadTitle
	}
	return s.repo.CreateClass(ctx, store.NewClass{
		ID: s.NewID(), InstructorID: claims.Subject, Title: title, Description: description,
	})
}

// ListMine returns the caller's classes.
func (s *Service) ListMine(ctx context.Context, claims *contracts.AccessTokenClaims) ([]store.Class, error) {
	return s.repo.ListClassesByInstructor(ctx, claims.Subject)
}

// ListPublished returns the public catalog of published classes. Browsing is
// open to any authenticated user (the lowest tier).
func (s *Service) ListPublished(ctx context.Context) ([]store.Class, error) {
	return s.repo.ListPublishedClasses(ctx)
}

// SetStatus moves a class to a new lifecycle status; owner only.
func (s *Service) SetStatus(ctx context.Context, claims *contracts.AccessTokenClaims, classID, status string) error {
	if !validStatuses[status] {
		return ErrBadStatus
	}
	if err := s.requireOwner(ctx, claims.Subject, classID); err != nil {
		return err
	}
	return s.repo.UpdateClassStatus(ctx, classID, status)
}

func (s *Service) requireOwner(ctx context.Context, userID, classID string) error {
	c, err := s.repo.GetClass(ctx, classID)
	if err != nil {
		return ErrNotFound
	}
	if c.InstructorID != userID {
		return ErrForbidden
	}
	return nil
}

// newID returns a 26-char Crockford-base32 opaque class id.
func newID() string {
	const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var b [26]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("class: crypto/rand unavailable: " + err.Error())
	}
	for i := range b {
		b[i] = crockford[int(b[i])%len(crockford)]
	}
	return string(b[:])
}
