// Package session is the live-session domain: creating class/direct sessions,
// admitting participants, and issuing per-room LiveKit grants. It is the first
// feature to consume the assurance tiers and the can_instruct capability:
//
//   - Joining any live session requires phone_verified (the Decree 147
//     interaction floor) — a browsing/declared user cannot enter a live room.
//   - Hosting a class additionally requires the can_instruct capability.
//   - The per-room media grant (publish/subscribe) is derived from the
//     participant's role at join time and minted as a LiveKit token; it never
//     rides in the platform access token (contracts §1).
package session

import (
	"context"
	"errors"
	"time"

	"github.com/jcrexon/laplat/internal/livekit"
	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/pkg/contracts"
)

// Roles within a session.
const (
	RoleHost        = "host"        // creator/controller: publishes, may start/end
	RoleParticipant = "participant" // joiner: publishes in direct, subscribes in class
)

// Errors (mapped to status codes by the HTTP layer).
var (
	ErrForbidden     = errors.New("session: forbidden for this assurance tier or role")
	ErrNotFound      = errors.New("session: not found")
	ErrSessionEnded  = errors.New("session: already ended")
	ErrInvalidKind   = errors.New("session: kind must be class or direct")
	ErrClassRequired = errors.New("session: class id required for a class session")
)

// Granter mints LiveKit room tokens (livekit.Granter satisfies it).
type Granter interface {
	Token(identity, name string, grant livekit.VideoGrant) (string, error)
}

// Repo is the persistence the service needs (*store.Store satisfies it).
type Repo interface {
	CreateSession(ctx context.Context, s store.NewSession) (store.Session, error)
	GetSession(ctx context.Context, id string) (store.Session, error)
	StartSession(ctx context.Context, id string) error
	EndSession(ctx context.Context, id string) error
	AddParticipant(ctx context.Context, sessionID, userID, role string) error
	RemoveParticipant(ctx context.Context, sessionID, userID string) error
	ListActiveParticipants(ctx context.Context, sessionID string) ([]store.SessionParticipant, error)
}

// Service orchestrates sessions and grants.
type Service struct {
	repo    Repo
	granter Granter
	wsURL   string

	NewID func() string
	Now   func() time.Time
}

// NewService wires the repo, the LiveKit granter, and the media server URL
// handed back to clients.
func NewService(repo Repo, granter Granter, wsURL string) (*Service, error) {
	if repo == nil || granter == nil {
		return nil, errors.New("session: repo and granter are required")
	}
	if wsURL == "" {
		return nil, errors.New("session: livekit ws url is required")
	}
	return &Service{repo: repo, granter: granter, wsURL: wsURL, NewID: newID, Now: time.Now}, nil
}

// CreateSession creates a class or direct session and records the caller as its
// host. A class requires the can_instruct capability; both kinds require the
// caller to meet phone verification.
func (s *Service) CreateSession(ctx context.Context, claims *contracts.AccessTokenClaims, kind string, classID *string) (store.Session, error) {
	if kind != "class" && kind != "direct" {
		return store.Session{}, ErrInvalidKind
	}
	if !claims.MeetsPhoneVerification() {
		return store.Session{}, ErrForbidden
	}
	if kind == "class" {
		if !claims.HasCapability(contracts.CapCanInstruct) {
			return store.Session{}, ErrForbidden
		}
		if classID == nil || *classID == "" {
			return store.Session{}, ErrClassRequired
		}
	} else {
		classID = nil // a direct session never carries a class id
	}

	id := s.NewID()
	sess, err := s.repo.CreateSession(ctx, store.NewSession{
		ID:          id,
		Kind:        kind,
		ClassID:     classID,
		LivekitRoom: "ses_" + id,
	})
	if err != nil {
		return store.Session{}, err
	}
	if err := s.repo.AddParticipant(ctx, id, claims.Subject, RoleHost); err != nil {
		return store.Session{}, err
	}
	return sess, nil
}

// JoinResult is what a joiner needs to connect to the media server.
type JoinResult struct {
	SessionID string
	Room      string
	Role      string
	Token     string // LiveKit access token
	WSURL     string
}

// Join admits the caller (phone_verified required) and mints their room grant.
// An existing participant (e.g. the host) keeps their role; a new joiner is
// admitted as a participant, subject to the DB's direct-session cap of two.
func (s *Service) Join(ctx context.Context, claims *contracts.AccessTokenClaims, sessionID string) (JoinResult, error) {
	if !claims.MeetsPhoneVerification() {
		return JoinResult{}, ErrForbidden
	}
	sess, err := s.repo.GetSession(ctx, sessionID)
	if err != nil {
		return JoinResult{}, ErrNotFound
	}
	if sess.Status == "ended" {
		return JoinResult{}, ErrSessionEnded
	}

	role, err := s.roleFor(ctx, sess, claims.Subject)
	if err != nil {
		return JoinResult{}, err
	}

	grant := livekit.VideoGrant{
		Room:           sess.LivekitRoom,
		RoomJoin:       true,
		CanSubscribe:   true,
		CanPublishData: true,
		// Hosts always publish; in a 1:1 direct call both peers publish; class
		// participants are subscribe-only until promoted.
		CanPublish: role == RoleHost || sess.Kind == "direct",
	}
	tok, err := s.granter.Token(claims.Subject, "", grant)
	if err != nil {
		return JoinResult{}, err
	}
	return JoinResult{
		SessionID: sess.ID,
		Room:      sess.LivekitRoom,
		Role:      role,
		Token:     tok,
		WSURL:     s.wsURL,
	}, nil
}

// roleFor returns the caller's existing role, or admits them as a participant.
func (s *Service) roleFor(ctx context.Context, sess store.Session, userID string) (string, error) {
	parts, err := s.repo.ListActiveParticipants(ctx, sess.ID)
	if err != nil {
		return "", err
	}
	for _, p := range parts {
		if p.UserID == userID {
			return p.Role, nil // already in the room (host or participant)
		}
	}
	if err := s.repo.AddParticipant(ctx, sess.ID, userID, RoleParticipant); err != nil {
		return "", err // includes the direct-session cap violation
	}
	return RoleParticipant, nil
}

// Start marks a session live; host only.
func (s *Service) Start(ctx context.Context, claims *contracts.AccessTokenClaims, sessionID string) error {
	if err := s.requireHost(ctx, claims.Subject, sessionID); err != nil {
		return err
	}
	return s.repo.StartSession(ctx, sessionID)
}

// End marks a session ended; host only.
func (s *Service) End(ctx context.Context, claims *contracts.AccessTokenClaims, sessionID string) error {
	if err := s.requireHost(ctx, claims.Subject, sessionID); err != nil {
		return err
	}
	return s.repo.EndSession(ctx, sessionID)
}

// Leave removes the caller from the session's active participants.
func (s *Service) Leave(ctx context.Context, claims *contracts.AccessTokenClaims, sessionID string) error {
	return s.repo.RemoveParticipant(ctx, sessionID, claims.Subject)
}

func (s *Service) requireHost(ctx context.Context, userID, sessionID string) error {
	parts, err := s.repo.ListActiveParticipants(ctx, sessionID)
	if err != nil {
		return err
	}
	for _, p := range parts {
		if p.UserID == userID {
			if p.Role != RoleHost {
				return ErrForbidden
			}
			return nil
		}
	}
	return ErrForbidden
}
