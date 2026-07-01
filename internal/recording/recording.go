// Package recording is the session-recording control plane. It starts and stops
// LiveKit egress for a session, but only behind the consent ledger's gate
// (RecordingAllowed): a recording may start only when every present participant
// has consented, and a consent withdrawal stops an in-flight recording (D-2).
// The recordings table holds operational state (egress id, status, output);
// the legal record of consent lives in the append-only consent ledger.
package recording

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	"github.com/jcrexon/laplat/internal/livekit"
	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/pkg/contracts"
)

// Our recording statuses (mirror the DB CHECK set).
const (
	StatusStarting  = "starting"
	StatusActive    = "active"
	StatusStopping  = "stopping"
	StatusCompleted = "completed"
	StatusFailed    = "failed"
	StatusAborted   = "aborted"
)

// Errors (mapped to status codes by the HTTP layer).
var (
	ErrForbidden        = errors.New("recording: host only")
	ErrNotFound         = errors.New("recording: session not found")
	ErrSessionEnded     = errors.New("recording: session already ended")
	ErrConsentRequired  = errors.New("recording: not all present participants have consented")
	ErrAlreadyRecording = errors.New("recording: a recording is already in flight")
	ErrNotRecording     = errors.New("recording: no recording in flight")
	ErrCapacity         = errors.New("recording: concurrent recording capacity reached")
)

// Egress starts and stops LiveKit room recordings (*livekit.EgressClient
// satisfies it).
type Egress interface {
	StartRoomComposite(ctx context.Context, room string) (*livekit.EgressInfo, error)
	StopEgress(ctx context.Context, egressID string) (*livekit.EgressInfo, error)
}

// Repo is the persistence the service needs (*store.Store satisfies it).
type Repo interface {
	GetSession(ctx context.Context, id string) (store.Session, error)
	ListActiveParticipants(ctx context.Context, sessionID string) ([]store.SessionParticipant, error)
	RecordingAllowed(ctx context.Context, sessionID string) (bool, error)
	CreateRecording(ctx context.Context, id, sessionID, status string) error
	SetRecordingEgress(ctx context.Context, id, egressID, status string) error
	UpdateRecordingStatus(ctx context.Context, id, status string, terminal bool, outputURI, errMsg *string) error
	ActiveRecording(ctx context.Context, sessionID string) (store.Recording, bool, error)
	RecordingsBySession(ctx context.Context, sessionID string) ([]store.Recording, error)
	RecordingByEgress(ctx context.Context, egressID string) (store.Recording, bool, error)
	RecordingByID(ctx context.Context, id string) (store.Recording, bool, error)
	CompletedRecordingsBySession(ctx context.Context, sessionID string) ([]store.Recording, error)
	CountInFlightRecordings(ctx context.Context) (int, error)
	AppendAudit(ctx context.Context, in store.AuditInput) error
}

// Service orchestrates recording start/stop behind the consent gate.
type Service struct {
	repo   Repo
	egress Egress

	maxConcurrent int // 0 = unlimited
	newID         func() string
	Now           func() time.Time
}

// ServiceOption configures a Service.
type ServiceOption func(*Service)

// WithMaxConcurrent caps the number of in-flight recordings across all sessions
// (ADR-008/012 start quota). A zero or negative value leaves it unlimited.
func WithMaxConcurrent(n int) ServiceOption {
	return func(s *Service) {
		if n > 0 {
			s.maxConcurrent = n
		}
	}
}

// NewService wires the repo and egress client.
func NewService(repo Repo, egress Egress, opts ...ServiceOption) (*Service, error) {
	if repo == nil || egress == nil {
		return nil, errors.New("recording: repo and egress are required")
	}
	s := &Service{repo: repo, egress: egress, newID: newID, Now: time.Now}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// Start begins recording the session. Host only. The consent gate
// (RecordingAllowed) must pass — every present participant must have consented
// (D-2) — and no recording may already be in flight.
func (s *Service) Start(ctx context.Context, claims *contracts.AccessTokenClaims, sessionID string) (store.Recording, error) {
	sess, err := s.requireHostSession(ctx, claims.Subject, sessionID)
	if err != nil {
		return store.Recording{}, err
	}
	allowed, err := s.repo.RecordingAllowed(ctx, sessionID)
	if err != nil {
		return store.Recording{}, err
	}
	if !allowed {
		return store.Recording{}, ErrConsentRequired
	}

	// Coarse start quota: bound concurrent egress load / storage growth
	// (ADR-008/012). A soft cap — the count-then-create is not atomic, so a burst
	// of concurrent starts may overshoot slightly; that is acceptable for a
	// load guard (the per-session single-in-flight invariant is the hard one).
	if s.maxConcurrent > 0 {
		n, err := s.repo.CountInFlightRecordings(ctx)
		if err != nil {
			return store.Recording{}, err
		}
		if n >= s.maxConcurrent {
			return store.Recording{}, ErrCapacity
		}
	}

	id := s.newID()
	if err := s.repo.CreateRecording(ctx, id, sessionID, StatusStarting); err != nil {
		// The partial unique index rejects a second in-flight recording.
		if _, ok, _ := s.repo.ActiveRecording(ctx, sessionID); ok {
			return store.Recording{}, ErrAlreadyRecording
		}
		return store.Recording{}, err
	}

	info, err := s.egress.StartRoomComposite(ctx, sess.LivekitRoom)
	if err != nil {
		// Egress refused: mark the row failed so the session is recordable again.
		msg := err.Error()
		_ = s.repo.UpdateRecordingStatus(ctx, id, StatusFailed, true, nil, &msg)
		return store.Recording{}, err
	}
	status := mapStatus(info.Status)
	if err := s.repo.SetRecordingEgress(ctx, id, info.EgressID, status); err != nil {
		return store.Recording{}, err
	}
	rec, _, err := s.repo.ActiveRecording(ctx, sessionID)
	if err != nil {
		return store.Recording{}, err
	}
	return rec, nil
}

// Stop stops the session's in-flight recording. Host only.
func (s *Service) Stop(ctx context.Context, claims *contracts.AccessTokenClaims, sessionID string) error {
	if _, err := s.requireHostSession(ctx, claims.Subject, sessionID); err != nil {
		return err
	}
	rec, ok, err := s.repo.ActiveRecording(ctx, sessionID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotRecording
	}
	return s.stop(ctx, rec)
}

// ReconcileForSession re-checks the consent gate for any in-flight recording
// and stops it if recording is no longer permitted. It is the system reaction
// to a consent withdrawal (D-2) and is therefore NOT host-gated. A no-op when
// nothing is recording or consent still holds.
func (s *Service) ReconcileForSession(ctx context.Context, sessionID string) error {
	rec, ok, err := s.repo.ActiveRecording(ctx, sessionID)
	if err != nil || !ok {
		return err
	}
	allowed, err := s.repo.RecordingAllowed(ctx, sessionID)
	if err != nil {
		return err
	}
	if allowed {
		return nil
	}
	return s.stop(ctx, rec)
}

// List returns a session's recordings. Host only.
func (s *Service) List(ctx context.Context, claims *contracts.AccessTokenClaims, sessionID string) ([]store.Recording, error) {
	if _, err := s.requireHostSession(ctx, claims.Subject, sessionID); err != nil {
		return nil, err
	}
	return s.repo.RecordingsBySession(ctx, sessionID)
}

// stop asks egress to stop and records the resulting status.
func (s *Service) stop(ctx context.Context, rec store.Recording) error {
	if rec.EgressID == "" {
		// Never reached egress (still 'starting'); abort the row locally.
		return s.repo.UpdateRecordingStatus(ctx, rec.ID, StatusAborted, true, nil, nil)
	}
	info, err := s.egress.StopEgress(ctx, rec.EgressID)
	if err != nil {
		return err
	}
	status := mapStatus(info.Status)
	var outURI *string
	if o := info.Output(); o != "" {
		outURI = &o
	}
	return s.repo.UpdateRecordingStatus(ctx, rec.ID, status, isTerminal(status), outURI, nil)
}

// requireHostSession loads the session and verifies the caller is its host and
// that it has not ended.
func (s *Service) requireHostSession(ctx context.Context, userID, sessionID string) (store.Session, error) {
	sess, err := s.repo.GetSession(ctx, sessionID)
	if err != nil {
		return store.Session{}, ErrNotFound
	}
	if sess.Status == "ended" {
		return store.Session{}, ErrSessionEnded
	}
	parts, err := s.repo.ListActiveParticipants(ctx, sessionID)
	if err != nil {
		return store.Session{}, err
	}
	for _, p := range parts {
		if p.UserID == userID {
			if p.Role != "host" {
				return store.Session{}, ErrForbidden
			}
			return sess, nil
		}
	}
	return store.Session{}, ErrForbidden
}

// mapStatus translates a LiveKit egress status to our recording status.
func mapStatus(lk string) string {
	switch lk {
	case livekit.EgressStarting:
		return StatusStarting
	case livekit.EgressActive:
		return StatusActive
	case livekit.EgressEnding:
		return StatusStopping
	case livekit.EgressComplete:
		return StatusCompleted
	case livekit.EgressFailed:
		return StatusFailed
	case livekit.EgressAborted, livekit.EgressLimitReached:
		return StatusAborted
	default:
		return StatusActive // unknown but live; webhooks will correct it
	}
}

func isTerminal(status string) bool {
	switch status {
	case StatusCompleted, StatusFailed, StatusAborted:
		return true
	default:
		return false
	}
}

// HandleWebhookEvent applies a verified LiveKit egress webhook event to the
// matching recording row. Unknown egress IDs are silently ignored — duplicate or
// out-of-order webhook deliveries are safe.
func (s *Service) HandleWebhookEvent(ctx context.Context, ev *livekit.WebhookEvent) error {
	if ev.EgressInfo == nil {
		return nil // not an egress lifecycle event
	}
	rec, ok, err := s.repo.RecordingByEgress(ctx, ev.EgressInfo.EgressID)
	if err != nil {
		return err
	}
	if !ok {
		return nil // unknown egress id; stale or out-of-scope webhook
	}
	if isTerminal(rec.Status) {
		// Already finished. Ignore any further event — a replayed or out-of-order
		// webhook must never reopen a completed/failed/aborted recording. The store
		// enforces this too (sticky terminal state); this just avoids the write.
		return nil
	}
	status := mapStatus(ev.EgressInfo.Status)
	terminal := isTerminal(status)
	var outURI *string
	if o := ev.EgressInfo.Output(); o != "" {
		outURI = &o
	}
	var errMsg *string
	if ev.EgressInfo.Error != "" {
		errMsg = &ev.EgressInfo.Error
	}
	return s.repo.UpdateRecordingStatus(ctx, rec.ID, status, terminal, outURI, errMsg)
}

// ListCompleted returns completed recordings for a session. Any authenticated
// user may call this (free-recording floor per ACCESS-MODEL; the entitlement
// gate on the HTTP handler enforces ownership for paid classes).
func (s *Service) ListCompleted(ctx context.Context, sessionID string) ([]store.Recording, error) {
	return s.repo.CompletedRecordingsBySession(ctx, sessionID)
}

// Recording returns a single recording by id (used by the serving-authz check).
func (s *Service) Recording(ctx context.Context, id string) (store.Recording, bool, error) {
	return s.repo.RecordingByID(ctx, id)
}

// AuditPlayback records that subjectID was authorised to fetch rec's bytes
// (ADR-011 recording.played). The actor is the viewer; the target is the
// recording. Metadata is left empty so the entry round-trips the signed bytes.
func (s *Service) AuditPlayback(ctx context.Context, subjectID string, rec store.Recording) error {
	return s.repo.AppendAudit(ctx, store.AuditInput{
		ActorID:    subjectID,
		ActorRole:  contracts.AuditRoleSelf,
		Action:     contracts.ActionRecordingPlayed,
		TargetType: "recording",
		TargetID:   rec.ID,
	})
}

// newID returns a 26-char Crockford-base32 record id (ULID-shaped, identity
// only), matching the opaque-id style used elsewhere.
func newID() string {
	const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var b [26]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("recording: crypto/rand unavailable: " + err.Error())
	}
	for i := range b {
		b[i] = crockford[int(b[i])%len(crockford)]
	}
	return string(b[:])
}
