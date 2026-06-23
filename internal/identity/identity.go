// Package identity orchestrates adult identity verification (eKYC). The actual
// verification — document capture, liveness, face match, age — is a vendor's
// job; this package owns only the thin, vendor-agnostic glue: a pluggable
// Verifier port, region routing (Vietnamese users must use a VN-resident,
// C06-licensed provider per Decree 147; others use a global vendor), and the
// pending -> verified -> active state transition on identity_vault.
//
// OIDC (Sign in with Google/Apple) is a LOGIN factor and does not satisfy this;
// adult verification is always a separate gate.
package identity

import (
	"context"
	"errors"
	"time"
)

const defaultRetention = 24 * 30 * 24 * time.Hour // Decree 147 floor (>= 24 months)

var (
	// ErrNoProvider means no verifier is configured for the user's region.
	ErrNoProvider = errors.New("identity: no verifier for region")
	// ErrUnderage means verification succeeded but the subject is not an adult.
	// Adults-only: this must never be activated.
	ErrUnderage = errors.New("identity: subject is not an adult")
	// ErrNotApproved means the provider returned a non-approved result.
	ErrNotApproved = errors.New("identity: verification not approved")
)

// StartResult tells the client how to proceed with the chosen provider (a
// hosted redirect URL and/or an opaque session reference).
type StartResult struct {
	Provider    string
	Ref         string
	RedirectURL string
}

// Result is the outcome a provider delivers (via webhook) or an operator
// records. Only the minimal verified facts — never raw documents.
type Result struct {
	UserID      string
	ProviderRef string
	Approved    bool
	IsAdult     bool
	RetainUntil time.Time // when zero, the Decree-147 default is applied
}

// Verifier is the pluggable eKYC provider port. Implementations: a VN vendor
// (FPT/VNPT), a global vendor (Stripe Identity/Persona), or the manual
// operator provider.
type Verifier interface {
	Name() string
	// Begin starts a verification session for a user.
	Begin(ctx context.Context, userID string) (StartResult, error)
}

// Repo is the persistence the orchestrator needs (*store.Store satisfies it).
type Repo interface {
	CreateIdentityRecord(ctx context.Context, userID string) error
	SetIdentityVerificationPending(ctx context.Context, userID string) error
	VerifyAdultIdentity(ctx context.Context, userID, providerRef string, retainUntil time.Time) error
	AcceptToS(ctx context.Context, userID, version string, adultAttested bool) error
	ActivateUser(ctx context.Context, userID string) error
}

// Service routes verification to a region-appropriate provider and applies
// results to the identity vault.
type Service struct {
	repo      Repo
	providers map[string]Verifier // keyed by region; "default" is the fallback
	Now       func() time.Time
}

// NewService wires the repo and a region->Verifier map. A "default" entry is
// required as the fallback for unmatched regions.
func NewService(repo Repo, providers map[string]Verifier) (*Service, error) {
	if repo == nil {
		return nil, errors.New("identity: repo required")
	}
	if _, ok := providers["default"]; !ok {
		return nil, errors.New("identity: a \"default\" provider is required")
	}
	return &Service{repo: repo, providers: providers, Now: time.Now}, nil
}

// providerFor selects the verifier for a region, falling back to "default".
func (s *Service) providerFor(region string) Verifier {
	if v, ok := s.providers[region]; ok {
		return v
	}
	return s.providers["default"]
}

// Begin starts adult verification for a user in the given region. It ensures
// the vault row exists, marks verification pending, and returns the provider's
// start instructions.
func (s *Service) Begin(ctx context.Context, userID, region string) (StartResult, error) {
	v := s.providerFor(region)
	if v == nil {
		return StartResult{}, ErrNoProvider
	}
	if err := s.repo.CreateIdentityRecord(ctx, userID); err != nil {
		return StartResult{}, err
	}
	res, err := v.Begin(ctx, userID)
	if err != nil {
		return StartResult{}, err
	}
	if err := s.repo.SetIdentityVerificationPending(ctx, userID); err != nil {
		return StartResult{}, err
	}
	return res, nil
}

// Apply records a verification result. On an approved adult it writes the
// verified-adult state and activates the account (the DB trigger permits
// activation only once this state exists). A non-adult is refused outright
// (adults-only). A non-approved result is reported as ErrNotApproved and leaves
// the vault in its pending/none state for retry.
func (s *Service) Apply(ctx context.Context, r Result) error {
	if !r.Approved {
		return ErrNotApproved
	}
	if !r.IsAdult {
		return ErrUnderage
	}
	retain := r.RetainUntil
	if retain.IsZero() {
		retain = s.now().Add(defaultRetention)
	}
	if err := s.repo.VerifyAdultIdentity(ctx, r.UserID, r.ProviderRef, retain); err != nil {
		return err
	}
	return s.repo.ActivateUser(ctx, r.UserID)
}

// AcceptToS records a Terms-of-Service acceptance and its 18+ self-attestation.
// An adult attestation is the 'declared' assurance tier: it activates the
// account (the relaxed activation trigger permits this) so the user can use
// general features without eKYC. High-risk actions still require 'verified'
// eKYC, enforced at the point of use. A non-adult attestation is recorded but
// does not activate — the account stays browse-only.
func (s *Service) AcceptToS(ctx context.Context, userID, version string, adultAttested bool) error {
	if version == "" {
		return errors.New("identity: tos version required")
	}
	if err := s.repo.AcceptToS(ctx, userID, version, adultAttested); err != nil {
		return err
	}
	if !adultAttested {
		return nil
	}
	return s.repo.ActivateUser(ctx, userID)
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// ManualVerifier is the operator-review provider: it starts a verification that
// a human approves out of band (via adminctl). It is the stopgap before a real
// vendor is contracted, and the default for any region without one.
type ManualVerifier struct{}

func (ManualVerifier) Name() string { return "manual" }

func (ManualVerifier) Begin(_ context.Context, userID string) (StartResult, error) {
	return StartResult{Provider: "manual", Ref: "manual:" + userID}, nil
}
