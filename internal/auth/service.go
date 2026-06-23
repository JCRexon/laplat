package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/pkg/contracts"
)

// Service errors. These are intentionally coarse: refresh failures all surface
// as ErrUnauthenticated to the transport so the client cannot distinguish
// "unknown token" from "reused token" from "expired" (no oracle).
var (
	// ErrUnauthenticated means the presented credential is not usable.
	ErrUnauthenticated = errors.New("auth: unauthenticated")
	// ErrAccountNotActive means the user exists but is not in good standing
	// (pending/suspended/deleted) and so may not hold a live session.
	ErrAccountNotActive = errors.New("auth: account not active")
)

// SessionRepo is the persistence the auth service needs. *store.Store satisfies
// it; tests can substitute a fake.
type SessionRepo interface {
	GetUser(ctx context.Context, id string) (store.User, error)
	GetIdentity(ctx context.Context, userID string) (store.Identity, error)
	HasAdultAttestation(ctx context.Context, userID string) (bool, error)
	CurrentTokenVersion(ctx context.Context, userID string) (int, error)
	IssueRefreshToken(ctx context.Context, userID string, tok store.NewRefreshToken) error
	RotateRefreshToken(ctx context.Context, presentedHash []byte, next store.NewRefreshToken) (store.Rotation, error)
	RevokeRefreshFamilyByHash(ctx context.Context, presentedHash []byte) error
	RevokeAccessToken(ctx context.Context, jti string, expiresAt time.Time) error
}

// Service issues and rotates sessions: an access token (short-lived, stateless)
// paired with an opaque refresh token (long-lived, rotated on use). It never
// trusts client-supplied authorisation state — capabilities and identity
// verification are always re-derived from the database at mint time, so a
// suspension or demotion takes effect on the next refresh rather than waiting
// out a token's TTL.
type Service struct {
	minter     *Minter
	repo       SessionRepo
	refreshTTL time.Duration

	// Overridable for tests.
	Now       func() time.Time
	newID     func() string
	newSecret func() string
}

// NewService wires the minter and repository. refreshTTL must be positive.
func NewService(minter *Minter, repo SessionRepo, refreshTTL time.Duration) (*Service, error) {
	if minter == nil {
		return nil, errors.New("auth: minter required")
	}
	if repo == nil {
		return nil, errors.New("auth: repo required")
	}
	if refreshTTL <= 0 {
		return nil, errors.New("auth: refresh TTL must be positive")
	}
	return &Service{
		minter:     minter,
		repo:       repo,
		refreshTTL: refreshTTL,
		Now:        time.Now,
		newID:      newOpaqueID,
		newSecret:  newRefreshSecret,
	}, nil
}

// Session is the pair returned to a client. The refresh token's raw value is
// returned exactly once (only its hash is stored); the access token's claims
// are returned for the caller's convenience.
type Session struct {
	AccessToken      string
	AccessClaims     contracts.AccessTokenClaims
	RefreshToken     string
	RefreshExpiresAt time.Time
}

// IssueSession mints the first session for an already-authenticated user. The
// first-factor proof (eKYC / OTP / IdP) is the caller's responsibility and is
// out of scope here — this is the issuance primitive that flow invokes once it
// has established who the user is. The account must be in good standing
// (pending or active); a pending account can hold a session to complete
// onboarding/eKYC, but its token carries no capabilities and idv "none".
func (s *Service) IssueSession(ctx context.Context, userID string) (Session, error) {
	user, err := s.repo.GetUser(ctx, userID)
	if err != nil {
		return Session{}, ErrUnauthenticated
	}
	if !canHoldSession(user.Status) {
		return Session{}, ErrAccountNotActive
	}
	identity, err := s.repo.GetIdentity(ctx, userID)
	if err != nil {
		return Session{}, ErrUnauthenticated
	}

	secret := s.newSecret()
	id := s.newID()
	expiresAt := s.Now().Add(s.refreshTTL)
	if err := s.repo.IssueRefreshToken(ctx, userID, store.NewRefreshToken{
		ID:        id,
		Hash:      hashSecret(secret),
		ExpiresAt: expiresAt,
	}); err != nil {
		return Session{}, err
	}
	return s.mint(ctx, user, identity, secret, expiresAt)
}

// Refresh rotates a refresh token into a new session. Reuse of an already-
// rotated token revokes the whole family in the store (theft response) and is
// reported as ErrUnauthenticated. Capabilities and identity state are re-read
// from the DB, and a no-longer-active account is rejected.
func (s *Service) Refresh(ctx context.Context, presentedRefresh string) (Session, error) {
	newSecret := s.newSecret()
	newID := s.newID()
	expiresAt := s.Now().Add(s.refreshTTL)

	rot, err := s.repo.RotateRefreshToken(ctx, hashSecret(presentedRefresh), store.NewRefreshToken{
		ID:        newID,
		Hash:      hashSecret(newSecret),
		ExpiresAt: expiresAt,
	})
	if err != nil {
		// Unknown / expired / reused all collapse to unauthenticated.
		return Session{}, ErrUnauthenticated
	}

	user, err := s.repo.GetUser(ctx, rot.UserID)
	if err != nil {
		return Session{}, ErrUnauthenticated
	}
	if !canHoldSession(user.Status) {
		return Session{}, ErrAccountNotActive
	}
	identity, err := s.repo.GetIdentity(ctx, rot.UserID)
	if err != nil {
		return Session{}, ErrUnauthenticated
	}
	return s.mint(ctx, user, identity, newSecret, expiresAt)
}

// Logout revokes the presented refresh token's entire family and denylists the
// current access token by its jti until its natural expiry. It is best-effort
// and idempotent: an unknown refresh token is not treated as an error, so a
// client can always "log out".
func (s *Service) Logout(ctx context.Context, presentedRefresh, accessJTI string, accessExpiresAt time.Time) error {
	if err := s.repo.RevokeRefreshFamilyByHash(ctx, hashSecret(presentedRefresh)); err != nil &&
		!errors.Is(err, store.ErrRefreshNotFound) {
		return err
	}
	if accessJTI != "" {
		if err := s.repo.RevokeAccessToken(ctx, accessJTI, accessExpiresAt); err != nil {
			return err
		}
	}
	return nil
}

// canHoldSession reports whether an account in this status may hold a session.
// Pending (onboarding, pre-eKYC) and active may; suspended and deleted may not.
func canHoldSession(status string) bool {
	return status == "pending" || status == "active"
}

// mint derives claims from current DB state and signs the access token.
func (s *Service) mint(ctx context.Context, user store.User, identity store.Identity, refreshSecret string, refreshExp time.Time) (Session, error) {
	tv, err := s.repo.CurrentTokenVersion(ctx, user.ID)
	if err != nil {
		return Session{}, err
	}
	declaredAdult, err := s.repo.HasAdultAttestation(ctx, user.ID)
	if err != nil {
		return Session{}, err
	}
	access, claims, err := s.minter.MintAccess(user.ID, tv,
		identityState(identity, declaredAdult), capabilities(user))
	if err != nil {
		return Session{}, err
	}
	return Session{
		AccessToken:      access,
		AccessClaims:     claims,
		RefreshToken:     refreshSecret,
		RefreshExpiresAt: refreshExp,
	}, nil
}

// identityState maps DB state to the assurance tier in the claim, ordered
// verified > declared > pending > none. eKYC ("verified") outranks a self-
// attestation ("declared"); a declared adult keeps that tier even while an eKYC
// check is pending (so a pending check is never a downgrade from declared).
func identityState(id store.Identity, declaredAdult bool) contracts.IdentityVerificationState {
	if id.VerificationStatus == string(contracts.IdentityVerified) {
		return contracts.IdentityVerified
	}
	if declaredAdult {
		return contracts.IdentityDeclared
	}
	if id.VerificationStatus == string(contracts.IdentityPending) {
		return contracts.IdentityPending
	}
	return contracts.IdentityNone
}

// capabilities derives global capabilities from the user's backing columns
// (contracts §1). Per-room roles are never minted here (A-3 / B-2).
func capabilities(u store.User) []contracts.Capability {
	caps := make([]contracts.Capability, 0, 2)
	if u.CanInstruct {
		caps = append(caps, contracts.CapCanInstruct)
	}
	if u.IsPlatformModerator {
		caps = append(caps, contracts.CapPlatformModerator)
	}
	return caps
}

// hashSecret hashes a refresh token for storage/lookup. The raw token is high-
// entropy (128 bits), so a fast cryptographic hash is sufficient and avoids a
// per-verify KDF cost on the refresh hot path; it is never reversible to the
// token and never stored in the clear.
func hashSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// newRefreshSecret returns a 128-bit, URL-safe, unguessable refresh token.
func newRefreshSecret() string {
	var b [16]byte
	mustRand(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// newOpaqueID returns a 26-char Crockford-base32 opaque id for a refresh-token
// row (ULID-shaped, but identity only — no embedded timestamp is relied upon).
func newOpaqueID() string {
	const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var b [26]byte
	mustRand(b[:])
	for i := range b {
		b[i] = crockford[int(b[i])%len(crockford)]
	}
	return string(b[:])
}

func mustRand(b []byte) {
	if _, err := rand.Read(b); err != nil {
		panic("auth: crypto/rand unavailable: " + err.Error())
	}
}
