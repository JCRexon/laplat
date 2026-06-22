// Package auth holds the auth service's domain logic: access-token issuance
// policy, refresh-token rotation, and (later) the HTTP handlers. Token
// verification primitives are shared via pkg/token; minting lives here because
// only the auth service holds the signing key.
package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jcrexon/laplat/pkg/contracts"
	"github.com/jcrexon/laplat/pkg/token"
)

// MaxAccessTTL caps access-token lifetime. Short TTL bounds the blast radius of
// a leaked token (A-5); revocation handles the rest.
const MaxAccessTTL = 15 * time.Minute

// Minter issues access tokens. Now and NewJTI are overridable for tests.
type Minter struct {
	signer *token.Signer
	issuer string
	ttl    time.Duration

	Now    func() time.Time
	NewJTI func() string
}

// NewMinter validates issuance policy. TTL must be within (0, MaxAccessTTL].
func NewMinter(signer *token.Signer, issuer string, ttl time.Duration) (*Minter, error) {
	if signer == nil {
		return nil, errors.New("auth: signer required")
	}
	if issuer == "" {
		return nil, errors.New("auth: issuer required")
	}
	if ttl <= 0 || ttl > MaxAccessTTL {
		return nil, fmt.Errorf("auth: access TTL must be in (0, %s], got %s", MaxAccessTTL, ttl)
	}
	return &Minter{signer: signer, issuer: issuer, ttl: ttl, Now: time.Now, NewJTI: randJTI}, nil
}

// MintAccess builds and signs an access token for a user. tokenVersion must be
// the user's current users.token_version so a later bump revokes this token
// (A-5). The caller passes the verified identity state and global capabilities;
// per-room roles are NEVER minted into the token (A-3 / B-2).
func (m *Minter) MintAccess(
	userID string,
	tokenVersion int,
	idv contracts.IdentityVerificationState,
	caps []contracts.Capability,
) (string, contracts.AccessTokenClaims, error) {
	now := m.Now()
	claims := contracts.AccessTokenClaims{
		Issuer:               m.issuer,
		Subject:              userID,
		IssuedAt:             now.Unix(),
		ExpiresAt:            now.Add(m.ttl).Unix(),
		TokenID:              m.NewJTI(),
		SchemaVersion:        contracts.AccessTokenSchemaVersion,
		TokenVersion:         tokenVersion,
		IdentityVerification: idv,
		Capabilities:         caps,
	}
	tok, err := m.signer.Sign(claims)
	if err != nil {
		return "", contracts.AccessTokenClaims{}, err
	}
	return tok, claims, nil
}

// randJTI returns a 128-bit random, unguessable token id.
func randJTI() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is non-recoverable; fail loudly rather than mint
		// a predictable jti.
		panic("auth: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
