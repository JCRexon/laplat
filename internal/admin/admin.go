// Package admin holds operator-only provisioning logic that runs with trusted
// database access (the adminctl CLI), never from user-facing handlers.
package admin

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	"github.com/jcrexon/laplat/internal/store"
)

// defaultRetention is the Decree-147 floor (>= 24 months) used when a caller
// does not specify an identity retention window.
const defaultRetention = 24 * 30 * 24 * time.Hour

// BootstrapParams describes the first platform moderator to establish.
type BootstrapParams struct {
	UserID      string // optional; a fresh opaque id is generated when empty
	Handle      string
	DisplayName string
	ProviderRef string    // opaque audit note for the identity row
	RetainUntil time.Time // identity retention; defaulted when zero
}

// Bootstrap creates (or reuses) a user and makes it an active, verified-adult
// platform moderator. This is the break-glass operator path: it writes verified
// identity state directly, bypassing eKYC, so it must only ever run with
// trusted DB + signing-key access. It is idempotent for a given user id.
func Bootstrap(ctx context.Context, st *store.Store, p BootstrapParams) (string, error) {
	if p.Handle == "" || p.DisplayName == "" {
		return "", errors.New("admin: handle and display name are required")
	}
	id := p.UserID
	if id == "" {
		id = newOpaqueID()
	}

	exists, err := st.UserExists(ctx, id)
	if err != nil {
		return "", err
	}
	if !exists {
		if _, err := st.CreateUser(ctx, store.NewUser{
			ID: id, Handle: p.Handle, DisplayName: p.DisplayName,
		}); err != nil {
			return "", err
		}
	}

	if err := st.CreateIdentityRecord(ctx, id); err != nil {
		return "", err
	}
	retain := p.RetainUntil
	if retain.IsZero() {
		retain = time.Now().Add(defaultRetention)
	}
	ref := p.ProviderRef
	if ref == "" {
		ref = "operator-bootstrap"
	}
	if err := st.VerifyAdultIdentity(ctx, id, ref, retain); err != nil {
		return "", err
	}
	if err := st.PromoteToModerator(ctx, id); err != nil {
		return "", err
	}
	// Activation passes the verified-adult trigger because the steps above
	// established a verified identity.
	if err := st.ActivateUser(ctx, id); err != nil {
		return "", err
	}
	return id, nil
}

// newOpaqueID returns a 26-char Crockford-base32 opaque user id.
func newOpaqueID() string {
	const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var b [26]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("admin: crypto/rand unavailable: " + err.Error())
	}
	for i := range b {
		b[i] = crockford[int(b[i])%len(crockford)]
	}
	return string(b[:])
}
