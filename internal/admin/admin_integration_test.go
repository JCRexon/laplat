//go:build integration

package admin_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jcrexon/laplat/internal/admin"
	"github.com/jcrexon/laplat/internal/auth"
	"github.com/jcrexon/laplat/internal/dbtest"
	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/pkg/contracts"
	"github.com/jcrexon/laplat/pkg/token"
)

// Bootstrap must yield an active, verified-adult platform moderator, and a
// token minted for it must validate and carry the moderator capability — the
// full break-glass admin path.
func Test_Bootstrap_ThenMintAdminToken(t *testing.T) {
	pg := dbtest.New(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pg.ConnString())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	st := store.New(pool)

	id, err := admin.Bootstrap(ctx, st, admin.BootstrapParams{Handle: "root", DisplayName: "Root Admin"})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	u, err := st.GetUser(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if u.Status != "active" || !u.IsPlatformModerator {
		t.Fatalf("bootstrapped user: status=%q moderator=%v", u.Status, u.IsPlatformModerator)
	}

	// Mint via the same path adminctl uses, then validate end-to-end.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := token.NewSigner("kid-1", priv)
	minter, _ := auth.NewMinter(signer, contracts.TokenIssuer, 15*time.Minute)
	svc, _ := auth.NewService(minter, st, 720*time.Hour)
	validator := token.NewValidator(token.NewVerifier(map[string]ed25519.PublicKey{"kid-1": pub}), st)

	sess, err := svc.IssueSession(ctx, id)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	claims, err := validator.Validate(ctx, sess.AccessToken)
	if err != nil {
		t.Fatalf("admin token should validate: %v", err)
	}
	if !claims.HasCapability(contracts.CapPlatformModerator) {
		t.Fatalf("admin token missing platform_moderator capability: %v", claims.Capabilities)
	}

	// Idempotent: re-bootstrapping the same id must not error.
	if _, err := admin.Bootstrap(ctx, st, admin.BootstrapParams{UserID: id, Handle: "root", DisplayName: "Root Admin"}); err != nil {
		t.Fatalf("re-bootstrap should be idempotent: %v", err)
	}
}
