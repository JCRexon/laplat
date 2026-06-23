// Command adminctl is the operator break-glass tool for the auth platform. It
// runs with the same trusted configuration as authd (DB DSN + Ed25519 signing
// key) and is the ONLY way the first platform moderator is created and the only
// way an admin bearer token is minted without a user-facing login.
//
// Usage:
//
//	adminctl bootstrap -handle <h> -name <n> [-user-id <id>]
//	adminctl mint -user-id <id>
//
// Configuration comes from the environment (see internal/config).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jcrexon/laplat/internal/admin"
	"github.com/jcrexon/laplat/internal/auth"
	"github.com/jcrexon/laplat/internal/config"
	"github.com/jcrexon/laplat/internal/identity"
	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/pkg/contracts"
	"github.com/jcrexon/laplat/pkg/token"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "adminctl:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: adminctl <bootstrap|mint> [flags]")
	}
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.DBDSN)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return err
	}
	st := store.New(pool)

	switch args[0] {
	case "bootstrap":
		return runBootstrap(ctx, st, args[1:])
	case "verify":
		return runVerify(ctx, st, args[1:])
	case "mint":
		return runMint(ctx, st, cfg, args[1:])
	default:
		return fmt.Errorf("unknown command %q (want bootstrap|verify|mint)", args[0])
	}
}

// runVerify is the manual (operator) eKYC approval path: it records a
// verified-adult result through the identity service's manual provider and
// activates the account. Use for the operator-review stopgap before a real
// eKYC vendor is wired in.
func runVerify(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	userID := fs.String("user-id", "", "user id to mark as a verified adult")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *userID == "" {
		return errors.New("verify: -user-id is required")
	}
	svc, err := identity.NewService(st, map[string]identity.Verifier{"default": identity.ManualVerifier{}})
	if err != nil {
		return err
	}
	if err := svc.Apply(ctx, identity.Result{
		UserID:      *userID,
		ProviderRef: "operator-manual",
		Approved:    true,
		IsAdult:     true,
	}); err != nil {
		return err
	}
	fmt.Printf("verified (adult) and activated: %s\n", *userID)
	return nil
}

func runBootstrap(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	userID := fs.String("user-id", "", "existing/desired user id (generated if empty)")
	handle := fs.String("handle", "", "unique handle for the moderator")
	name := fs.String("name", "", "display name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	id, err := admin.Bootstrap(ctx, st, admin.BootstrapParams{
		UserID: *userID, Handle: *handle, DisplayName: *name,
	})
	if err != nil {
		return err
	}
	fmt.Printf("bootstrapped platform moderator: %s\n", id)
	fmt.Println("mint an access token with: adminctl mint -user-id", id)
	return nil
}

func runMint(ctx context.Context, st *store.Store, cfg config.Config, args []string) error {
	fs := flag.NewFlagSet("mint", flag.ContinueOnError)
	userID := fs.String("user-id", "", "user id to mint a session for")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *userID == "" {
		return errors.New("mint: -user-id is required")
	}

	signer, err := token.NewSigner(cfg.Kid, cfg.SigningKey)
	if err != nil {
		return err
	}
	minter, err := auth.NewMinter(signer, contracts.TokenIssuer, cfg.AccessTTL)
	if err != nil {
		return err
	}
	svc, err := auth.NewService(minter, st, cfg.RefreshTTL)
	if err != nil {
		return err
	}
	sess, err := svc.IssueSession(ctx, *userID)
	if err != nil {
		return err
	}
	fmt.Println("access_token: ", sess.AccessToken)
	fmt.Println("refresh_token:", sess.RefreshToken)
	fmt.Println("access_exp:   ", time.Unix(sess.AccessClaims.ExpiresAt, 0).UTC().Format(time.RFC3339))
	fmt.Println("caps:         ", sess.AccessClaims.Capabilities)
	return nil
}
