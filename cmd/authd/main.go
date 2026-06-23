// Command authd runs the auth service: it mints and rotates sessions and
// exposes the bearer-auth-protected endpoints in internal/auth.
//
// Configuration is entirely from the environment (see internal/config). The
// Ed25519 signing key is read from LAPLAT_TOKEN_SIGNING_KEY for MVP; in
// production it belongs in a KMS/HSM and should never be an env var (A-1).
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jcrexon/laplat/internal/auth"
	"github.com/jcrexon/laplat/internal/config"
	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/pkg/contracts"
	"github.com/jcrexon/laplat/pkg/token"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("authd exited with error", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}

	// Stop the context on SIGINT/SIGTERM so startup and serving both unwind
	// cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, cfg.DBDSN)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return err
	}

	st := store.New(pool)
	signer, err := token.NewSigner(cfg.Kid, cfg.SigningKey)
	if err != nil {
		return err
	}
	minter, err := auth.NewMinter(signer, contracts.TokenIssuer, cfg.AccessTTL)
	if err != nil {
		return err
	}
	validator := token.NewValidator(token.NewVerifier(cfg.VerifyKeys), st)
	svc, err := auth.NewService(minter, st, cfg.RefreshTTL)
	if err != nil {
		return err
	}

	handler := auth.NewHandler(svc, validator)
	fed, err := buildFederation(cfg, st, svc)
	if err != nil {
		return err
	}
	if fed != nil {
		handler.RegisterOIDC(fed)
		log.Info("oidc federated login enabled",
			"google", cfg.OIDC.Google != nil, "apple", cfg.OIDC.Apple != nil)
	}

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           rootHandler(handler, pool),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Graceful shutdown: when the context is cancelled, drain in-flight
	// requests within a bounded window.
	errCh := make(chan error, 1)
	go func() {
		log.Info("authd listening", "addr", cfg.HTTPAddr)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		log.Info("shutdown signal received, draining")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// rootHandler mounts the auth API and adds liveness/readiness probes. Probe
// paths are more specific than "/", so they take precedence in the mux.
func rootHandler(api http.Handler, pool *pgxpool.Pool) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", api)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := pool.Ping(ctx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return mux
}
