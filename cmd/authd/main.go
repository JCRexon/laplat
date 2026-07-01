// Command authd runs the auth service: it mints and rotates sessions and
// exposes the bearer-auth-protected endpoints in internal/auth.
//
// Configuration is entirely from the environment (see internal/config). The
// Ed25519 signing key is read from LAPLAT_TOKEN_SIGNING_KEY for MVP; in
// production it belongs in a KMS/HSM and should never be an env var (A-1).
package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jcrexon/laplat/internal/audit"
	"github.com/jcrexon/laplat/internal/auth"
	"github.com/jcrexon/laplat/internal/class"
	"github.com/jcrexon/laplat/internal/config"
	"github.com/jcrexon/laplat/internal/consent"
	"github.com/jcrexon/laplat/internal/ekyc"
	"github.com/jcrexon/laplat/internal/emailsend"
	"github.com/jcrexon/laplat/internal/entitlement"
	"github.com/jcrexon/laplat/internal/httpx"
	"github.com/jcrexon/laplat/internal/identity"
	"github.com/jcrexon/laplat/internal/livekit"
	"github.com/jcrexon/laplat/internal/moderation"
	"github.com/jcrexon/laplat/internal/otpconsole"
	"github.com/jcrexon/laplat/internal/presence"
	"github.com/jcrexon/laplat/internal/recording"
	"github.com/jcrexon/laplat/internal/session"
	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/internal/vaultsign"
	"github.com/jcrexon/laplat/pkg/contracts"
	"github.com/jcrexon/laplat/pkg/signing"
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

	if err := waitForDB(ctx, log, pool); err != nil {
		return err
	}

	// Select the signing backend once: Vault Transit (key never enters this
	// process) when configured, otherwise the in-process env-var key. Both token
	// and audit signing share it, exactly as they shared the raw key before. With
	// Vault, the public key is fetched from Vault and added to the verify set.
	keySigner, verifyKeys, err := buildSigning(ctx, cfg)
	if err != nil {
		return err
	}
	if cfg.Vault != nil {
		log.Info("token + audit signing via Vault Transit", "addr", cfg.Vault.Address, "key", cfg.Vault.KeyName)
	}
	auditSigner, err := audit.NewSignerFromKeySigner(keySigner)
	if err != nil {
		return err
	}
	st := store.New(pool, store.WithAuditSigner(auditSigner))
	signer, err := token.NewSignerFromKeySigner(keySigner)
	if err != nil {
		return err
	}
	minter, err := auth.NewMinter(signer, contracts.TokenIssuer, cfg.AccessTTL)
	if err != nil {
		return err
	}
	validator := token.NewValidator(token.NewVerifier(verifyKeys), st)
	svc, err := auth.NewService(minter, st, cfg.RefreshTTL)
	if err != nil {
		return err
	}

	handler := auth.NewHandler(svc, validator)
	handler.RegisterProfile(st)

	// Identity: self-declaration ('declared' tier) always; the VN eKYC vendor
	// ('verified' tier) for region VN when configured.
	providers := map[string]identity.Verifier{"default": identity.ManualVerifier{}}
	var ekycFlow auth.EKYCService
	if cfg.EKYC != nil {
		client, err := ekyc.NewHTTPClient(ekyc.HTTPConfig{URL: cfg.EKYC.VendorURL, Token: cfg.EKYC.VendorToken}, nil)
		if err != nil {
			return err
		}
		vn, err := ekyc.NewVN(client, cfg.EKYC.WebhookSecret)
		if err != nil {
			return err
		}
		providers["VN"] = vn
		idSvc, err := identity.NewService(st, providers)
		if err != nil {
			return err
		}
		ekycFlow = &ekycBridge{id: idSvc, vn: vn}
		handler.RegisterIdentity(idSvc, ekycFlow)
		log.Info("vn eKYC enabled (verified tier)")
	} else {
		idSvc, err := identity.NewService(st, providers)
		if err != nil {
			return err
		}
		handler.RegisterIdentity(idSvc, nil)
	}

	fed, err := buildFederation(cfg, st, svc)
	if err != nil {
		return err
	}
	if fed != nil {
		handler.RegisterOIDC(fed)
		log.Info("oidc federated login enabled",
			"google", cfg.OIDC.Google != nil, "apple", cfg.OIDC.Apple != nil)
	}
	// Senders are captured so the step-up (re-auth) flow can reuse them — the
	// natural step-up for a passwordless platform is a fresh OTP to the user's
	// registered factor.
	var emailSender auth.CodeSender
	var smsSender auth.SMSSender
	if cfg.SMTP != nil {
		sender, err := emailsend.NewSMTPSender(emailsend.SMTPConfig{
			Host: cfg.SMTP.Host, Port: cfg.SMTP.Port, From: cfg.SMTP.From,
			Username: cfg.SMTP.Username, Password: cfg.SMTP.Password,
		})
		if err != nil {
			return err
		}
		emailSender = sender
		el, err := auth.NewEmailLogin(st, svc, sender)
		if err != nil {
			return err
		}
		handler.RegisterEmailLogin(el)
		log.Info("email-otp login enabled", "from", cfg.SMTP.From)
	} else if cfg.DevOTPConsole {
		emailSender = otpconsole.New(log, "email")
		el, err := auth.NewEmailLogin(st, svc, emailSender)
		if err != nil {
			return err
		}
		handler.RegisterEmailLogin(el)
		log.Warn("email-otp login enabled with DEV CONSOLE sender — codes are logged, never use in production")
	}
	if cfg.SMS != nil {
		sender, err := buildSMSSender(cfg.SMS)
		if err != nil {
			return err
		}
		smsSender = sender
		pl, err := auth.NewPhoneLogin(st, svc, sender)
		if err != nil {
			return err
		}
		handler.RegisterPhoneLogin(pl)
		log.Info("phone-otp login enabled", "provider", cfg.SMS.Provider)
	} else if cfg.DevOTPConsole {
		smsSender = otpconsole.New(log, "sms")
		pl, err := auth.NewPhoneLogin(st, svc, smsSender)
		if err != nil {
			return err
		}
		handler.RegisterPhoneLogin(pl)
		log.Warn("phone-otp login enabled with DEV CONSOLE sender — codes are logged, never use in production")
	}

	// Step-up re-authentication + the consolidated data export (PDPL right-of-
	// access). Available whenever at least one OTP sender exists; federated-only
	// accounts with no phone/email get a clear "unavailable" response.
	if emailSender != nil || smsSender != nil {
		stepUp, err := auth.NewStepUp(st, smsSender, emailSender)
		if err != nil {
			return err
		}
		handler.RegisterStepUp(stepUp)
		log.Info("step-up re-auth + data export enabled")
	}

	// Compose the API: auth at "/", class management always, and live sessions
	// when LiveKit is configured.
	apiMux := http.NewServeMux()
	apiMux.Handle("/", handler)

	// Entitlements gate paid content (ACCESS-MODEL): the class enrollment path and
	// recording playback consult it; free content passes through unchanged.
	entitlementSvc, err := entitlement.NewService(st)
	if err != nil {
		return err
	}
	entitlementHandler := entitlement.NewHandler(entitlementSvc, validator)
	apiMux.Handle("/v1/entitlements", entitlementHandler)
	apiMux.Handle("/v1/entitlements/", entitlementHandler)

	classSvc, err := class.NewService(st, class.WithEntitlements(entitlementSvc))
	if err != nil {
		return err
	}
	classHandler := class.NewHandler(classSvc, validator)
	apiMux.Handle("/v1/classes", classHandler)
	apiMux.Handle("/v1/classes/", classHandler)

	modSvc, err := moderation.NewService(st)
	if err != nil {
		return err
	}
	apiMux.Handle("/v1/moderation/", moderation.NewHandler(modSvc, validator))

	consentSvc, err := consent.NewService(st)
	if err != nil {
		return err
	}
	apiMux.Handle("/v1/consent/", consent.NewHandler(consentSvc, validator))

	if cfg.LiveKit != nil {
		granter, err := livekit.NewGranter(cfg.LiveKit.APIKey, cfg.LiveKit.APISecret, 10*time.Minute)
		if err != nil {
			return err
		}
		sessionSvc, err := session.NewService(st, granter, cfg.LiveKit.URL)
		if err != nil {
			return err
		}
		sessionHandler := session.NewHandler(sessionSvc, validator)
		apiMux.Handle("/v1/sessions", sessionHandler)  // exact (create)
		apiMux.Handle("/v1/sessions/", sessionHandler) // subtree (join/start/end/leave)
		log.Info("live sessions enabled", "url", cfg.LiveKit.URL)

		egressClient, err := livekit.NewEgressClient(cfg.LiveKit.HTTPURL, cfg.LiveKit.APIKey, cfg.LiveKit.APISecret, cfg.LiveKit.FilePrefix)
		if err != nil {
			return err
		}
		recordingSvc, err := recording.NewService(st, egressClient, recording.WithMaxConcurrent(cfg.LiveKit.RecordingMaxConcurrent))
		if err != nil {
			return err
		}
		recHandler := recording.NewHandler(recordingSvc, validator, cfg.LiveKit.APIKey, cfg.LiveKit.APISecret, cfg.LiveKit.RecordingsBaseURL, cfg.LiveKit.FilePrefix, cfg.LiveKit.RecordingsSecret, log, recording.WithEntitlements(entitlementSvc), recording.WithPlaybackTTL(cfg.LiveKit.PlaybackTTL))
		apiMux.Handle("/v1/recordings/", recHandler)
		apiMux.Handle("/v1/webhooks/", recHandler)
		// D-2: a consent withdrawal must stop an in-flight recording. Reconcile
		// best-effort after any consent change; failures are logged, not fatal,
		// since the (committed) ledger is the source of truth.
		consentSvc.OnChange(func(ctx context.Context, sessionID string) {
			if err := recordingSvc.ReconcileForSession(ctx, sessionID); err != nil {
				log.Error("recording reconcile failed", "session", sessionID, "err", err)
			}
		})
		log.Info("recording enabled", "egress", cfg.LiveKit.HTTPURL)
	}
	var api http.Handler = apiMux

	// Presence checkpoint worker (ADR-010 stage 2): periodically folds a
	// Vault-signed Merkle root over new presence events into the audit chain. Runs
	// in-process (no separate deployable); disabled when the interval is 0.
	if cfg.PresenceCheckpointInterval > 0 {
		presenceSvc, err := presence.NewService(st, audit.NewVerifier(verifyKeys))
		if err != nil {
			return err
		}
		go runPresenceCheckpoints(ctx, log, presenceSvc, cfg.PresenceCheckpointInterval)
		log.Info("presence checkpoint worker enabled", "interval", cfg.PresenceCheckpointInterval)
	}

	// Rate-limit the API per client IP, but NOT the health probes (k8s must
	// always reach them) nor the server-to-server endpoints, which arrive from a
	// single source IP and carry their own auth: the nginx auth_request for
	// recording playback (one subrequest per video range fetch) and the LiveKit
	// egress webhooks. Then wrap everything in request-id/logging/recovery.
	limiter := httpx.NewRateLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst)
	limitedAPI := limiter.LimitExcept(api, "/v1/recordings/authz", "/v1/webhooks/")
	root := httpx.Chain(rootHandler(limitedAPI, pool),
		httpx.RequestID,      // outermost: id available to logging + responses
		httpx.AccessLog(log), // record every response (incl. 429/500)
		httpx.Recover(log),   // panic -> 500, recorded by AccessLog
	)

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           root,
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

// buildSigning selects the Ed25519 signing backend and returns the verify-key
// set to trust. With Vault configured the private key stays in Vault and signing
// is a Transit call; the public key is fetched from Vault (unless already
// published in EnvVerifyKeys) so the service can verify its own tokens. Without
// Vault the in-process env-var key is used (the MVP default) and its public key
// was already self-registered by config.Load.
func buildSigning(ctx context.Context, cfg config.Config) (signing.KeySigner, map[string]ed25519.PublicKey, error) {
	verify := cfg.VerifyKeys
	if cfg.Vault == nil {
		ks, err := signing.NewLocalKeySigner(cfg.Kid, cfg.SigningKey)
		return ks, verify, err
	}

	vs, err := vaultsign.New(vaultsign.Config{
		Address: cfg.Vault.Address,
		Token:   cfg.Vault.Token,
		Mount:   cfg.Vault.Mount,
		KeyName: cfg.Vault.KeyName,
		KeyID:   cfg.Kid,
	}, nil)
	if err != nil {
		return nil, nil, err
	}
	if _, ok := verify[cfg.Kid]; !ok {
		fetchCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		pub, err := vs.PublicKey(fetchCtx)
		if err != nil {
			return nil, nil, fmt.Errorf("fetch signing public key from vault: %w", err)
		}
		verify[cfg.Kid] = pub
	}
	return vs, verify, nil
}

// runPresenceCheckpoints ticks the presence checkpoint worker until the context is
// cancelled. Each tick folds new presence events into one signed Merkle root;
// failures are logged and retried on the next tick (the work is resumable).
func runPresenceCheckpoints(ctx context.Context, log *slog.Logger, svc *presence.Service, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			wrote, err := svc.Checkpoint(ctx)
			if err != nil {
				log.Error("presence checkpoint failed", "err", err)
				continue
			}
			if wrote {
				log.Info("presence checkpoint written")
			}
		}
	}
}

// waitForDB pings the pool until it succeeds or a bounded deadline passes. A
// database that isn't accepting connections yet at startup is a transient,
// expected condition under orchestration (compose/k8s), not a fatal one.
func waitForDB(ctx context.Context, log *slog.Logger, pool *pgxpool.Pool) error {
	const timeout = 30 * time.Second
	deadline := time.Now().Add(timeout)
	for attempt := 1; ; attempt++ {
		err := pool.Ping(ctx)
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("database not ready after %s: %w", timeout, err)
		}
		log.Info("waiting for database to accept connections", "attempt", attempt)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
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
