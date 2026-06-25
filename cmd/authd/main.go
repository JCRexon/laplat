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

	"github.com/jcrexon/laplat/internal/audit"
	"github.com/jcrexon/laplat/internal/auth"
	"github.com/jcrexon/laplat/internal/class"
	"github.com/jcrexon/laplat/internal/config"
	"github.com/jcrexon/laplat/internal/ekyc"
	"github.com/jcrexon/laplat/internal/emailsend"
	"github.com/jcrexon/laplat/internal/httpx"
	"github.com/jcrexon/laplat/internal/identity"
	"github.com/jcrexon/laplat/internal/livekit"
	"github.com/jcrexon/laplat/internal/moderation"
	"github.com/jcrexon/laplat/internal/otpconsole"
	"github.com/jcrexon/laplat/internal/session"
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

	auditSigner, err := audit.NewSigner(cfg.Kid, cfg.SigningKey)
	if err != nil {
		return err
	}
	st := store.New(pool, store.WithAuditSigner(auditSigner))
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
	if cfg.SMTP != nil {
		sender, err := emailsend.NewSMTPSender(emailsend.SMTPConfig{
			Host: cfg.SMTP.Host, Port: cfg.SMTP.Port, From: cfg.SMTP.From,
			Username: cfg.SMTP.Username, Password: cfg.SMTP.Password,
		})
		if err != nil {
			return err
		}
		el, err := auth.NewEmailLogin(st, svc, sender)
		if err != nil {
			return err
		}
		handler.RegisterEmailLogin(el)
		log.Info("email-otp login enabled", "from", cfg.SMTP.From)
	} else if cfg.DevOTPConsole {
		el, err := auth.NewEmailLogin(st, svc, otpconsole.New(log, "email"))
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
		pl, err := auth.NewPhoneLogin(st, svc, sender)
		if err != nil {
			return err
		}
		handler.RegisterPhoneLogin(pl)
		log.Info("phone-otp login enabled", "provider", cfg.SMS.Provider)
	} else if cfg.DevOTPConsole {
		pl, err := auth.NewPhoneLogin(st, svc, otpconsole.New(log, "sms"))
		if err != nil {
			return err
		}
		handler.RegisterPhoneLogin(pl)
		log.Warn("phone-otp login enabled with DEV CONSOLE sender — codes are logged, never use in production")
	}

	// Compose the API: auth at "/", class management always, and live sessions
	// when LiveKit is configured.
	apiMux := http.NewServeMux()
	apiMux.Handle("/", handler)

	classSvc, err := class.NewService(st)
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
	}
	var api http.Handler = apiMux

	// Rate-limit the API per client IP, but NOT the health probes (k8s must
	// always reach them). Then wrap everything in request-id/logging/recovery.
	limiter := httpx.NewRateLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst)
	limitedAPI := limiter.Limit(api)
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
