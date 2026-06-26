package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jcrexon/laplat/pkg/contracts"
	"github.com/jcrexon/laplat/pkg/token"
)

// maxRefreshTokenLen bounds the accepted refresh-token length at the boundary.
// Our tokens are 22 chars (128 bits, base64url); the cap rejects oversized junk
// before it reaches the hasher.
const maxRefreshTokenLen = 512

// claimsKey is the private context key under which validated access-token
// claims are stored by RequireAuth.
type claimsKey struct{}

// Handler is the auth service's HTTP surface. Construct it with NewHandler and
// serve it directly (it is an http.Handler).
type Handler struct {
	svc       *Service
	validator *token.Validator
	oidc      *Federation  // nil unless RegisterOIDC was called
	email     *EmailLogin  // nil unless RegisterEmailLogin was called
	phone     *PhoneLogin  // nil unless RegisterPhoneLogin was called
	tos       ToSAcceptor  // nil unless RegisterIdentity was called
	ekyc      EKYCService  // nil unless RegisterIdentity received one
	profile   ProfileReader // nil unless RegisterProfile was called
	mux       *http.ServeMux
}

// NewHandler wires the service and the access-token validator and registers
// routes. The validator backs the bearer-auth middleware (A-1 + A-5).
func NewHandler(svc *Service, validator *token.Validator) *Handler {
	h := &Handler{svc: svc, validator: validator, mux: http.NewServeMux()}
	// Public: presents a refresh token, no access token required.
	h.mux.HandleFunc("POST /v1/token/refresh", h.handleRefresh)
	// Protected: require a (still-valid) access token to log out / introspect.
	h.mux.Handle("POST /v1/token/logout", h.requireAuth(http.HandlerFunc(h.handleLogout)))
	h.mux.Handle("POST /v1/token/logout-all", h.requireAuth(http.HandlerFunc(h.handleLogoutAll)))
	h.mux.Handle("GET /v1/me", h.requireAuth(http.HandlerFunc(h.handleMe)))
	h.mux.Handle("PATCH /v1/me", h.requireAuth(http.HandlerFunc(h.handleUpdateProfile)))
	h.mux.Handle("DELETE /v1/me", h.requireAuth(http.HandlerFunc(h.handleCloseAccount)))
	h.mux.Handle("POST /v1/instructor/apply", h.requireAuth(http.HandlerFunc(h.handleBecomeInstructor)))
	h.mux.Handle("GET /v1/me/identities", h.requireAuth(http.HandlerFunc(h.handleMeIdentities)))
	h.mux.Handle("GET /v1/me/sessions", h.requireAuth(http.HandlerFunc(h.handleMeSessions)))
	h.mux.Handle("GET /v1/me/consents", h.requireAuth(http.HandlerFunc(h.handleMeConsents)))
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }

// --- middleware --------------------------------------------------------------

// requireAuth validates the Bearer access token and stashes the claims in the
// request context. Any validation failure (bad signature, wrong alg, expired,
// revoked, superseded) yields 401 with no detail.
func (h *Handler) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := bearerToken(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		claims, err := h.validator.Validate(r.Context(), raw)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		ctx := context.WithValue(r.Context(), claimsKey{}, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ClaimsFrom returns the validated claims attached by RequireAuth, if any.
func ClaimsFrom(ctx context.Context) (*contracts.AccessTokenClaims, bool) {
	c, ok := ctx.Value(claimsKey{}).(*contracts.AccessTokenClaims)
	return c, ok
}

// --- handlers ----------------------------------------------------------------

type refreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

type sessionResponse struct {
	AccessToken      string `json:"accessToken"`
	RefreshToken     string `json:"refreshToken"`
	AccessExpiresAt  int64  `json:"accessExpiresAt"`
	RefreshExpiresAt int64  `json:"refreshExpiresAt"`
}

func (h *Handler) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.RefreshToken == "" || len(req.RefreshToken) > maxRefreshTokenLen {
		writeError(w, http.StatusBadRequest, "invalid refresh token")
		return
	}
	sess, err := h.svc.Refresh(r.Context(), req.RefreshToken)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	writeSession(w, sess)
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	claims, _ := ClaimsFrom(r.Context()) // guaranteed by requireAuth
	var req refreshRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.RefreshToken) > maxRefreshTokenLen {
		writeError(w, http.StatusBadRequest, "invalid refresh token")
		return
	}
	if err := h.svc.Logout(r.Context(), req.RefreshToken, claims.TokenID,
		time.Unix(claims.ExpiresAt, 0)); err != nil {
		writeError(w, http.StatusInternalServerError, "logout failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type meResponse struct {
	UserID               string                 `json:"userId"`
	IdentityVerification string                 `json:"identityVerification"`
	Capabilities         []contracts.Capability `json:"capabilities"`
}

func (h *Handler) handleMe(w http.ResponseWriter, r *http.Request) {
	claims, _ := ClaimsFrom(r.Context())
	caps := claims.Capabilities
	if caps == nil {
		caps = []contracts.Capability{}
	}
	writeJSON(w, http.StatusOK, meResponse{
		UserID:               claims.Subject,
		IdentityVerification: string(claims.IdentityVerification),
		Capabilities:         caps,
	})
}

type updateProfileBody struct {
	Handle      string `json:"handle"`
	DisplayName string `json:"displayName"`
	Bio         string `json:"bio"`
}

// handleUpdateProfile sets the caller's editable profile fields (handle,
// display name, bio). A malformed field is 400; a taken handle is 409.
func (h *Handler) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	claims, _ := ClaimsFrom(r.Context())
	var req updateProfileBody
	if !decodeJSON(w, r, &req) {
		return
	}
	err := h.svc.UpdateProfile(r.Context(), claims.Subject, req.Handle, req.DisplayName, req.Bio)
	switch {
	case errors.Is(err, ErrInvalidProfile):
		writeError(w, http.StatusBadRequest, "invalid profile")
	case errors.Is(err, ErrHandleTaken):
		writeError(w, http.StatusConflict, "handle already taken")
	case err != nil:
		writeError(w, http.StatusInternalServerError, "could not update profile")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// handleLogoutAll revokes every session for the caller ("log out on all
// devices") without deleting the account. The presented token is invalid after.
func (h *Handler) handleLogoutAll(w http.ResponseWriter, r *http.Request) {
	claims, _ := ClaimsFrom(r.Context())
	if err := h.svc.LogoutEverywhere(r.Context(), claims.Subject); err != nil {
		writeError(w, http.StatusInternalServerError, "logout-all failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleBecomeInstructor grants the caller the can_instruct capability if they
// are verified (eKYC). 204 on success (refresh to pick up the capability); 403
// if not yet verified. Idempotent.
func (h *Handler) handleBecomeInstructor(w http.ResponseWriter, r *http.Request) {
	claims, _ := ClaimsFrom(r.Context())
	err := h.svc.BecomeInstructor(r.Context(), claims)
	switch {
	case errors.Is(err, ErrNotVerified):
		writeError(w, http.StatusForbidden, "requires verified identity")
	case err != nil:
		writeError(w, http.StatusInternalServerError, "could not grant instructor")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// handleCloseAccount is self-service account erasure: it soft-deletes the
// caller's account and revokes all their tokens (the presented token is invalid
// thereafter).
func (h *Handler) handleCloseAccount(w http.ResponseWriter, r *http.Request) {
	claims, _ := ClaimsFrom(r.Context())
	if err := h.svc.CloseAccount(r.Context(), claims.Subject); err != nil {
		writeError(w, http.StatusInternalServerError, "could not close account")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- helpers -----------------------------------------------------------------

// bearerToken extracts a token from "Authorization: Bearer <token>".
func bearerToken(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	tok := strings.TrimSpace(h[len(prefix):])
	if tok == "" {
		return "", false
	}
	return tok, true
}

// decodeJSON strictly decodes a small JSON body, writing a 400 on failure.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request body")
		return false
	}
	return true
}

func writeSession(w http.ResponseWriter, s Session) {
	writeJSON(w, http.StatusOK, sessionResponse{
		AccessToken:      s.AccessToken,
		RefreshToken:     s.RefreshToken,
		AccessExpiresAt:  s.AccessClaims.ExpiresAt,
		RefreshExpiresAt: s.RefreshExpiresAt.Unix(),
	})
}

// writeSessionError maps service errors to status codes without leaking which
// specific check failed.
func writeSessionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrUnauthenticated):
		writeError(w, http.StatusUnauthorized, "invalid credentials")
	case errors.Is(err, ErrAccountNotActive):
		writeError(w, http.StatusForbidden, "account not active")
	default:
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
