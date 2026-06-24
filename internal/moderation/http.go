package moderation

import (
	"errors"
	"net/http"
	"strings"

	"github.com/jcrexon/laplat/pkg/contracts"
	"github.com/jcrexon/laplat/pkg/token"
)

// Handler is the moderation HTTP surface, self-authenticating via the
// access-token validator and gating on the platform_moderator capability.
type Handler struct {
	svc       *Service
	validator *token.Validator
	mux       *http.ServeMux
}

// NewHandler wires the service and validator and registers routes.
func NewHandler(svc *Service, validator *token.Validator) *Handler {
	h := &Handler{svc: svc, validator: validator, mux: http.NewServeMux()}
	h.mux.Handle("POST /v1/moderation/users/{id}/suspend", h.auth(h.suspend))
	h.mux.Handle("POST /v1/moderation/users/{id}/reinstate", h.auth(h.reinstate))
	h.mux.Handle("POST /v1/moderation/users/{id}/instructor", h.auth(h.grantInstructor))
	h.mux.Handle("DELETE /v1/moderation/users/{id}/instructor", h.auth(h.revokeInstructor))
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }

func (h *Handler) auth(next func(http.ResponseWriter, *http.Request, *contracts.AccessTokenClaims)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := bearer(r)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		claims, err := h.validator.Validate(r.Context(), raw)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "invalid token")
			return
		}
		next(w, r, claims)
	})
}

func (h *Handler) suspend(w http.ResponseWriter, r *http.Request, claims *contracts.AccessTokenClaims) {
	if err := h.svc.Suspend(r.Context(), claims, r.PathValue("id")); err != nil {
		writeServiceErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) reinstate(w http.ResponseWriter, r *http.Request, claims *contracts.AccessTokenClaims) {
	if err := h.svc.Reinstate(r.Context(), claims, r.PathValue("id")); err != nil {
		writeServiceErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) grantInstructor(w http.ResponseWriter, r *http.Request, claims *contracts.AccessTokenClaims) {
	if err := h.svc.SetInstructor(r.Context(), claims, r.PathValue("id"), true); err != nil {
		writeServiceErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) revokeInstructor(w http.ResponseWriter, r *http.Request, claims *contracts.AccessTokenClaims) {
	if err := h.svc.SetInstructor(r.Context(), claims, r.PathValue("id"), false); err != nil {
		writeServiceErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeServiceErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrForbidden):
		writeErr(w, http.StatusForbidden, "requires platform moderator")
	case errors.Is(err, ErrCannotReinstate):
		writeErr(w, http.StatusConflict, "cannot reinstate")
	default:
		writeErr(w, http.StatusInternalServerError, "internal error")
	}
}

func bearer(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	tok := strings.TrimSpace(h[len(prefix):])
	return tok, tok != ""
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"` + msg + `"}`))
}
