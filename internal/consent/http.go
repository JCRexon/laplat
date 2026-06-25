package consent

import (
	"net/http"
	"strings"

	"github.com/jcrexon/laplat/pkg/contracts"
	"github.com/jcrexon/laplat/pkg/token"
)

// Handler is the recording-consent HTTP surface. It self-authenticates via the
// access-token validator; a subject only ever acts on their own consent, so the
// subject is taken from the token claims, never from the request body.
type Handler struct {
	svc       *Service
	validator *token.Validator
	mux       *http.ServeMux
}

// NewHandler wires the service and validator and registers routes under
// /v1/consent/ (kept off the LiveKit-gated /v1/sessions/ subtree).
func NewHandler(svc *Service, validator *token.Validator) *Handler {
	h := &Handler{svc: svc, validator: validator, mux: http.NewServeMux()}
	h.mux.Handle("POST /v1/consent/sessions/{sessionID}", h.auth(h.grant))
	h.mux.Handle("DELETE /v1/consent/sessions/{sessionID}", h.auth(h.withdraw))
	h.mux.Handle("GET /v1/consent/sessions/{sessionID}", h.auth(h.status))
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

// grant records the subject's consent to record the session.
func (h *Handler) grant(w http.ResponseWriter, r *http.Request, claims *contracts.AccessTokenClaims) {
	if err := h.svc.Grant(r.Context(), claims.Subject, r.PathValue("sessionID")); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// withdraw records a withdrawal of the subject's consent (a new granted=false
// record; the ledger is never deleted from).
func (h *Handler) withdraw(w http.ResponseWriter, r *http.Request, claims *contracts.AccessTokenClaims) {
	if err := h.svc.Withdraw(r.Context(), claims.Subject, r.PathValue("sessionID")); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// status reports the subject's current effective consent for the session.
func (h *Handler) status(w http.ResponseWriter, r *http.Request, claims *contracts.AccessTokenClaims) {
	granted, err := h.svc.Effective(r.Context(), claims.Subject, r.PathValue("sessionID"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if granted {
		_, _ = w.Write([]byte(`{"granted":true}`))
	} else {
		_, _ = w.Write([]byte(`{"granted":false}`))
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
