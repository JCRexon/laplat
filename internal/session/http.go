package session

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/jcrexon/laplat/pkg/contracts"
	"github.com/jcrexon/laplat/pkg/token"
)

// Handler is the live-session HTTP surface. It authenticates the platform access
// token itself (via the validator) so it stays independent of the auth handler.
type Handler struct {
	svc       *Service
	validator *token.Validator
	mux       *http.ServeMux
}

type ctxKey struct{}

// NewHandler wires the service and the access-token validator and registers the
// session routes.
func NewHandler(svc *Service, validator *token.Validator) *Handler {
	h := &Handler{svc: svc, validator: validator, mux: http.NewServeMux()}
	h.mux.Handle("POST /v1/sessions", h.auth(h.create))
	h.mux.Handle("POST /v1/sessions/{id}/join", h.auth(h.join))
	h.mux.Handle("POST /v1/sessions/{id}/start", h.auth(h.start))
	h.mux.Handle("POST /v1/sessions/{id}/end", h.auth(h.end))
	h.mux.Handle("POST /v1/sessions/{id}/leave", h.auth(h.leave))
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }

// auth validates the bearer access token and stashes the claims in context.
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
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, claims)), claims)
	})
}

type createBody struct {
	Kind    string  `json:"kind"`
	ClassID *string `json:"classId,omitempty"`
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request, claims *contracts.AccessTokenClaims) {
	var req createBody
	if !decode(w, r, &req) {
		return
	}
	sess, err := h.svc.CreateSession(r.Context(), claims, req.Kind, req.ClassID)
	if err != nil {
		writeServiceErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{
		"sessionId": sess.ID,
		"room":      sess.LivekitRoom,
		"kind":      sess.Kind,
	})
}

func (h *Handler) join(w http.ResponseWriter, r *http.Request, claims *contracts.AccessTokenClaims) {
	res, err := h.svc.Join(r.Context(), claims, r.PathValue("id"))
	if err != nil {
		writeServiceErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"sessionId": res.SessionID,
		"room":      res.Room,
		"role":      res.Role,
		"token":     res.Token,
		"wsUrl":     res.WSURL,
	})
}

func (h *Handler) start(w http.ResponseWriter, r *http.Request, claims *contracts.AccessTokenClaims) {
	if err := h.svc.Start(r.Context(), claims, r.PathValue("id")); err != nil {
		writeServiceErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) end(w http.ResponseWriter, r *http.Request, claims *contracts.AccessTokenClaims) {
	if err := h.svc.End(r.Context(), claims, r.PathValue("id")); err != nil {
		writeServiceErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) leave(w http.ResponseWriter, r *http.Request, claims *contracts.AccessTokenClaims) {
	if err := h.svc.Leave(r.Context(), claims, r.PathValue("id")); err != nil {
		writeServiceErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- helpers -----------------------------------------------------------------

func writeServiceErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrForbidden):
		writeErr(w, http.StatusForbidden, "insufficient assurance or role")
	case errors.Is(err, ErrNotFound):
		writeErr(w, http.StatusNotFound, "session not found")
	case errors.Is(err, ErrSessionEnded):
		writeErr(w, http.StatusConflict, "session ended")
	case errors.Is(err, ErrInvalidKind), errors.Is(err, ErrClassRequired):
		writeErr(w, http.StatusBadRequest, err.Error())
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

func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request body")
		return false
	}
	return true
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
