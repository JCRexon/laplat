package recording

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/pkg/contracts"
	"github.com/jcrexon/laplat/pkg/token"
)

// Handler is the recording control HTTP surface. It self-authenticates via the
// access-token validator; the service enforces host-only control.
type Handler struct {
	svc       *Service
	validator *token.Validator
	mux       *http.ServeMux
}

// NewHandler wires the service and validator and registers routes under
// /v1/recordings/ (kept off the LiveKit-gated /v1/sessions/ subtree).
func NewHandler(svc *Service, validator *token.Validator) *Handler {
	h := &Handler{svc: svc, validator: validator, mux: http.NewServeMux()}
	h.mux.Handle("POST /v1/recordings/sessions/{sessionID}", h.auth(h.start))
	h.mux.Handle("DELETE /v1/recordings/sessions/{sessionID}", h.auth(h.stop))
	h.mux.Handle("GET /v1/recordings/sessions/{sessionID}", h.auth(h.list))
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

// start begins recording the session (host only, consent gate enforced).
func (h *Handler) start(w http.ResponseWriter, r *http.Request, claims *contracts.AccessTokenClaims) {
	rec, err := h.svc.Start(r.Context(), claims, r.PathValue("sessionID"))
	if err != nil {
		writeServiceErr(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, recordingJSON(rec))
}

// stop stops the session's in-flight recording (host only).
func (h *Handler) stop(w http.ResponseWriter, r *http.Request, claims *contracts.AccessTokenClaims) {
	if err := h.svc.Stop(r.Context(), claims, r.PathValue("sessionID")); err != nil {
		writeServiceErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// list returns a session's recordings (host only).
func (h *Handler) list(w http.ResponseWriter, r *http.Request, claims *contracts.AccessTokenClaims) {
	recs, err := h.svc.List(r.Context(), claims, r.PathValue("sessionID"))
	if err != nil {
		writeServiceErr(w, err)
		return
	}
	out := make([]map[string]any, 0, len(recs))
	for _, rec := range recs {
		out = append(out, recordingJSON(rec))
	}
	writeJSON(w, http.StatusOK, map[string]any{"recordings": out})
}

func recordingJSON(r store.Recording) map[string]any {
	m := map[string]any{
		"id":        r.ID,
		"sessionId": r.SessionID,
		"status":    r.Status,
		"startedAt": r.StartedAt.Unix(),
	}
	if r.OutputURI != "" {
		m["outputUri"] = r.OutputURI
	}
	if r.EndedAt != nil {
		m["endedAt"] = r.EndedAt.Unix()
	}
	return m
}

func writeServiceErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrForbidden):
		writeErr(w, http.StatusForbidden, "host only")
	case errors.Is(err, ErrNotFound):
		writeErr(w, http.StatusNotFound, "session not found")
	case errors.Is(err, ErrSessionEnded):
		writeErr(w, http.StatusConflict, "session already ended")
	case errors.Is(err, ErrConsentRequired):
		writeErr(w, http.StatusForbidden, "not all present participants have consented")
	case errors.Is(err, ErrAlreadyRecording):
		writeErr(w, http.StatusConflict, "already recording")
	case errors.Is(err, ErrNotRecording):
		writeErr(w, http.StatusConflict, "no recording in flight")
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
