package class

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/pkg/contracts"
	"github.com/jcrexon/laplat/pkg/token"
)

// Handler is the class-management HTTP surface. It authenticates the platform
// access token itself, so it is independent of the auth handler.
type Handler struct {
	svc       *Service
	validator *token.Validator
	mux       *http.ServeMux
}

// NewHandler wires the service and validator and registers routes.
func NewHandler(svc *Service, validator *token.Validator) *Handler {
	h := &Handler{svc: svc, validator: validator, mux: http.NewServeMux()}
	h.mux.Handle("POST /v1/classes", h.auth(h.create))
	h.mux.Handle("GET /v1/classes", h.auth(h.listMine))
	h.mux.Handle("GET /v1/classes/published", h.auth(h.listPublished))
	// Enrollment: GET /v1/classes/enrolled must be more specific than
	// POST/DELETE /v1/classes/{id}/enroll — Go 1.22 mux prefers literals.
	h.mux.Handle("GET /v1/classes/enrolled", h.auth(h.listEnrolled))
	h.mux.Handle("POST /v1/classes/{id}/enroll", h.auth(h.enroll))
	h.mux.Handle("DELETE /v1/classes/{id}/enroll", h.auth(h.unenroll))
	h.mux.Handle("POST /v1/classes/{id}/status", h.auth(h.setStatus))
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
		next(w, r.WithContext(r.Context()), claims)
	})
}

type createBody struct {
	Title       string `json:"title"`
	Description string `json:"description"`
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request, claims *contracts.AccessTokenClaims) {
	var req createBody
	if !decode(w, r, &req) {
		return
	}
	c, err := h.svc.Create(r.Context(), claims, req.Title, req.Description)
	if err != nil {
		writeServiceErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, classView(c))
}

func (h *Handler) listMine(w http.ResponseWriter, r *http.Request, claims *contracts.AccessTokenClaims) {
	classes, err := h.svc.ListMine(r.Context(), claims)
	if err != nil {
		writeServiceErr(w, err)
		return
	}
	out := make([]map[string]string, 0, len(classes))
	for _, c := range classes {
		out = append(out, classView(c))
	}
	writeJSON(w, http.StatusOK, map[string]any{"classes": out})
}

func (h *Handler) listPublished(w http.ResponseWriter, r *http.Request, _ *contracts.AccessTokenClaims) {
	classes, err := h.svc.ListPublished(r.Context())
	if err != nil {
		writeServiceErr(w, err)
		return
	}
	out := make([]map[string]string, 0, len(classes))
	for _, c := range classes {
		out = append(out, classView(c))
	}
	writeJSON(w, http.StatusOK, map[string]any{"classes": out})
}

type statusBody struct {
	Status string `json:"status"`
}

func (h *Handler) enroll(w http.ResponseWriter, r *http.Request, claims *contracts.AccessTokenClaims) {
	if err := h.svc.Enroll(r.Context(), claims, r.PathValue("id")); err != nil {
		writeServiceErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) unenroll(w http.ResponseWriter, r *http.Request, claims *contracts.AccessTokenClaims) {
	if err := h.svc.Unenroll(r.Context(), claims, r.PathValue("id")); err != nil {
		writeServiceErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listEnrolled(w http.ResponseWriter, r *http.Request, claims *contracts.AccessTokenClaims) {
	classes, err := h.svc.ListEnrolled(r.Context(), claims)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	out := make([]map[string]string, 0, len(classes))
	for _, c := range classes {
		out = append(out, classView(c))
	}
	writeJSON(w, http.StatusOK, map[string]any{"classes": out})
}

func (h *Handler) setStatus(w http.ResponseWriter, r *http.Request, claims *contracts.AccessTokenClaims) {
	var req statusBody
	if !decode(w, r, &req) {
		return
	}
	if err := h.svc.SetStatus(r.Context(), claims, r.PathValue("id"), req.Status); err != nil {
		writeServiceErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- helpers -----------------------------------------------------------------

func classView(c store.Class) map[string]string {
	return map[string]string{
		"id":          c.ID,
		"title":       c.Title,
		"description": c.Description,
		"status":      c.Status,
	}
}

func writeServiceErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrForbidden):
		writeErr(w, http.StatusForbidden, "insufficient tier or capability")
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrClassNotFound):
		writeErr(w, http.StatusNotFound, "class not found")
	case errors.Is(err, ErrBadTitle), errors.Is(err, ErrBadStatus):
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
