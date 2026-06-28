package entitlement

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/pkg/contracts"
	"github.com/jcrexon/laplat/pkg/token"
)

// Handler is the entitlement HTTP surface. It self-authenticates via the
// access-token validator. "My library" is open to any authenticated user; grant
// and revoke require the platform_moderator capability (the comp/support path)
// until a payment provider drives Grant on a completed charge.
type Handler struct {
	svc       *Service
	validator *token.Validator
	mux       *http.ServeMux
}

// NewHandler wires the service and validator and registers routes.
func NewHandler(svc *Service, validator *token.Validator) *Handler {
	h := &Handler{svc: svc, validator: validator, mux: http.NewServeMux()}
	h.mux.Handle("GET /v1/entitlements/me", h.auth(h.listMine))
	h.mux.Handle("POST /v1/entitlements", h.auth(h.grant))
	h.mux.Handle("DELETE /v1/entitlements", h.auth(h.revoke))
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

// listMine returns the caller's active entitlements.
func (h *Handler) listMine(w http.ResponseWriter, r *http.Request, claims *contracts.AccessTokenClaims) {
	ents, err := h.svc.List(r.Context(), claims.Subject)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	out := make([]map[string]any, 0, len(ents))
	for _, e := range ents {
		out = append(out, entitlementJSON(e))
	}
	writeJSON(w, http.StatusOK, map[string]any{"entitlements": out})
}

type grantReq struct {
	SubjectID  string `json:"subjectId"`
	ClassID    string `json:"classId"`
	PriceCents int    `json:"priceCents"`
}

// grant records a moderator comp/support entitlement for a class.
func (h *Handler) grant(w http.ResponseWriter, r *http.Request, claims *contracts.AccessTokenClaims) {
	if !claims.HasCapability(contracts.CapPlatformModerator) {
		writeErr(w, http.StatusForbidden, "requires platform moderator")
		return
	}
	var req grantReq
	if !decode(w, r, &req) {
		return
	}
	ent, err := h.svc.Grant(r.Context(), req.SubjectID, ResourceClass, req.ClassID, SourceGrant, req.PriceCents, nil)
	switch {
	case err == nil:
		writeJSON(w, http.StatusCreated, entitlementJSON(ent))
	case errors.Is(err, ErrExists):
		writeErr(w, http.StatusConflict, "already entitled")
	case errors.Is(err, ErrBadInput):
		writeErr(w, http.StatusBadRequest, "invalid grant")
	default:
		writeErr(w, http.StatusInternalServerError, "internal error")
	}
}

type revokeReq struct {
	SubjectID string `json:"subjectId"`
	ClassID   string `json:"classId"`
}

// revoke withdraws a moderator-revocable entitlement (refund/admin).
func (h *Handler) revoke(w http.ResponseWriter, r *http.Request, claims *contracts.AccessTokenClaims) {
	if !claims.HasCapability(contracts.CapPlatformModerator) {
		writeErr(w, http.StatusForbidden, "requires platform moderator")
		return
	}
	var req revokeReq
	if !decode(w, r, &req) {
		return
	}
	ok, err := h.svc.Revoke(r.Context(), req.SubjectID, ResourceClass, req.ClassID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "no active entitlement")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func entitlementJSON(e store.Entitlement) map[string]any {
	m := map[string]any{
		"id":           e.ID,
		"subjectId":    e.SubjectID,
		"resourceType": e.ResourceType,
		"resourceId":   e.ResourceID,
		"source":       e.Source,
		"priceCents":   e.PriceCents,
		"grantedAt":    e.GrantedAt.UTC().Format(time.RFC3339),
	}
	if e.ExpiresAt != nil {
		m["expiresAt"] = e.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return m
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request body")
		return false
	}
	return true
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
