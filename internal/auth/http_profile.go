package auth

import (
	"context"
	"net/http"
	"time"

	"github.com/jcrexon/laplat/internal/store"
)

// ProfileReader queries the user-facing activity data for the /v1/me/* endpoints.
type ProfileReader interface {
	GetIdentityFactors(ctx context.Context, userID string) (store.IdentityFactors, error)
	ListSessionHistory(ctx context.Context, userID string) ([]store.SessionEntry, error)
	ListConsentHistory(ctx context.Context, userID string) ([]store.ConsentEntry, error)
}

// RegisterProfile wires the profile store so the /v1/me/identities,
// /v1/me/sessions, and /v1/me/consents endpoints are served.
func (h *Handler) RegisterProfile(r ProfileReader) {
	h.profile = r
}

func (h *Handler) handleMeIdentities(w http.ResponseWriter, r *http.Request) {
	if h.profile == nil {
		writeError(w, http.StatusNotImplemented, "not configured")
		return
	}
	claims, _ := ClaimsFrom(r.Context())
	factors, err := h.profile.GetIdentityFactors(r.Context(), claims.Subject)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load identities")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"email":     factors.Email,
		"phone":     factors.Phone,
		"federated": factors.Federated,
	})
}

type sessionHistoryItem struct {
	SessionID      string  `json:"sessionId"`
	Kind           string  `json:"kind"`
	Status         string  `json:"status"`
	Role           string  `json:"role"`
	JoinedAt       string  `json:"joinedAt"`
	LeftAt         *string `json:"leftAt"`
	ClassID        *string `json:"classId"`
	ClassTitle     *string `json:"classTitle"`
	ScheduledStart *string `json:"scheduledStart"`
	DurationMin    *int    `json:"durationMinutes"`
}

func (h *Handler) handleMeSessions(w http.ResponseWriter, r *http.Request) {
	if h.profile == nil {
		writeError(w, http.StatusNotImplemented, "not configured")
		return
	}
	claims, _ := ClaimsFrom(r.Context())
	entries, err := h.profile.ListSessionHistory(r.Context(), claims.Subject)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load sessions")
		return
	}
	items := make([]sessionHistoryItem, 0, len(entries))
	for _, e := range entries {
		item := sessionHistoryItem{
			SessionID:  e.SessionID,
			Kind:       e.Kind,
			Status:     e.Status,
			Role:       e.Role,
			JoinedAt:   e.JoinedAt.UTC().Format(time.RFC3339),
			ClassID:    e.ClassID,
			ClassTitle: e.ClassTitle,
		}
		if e.LeftAt != nil {
			s := e.LeftAt.UTC().Format(time.RFC3339)
			item.LeftAt = &s
			mins := int(e.LeftAt.Sub(e.JoinedAt).Minutes())
			if mins < 0 {
				mins = 0
			}
			item.DurationMin = &mins
		}
		if e.ScheduledStart != nil {
			s := e.ScheduledStart.UTC().Format(time.RFC3339)
			item.ScheduledStart = &s
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": items})
}

type consentHistoryItem struct {
	ID        string `json:"id"`
	SessionID string `json:"sessionId"`
	Purpose   string `json:"purpose"`
	Granted   bool   `json:"granted"`
	GrantedAt string `json:"grantedAt"`
}

func (h *Handler) handleMeConsents(w http.ResponseWriter, r *http.Request) {
	if h.profile == nil {
		writeError(w, http.StatusNotImplemented, "not configured")
		return
	}
	claims, _ := ClaimsFrom(r.Context())
	entries, err := h.profile.ListConsentHistory(r.Context(), claims.Subject)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load consents")
		return
	}
	items := make([]consentHistoryItem, 0, len(entries))
	for _, e := range entries {
		items = append(items, consentHistoryItem{
			ID:        e.ID,
			SessionID: e.SessionID,
			Purpose:   e.Purpose,
			Granted:   e.Granted,
			GrantedAt: e.GrantedAt.UTC().Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"consents": items})
}
