package auth

import (
	"context"
	"net/http"

	"github.com/jcrexon/laplat/pkg/contracts"
)

// ToSAcceptor records a Terms-of-Service acceptance + 18+ self-attestation
// (identity.Service satisfies it). Kept as a narrow interface so auth does not
// depend on the identity package.
type ToSAcceptor interface {
	AcceptToS(ctx context.Context, userID, version string, adultAttested bool) error
}

// RegisterIdentity mounts the self-declaration endpoint. The 18+ attestation is
// the 'declared' assurance tier (general features); eKYC remains separate.
func (h *Handler) RegisterIdentity(tos ToSAcceptor) {
	h.tos = tos
	h.mux.Handle("POST /v1/identity/tos-accept",
		h.requireAuth(http.HandlerFunc(h.handleToSAccept)))
}

type tosAcceptBody struct {
	AdultAttested bool `json:"adultAttested"`
}

// handleToSAccept records the caller's ToS acceptance and adult attestation
// against the current ToS version. On an adult attestation the account is
// activated; the client must then refresh to obtain a token carrying the
// upgraded "declared" tier (claims are re-derived from the DB at refresh).
func (h *Handler) handleToSAccept(w http.ResponseWriter, r *http.Request) {
	claims, _ := ClaimsFrom(r.Context()) // guaranteed by requireAuth
	var req tosAcceptBody
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := h.tos.AcceptToS(r.Context(), claims.Subject, contracts.CurrentToSVersion, req.AdultAttested); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record acceptance")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
