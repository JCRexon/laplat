package auth

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/jcrexon/laplat/pkg/contracts"
)

// ToSAcceptor records a Terms-of-Service acceptance + 18+ self-attestation
// (identity.Service satisfies it). Kept as a narrow interface so auth does not
// depend on the identity package.
type ToSAcceptor interface {
	AcceptToS(ctx context.Context, userID, version string, adultAttested bool) error
}

// EKYCService drives adult verification (the 'verified' tier). Begin starts a
// hosted check; ApplyCallback validates and applies a vendor completion webhook.
// ApplyCallback must return ErrWebhookSignature for an unauthentic/malformed
// callback, and nil for any validly-processed callback (including a not-approved
// outcome, which is acknowledged without changing state).
type EKYCService interface {
	BeginVerification(ctx context.Context, userID, region string) (provider, ref, redirectURL string, err error)
	ApplyCallback(ctx context.Context, body []byte, signature string) error
}

// ErrWebhookSignature marks an unauthentic or malformed eKYC callback.
var ErrWebhookSignature = errors.New("auth: ekyc webhook signature invalid")

// EKYCSignatureHeader carries the vendor's HMAC over the raw callback body.
const EKYCSignatureHeader = "X-EKYC-Signature"

// RegisterIdentity mounts the self-declaration endpoint (always) and, when an
// EKYCService is provided, the adult-verification begin/callback endpoints.
func (h *Handler) RegisterIdentity(tos ToSAcceptor, ekyc EKYCService) {
	h.tos = tos
	h.ekyc = ekyc
	h.mux.Handle("POST /v1/identity/tos-accept",
		h.requireAuth(http.HandlerFunc(h.handleToSAccept)))
	if ekyc != nil {
		h.mux.Handle("POST /v1/identity/verify/begin",
			h.requireAuth(http.HandlerFunc(h.handleVerifyBegin)))
		// Callback is a vendor webhook: authenticated by HMAC, not a bearer token.
		h.mux.HandleFunc("POST /v1/identity/verify/callback", h.handleVerifyCallback)
	}
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

type verifyBeginBody struct {
	Region string `json:"region"`
}

// handleVerifyBegin starts an eKYC session for the caller and returns the hosted
// redirect to complete it at.
func (h *Handler) handleVerifyBegin(w http.ResponseWriter, r *http.Request) {
	claims, _ := ClaimsFrom(r.Context())
	var req verifyBeginBody
	if !decodeJSON(w, r, &req) {
		return
	}
	region := req.Region
	if region == "" {
		region = "default"
	}
	provider, ref, redirect, err := h.ekyc.BeginVerification(r.Context(), claims.Subject, region)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not start verification")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"provider": provider, "ref": ref, "redirectUrl": redirect,
	})
}

// handleVerifyCallback applies a vendor completion webhook. The body is read raw
// (the HMAC is over the exact bytes); an unauthentic callback is 401. A
// validly-processed callback — approved OR rejected — is acknowledged with 204.
func (h *Handler) handleVerifyCallback(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "unreadable body")
		return
	}
	err = h.ekyc.ApplyCallback(r.Context(), body, r.Header.Get(EKYCSignatureHeader))
	switch {
	case errors.Is(err, ErrWebhookSignature):
		writeError(w, http.StatusUnauthorized, "invalid signature")
	case err != nil:
		writeError(w, http.StatusInternalServerError, "callback failed")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}
