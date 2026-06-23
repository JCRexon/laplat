package auth

import (
	"errors"
	"net/http"
)

// email field length cap at the boundary.
const maxEmailLen = 320 // RFC 5321 max addr length

// RegisterEmailLogin mounts the first-party email-OTP routes. Call after
// NewHandler when an email sender is configured; without it the routes 404.
func (h *Handler) RegisterEmailLogin(el *EmailLogin) {
	h.email = el
	h.mux.HandleFunc("POST /v1/auth/email/request", h.handleEmailRequest)
	h.mux.HandleFunc("POST /v1/auth/email/verify", h.handleEmailVerify)
}

type emailRequestBody struct {
	Email string `json:"email"`
}

type emailVerifyBody struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

func (h *Handler) handleEmailRequest(w http.ResponseWriter, r *http.Request) {
	var req emailRequestBody
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Email == "" || len(req.Email) > maxEmailLen {
		writeError(w, http.StatusBadRequest, "invalid email")
		return
	}
	// Uniform 202 regardless of whether the email maps to an account, and even
	// for a malformed address — never reveal account existence or validity here.
	if err := h.email.RequestCode(r.Context(), req.Email); err != nil {
		// A bad address shape is the only client error worth a 400; everything
		// else is internal and must not leak.
		if errors.Is(err, errBadEmail) {
			writeError(w, http.StatusBadRequest, "invalid email")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not send code")
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) handleEmailVerify(w http.ResponseWriter, r *http.Request) {
	var req emailVerifyBody
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Email == "" || len(req.Email) > maxEmailLen || req.Code == "" || len(req.Code) > 16 {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	sess, err := h.email.VerifyCode(r.Context(), req.Email, req.Code)
	if err != nil {
		// Wrong/expired/used code and not-active account both map cleanly; any
		// other error is internal.
		if errors.Is(err, ErrInvalidCode) {
			writeError(w, http.StatusUnauthorized, "invalid or expired code")
			return
		}
		writeSessionError(w, err)
		return
	}
	writeSession(w, sess)
}
