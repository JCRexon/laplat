package auth

import (
	"errors"
	"net/http"
)

const maxPhoneLen = 24 // "+" + up to 15 digits, with slack for separators

// RegisterPhoneLogin mounts the phone-OTP routes. Verify is intentionally not
// behind requireAuth: it serves both phone-first login (anonymous) and an
// authenticated phone-binding upgrade. When a valid bearer IS present, the
// phone is bound to that account; otherwise it logs in / creates an account.
func (h *Handler) RegisterPhoneLogin(pl *PhoneLogin) {
	h.phone = pl
	h.mux.HandleFunc("POST /v1/auth/phone/request", h.handlePhoneRequest)
	h.mux.HandleFunc("POST /v1/auth/phone/verify", h.handlePhoneVerify)
}

type phoneRequestBody struct {
	Phone string `json:"phone"`
}

type phoneVerifyBody struct {
	Phone string `json:"phone"`
	Code  string `json:"code"`
}

func (h *Handler) handlePhoneRequest(w http.ResponseWriter, r *http.Request) {
	var req phoneRequestBody
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Phone == "" || len(req.Phone) > maxPhoneLen {
		writeError(w, http.StatusBadRequest, "invalid phone")
		return
	}
	if err := h.phone.RequestCode(r.Context(), req.Phone); err != nil {
		if errors.Is(err, errBadPhone) {
			writeError(w, http.StatusBadRequest, "invalid phone")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not send code")
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) handlePhoneVerify(w http.ResponseWriter, r *http.Request) {
	var req phoneVerifyBody
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Phone == "" || len(req.Phone) > maxPhoneLen || req.Code == "" || len(req.Code) > 16 {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	// Optional auth: a valid bearer means "bind this phone to my account"
	// (upgrade). A present-but-invalid bearer is rejected; absent is anonymous
	// login.
	currentUserID := ""
	if raw, ok := bearerToken(r); ok {
		claims, err := h.validator.Validate(r.Context(), raw)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		currentUserID = claims.Subject
	}

	sess, err := h.phone.VerifyCode(r.Context(), req.Phone, req.Code, currentUserID)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidCode):
			writeError(w, http.StatusUnauthorized, "invalid or expired code")
		case errors.Is(err, ErrPhoneConflict):
			writeError(w, http.StatusConflict, "phone already in use")
		default:
			writeSessionError(w, err)
		}
		return
	}
	h.recordLogin(r.Context(), sess.AccessClaims.Subject, "phone")
	writeSession(w, sess)
}
