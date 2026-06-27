package auth

import (
	"errors"
	"net/http"
)

// stepUpHeader carries the raw step-up grant token from the BFF to the protected
// export endpoint. The BFF holds the token in a short-lived httpOnly cookie and
// forwards it here; it is never exposed to browser JavaScript.
const stepUpHeader = "X-StepUp-Token"

// RegisterStepUp mounts the step-up (re-authentication) routes and the protected
// data export. Call it after NewHandler once a StepUp service is built. Requires
// RegisterProfile too (the export reuses the profile reads); without a sender the
// request endpoint returns 409.
func (h *Handler) RegisterStepUp(su *StepUp) {
	h.stepup = su
	h.mux.Handle("POST /v1/me/stepup/request", h.requireAuth(http.HandlerFunc(h.handleStepUpRequest)))
	h.mux.Handle("POST /v1/me/stepup/verify", h.requireAuth(http.HandlerFunc(h.handleStepUpVerify)))
	h.mux.Handle("GET /v1/me/data-export", h.requireAuth(http.HandlerFunc(h.handleDataExport)))
}

func (h *Handler) handleStepUpRequest(w http.ResponseWriter, r *http.Request) {
	if h.stepup == nil {
		writeError(w, http.StatusNotImplemented, "not configured")
		return
	}
	claims, _ := ClaimsFrom(r.Context())
	res, err := h.stepup.RequestCode(r.Context(), claims.Subject)
	if err != nil {
		if errors.Is(err, ErrStepUpUnavailable) {
			writeError(w, http.StatusConflict, "no phone or email on file to verify against")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not send code")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"channel": res.Channel, "hint": res.Hint})
}

type stepUpVerifyBody struct {
	Code string `json:"code"`
}

func (h *Handler) handleStepUpVerify(w http.ResponseWriter, r *http.Request) {
	if h.stepup == nil {
		writeError(w, http.StatusNotImplemented, "not configured")
		return
	}
	var req stepUpVerifyBody
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Code == "" || len(req.Code) > 16 {
		writeError(w, http.StatusBadRequest, "invalid code")
		return
	}
	claims, _ := ClaimsFrom(r.Context())
	token, expiresAt, err := h.stepup.Verify(r.Context(), claims.Subject, req.Code)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidCode):
			writeError(w, http.StatusUnauthorized, "invalid or expired code")
		case errors.Is(err, ErrStepUpUnavailable):
			writeError(w, http.StatusConflict, "no phone or email on file to verify against")
		default:
			writeError(w, http.StatusInternalServerError, "could not verify code")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token":     token,
		"expiresAt": expiresAt.Unix(),
	})
}

func (h *Handler) handleDataExport(w http.ResponseWriter, r *http.Request) {
	if h.stepup == nil {
		writeError(w, http.StatusNotImplemented, "not configured")
		return
	}
	claims, _ := ClaimsFrom(r.Context())

	valid, err := h.stepup.ValidGrant(r.Context(), claims.Subject, r.Header.Get(stepUpHeader))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not verify step-up")
		return
	}
	if !valid {
		// 403 (not 401): the access token is fine, but this surface needs a fresh
		// re-authentication the caller hasn't completed.
		writeError(w, http.StatusForbidden, "step-up required")
		return
	}

	export, err := h.stepup.Export(r.Context(), claims.Subject)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not assemble export")
		return
	}
	writeJSON(w, http.StatusOK, export)
}
