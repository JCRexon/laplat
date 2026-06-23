package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"net/http"
)

// OIDC CSRF/replay cookies. Short-lived, scoped to the callback path.
const (
	stateCookie = "laplat_oidc_state"
	nonceCookie = "laplat_oidc_nonce"
	oidcPath    = "/v1/auth/oidc"
)

// RegisterOIDC mounts the federated-login routes on the handler. Call it after
// NewHandler when OIDC is configured; without it, those routes simply 404.
func (h *Handler) RegisterOIDC(fed *Federation) {
	h.oidc = fed
	h.mux.HandleFunc("GET /v1/auth/oidc/{provider}/start", h.handleOIDCStart)
	h.mux.HandleFunc("GET /v1/auth/oidc/{provider}/callback", h.handleOIDCCallback)
}

func (h *Handler) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	state, nonce := randToken(), randToken()
	authURL, err := h.oidc.AuthorizeURL(provider, state, nonce)
	if err != nil {
		writeError(w, http.StatusNotFound, "unknown provider")
		return
	}
	setOIDCCookie(w, stateCookie, state)
	setOIDCCookie(w, nonceCookie, nonce)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (h *Handler) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	code := r.URL.Query().Get("code")
	qState := r.URL.Query().Get("state")
	cState, _ := r.Cookie(stateCookie)
	cNonce, _ := r.Cookie(nonceCookie)

	// CSRF: the callback state must match the cookie set at start (constant-time).
	if code == "" || qState == "" || cState == nil ||
		subtle.ConstantTimeCompare([]byte(qState), []byte(cState.Value)) != 1 {
		writeError(w, http.StatusUnauthorized, "invalid oauth state")
		return
	}
	nonce := ""
	if cNonce != nil {
		nonce = cNonce.Value
	}

	// One-shot cookies: clear regardless of outcome.
	clearOIDCCookie(w, stateCookie)
	clearOIDCCookie(w, nonceCookie)

	sess, err := h.oidc.Complete(r.Context(), provider, code, nonce)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	writeSession(w, sess)
}

func setOIDCCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     oidcPath,
		MaxAge:   600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearOIDCCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: oidcPath, MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
}

// randToken is a 128-bit URL-safe random value for state/nonce.
func randToken() string {
	var b [16]byte
	mustRand(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
