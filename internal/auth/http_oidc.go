package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
)

// Federated-login CSRF/binding cookies. Short-lived, scoped to the callback path.
const (
	stateCookie  = "laplat_oidc_state"
	secretCookie = "laplat_oidc_secret" // holds the nonce (OIDC) or code_verifier (PKCE)
	oidcPath     = "/v1/auth/oidc"
)

// RegisterOIDC mounts the federated-login routes on the handler (Google/Apple
// via OIDC, Zalo via OAuth2+PKCE). Call it after NewHandler when federation is
// configured; without it, those routes simply 404.
func (h *Handler) RegisterOIDC(fed *Federation) {
	h.oidc = fed
	h.mux.HandleFunc("GET /v1/auth/oidc/{provider}/start", h.handleOIDCStart)
	h.mux.HandleFunc("GET /v1/auth/oidc/{provider}/callback", h.handleOIDCCallback)
}

func (h *Handler) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	binding, ok := h.oidc.Binding(provider)
	if !ok {
		writeError(w, http.StatusNotFound, "unknown provider")
		return
	}

	// One high-entropy secret per login. For OIDC it is the nonce sent verbatim
	// and echoed in the id_token; for PKCE it is the code_verifier and the
	// provider receives only its S256 hash. The secret stays in a cookie.
	state := randToken()
	secret := randSecret()
	challenge := secret
	if binding == BindingPKCE {
		challenge = pkceChallenge(secret)
	}

	authURL, err := h.oidc.Authorize(provider, state, challenge)
	if err != nil {
		writeError(w, http.StatusNotFound, "unknown provider")
		return
	}
	setOIDCCookie(w, stateCookie, state)
	setOIDCCookie(w, secretCookie, secret)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (h *Handler) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	code := r.URL.Query().Get("code")
	qState := r.URL.Query().Get("state")
	cState, _ := r.Cookie(stateCookie)
	cSecret, _ := r.Cookie(secretCookie)

	// CSRF: the callback state must match the cookie set at start (constant-time).
	if code == "" || qState == "" || cState == nil ||
		subtle.ConstantTimeCompare([]byte(qState), []byte(cState.Value)) != 1 {
		writeError(w, http.StatusUnauthorized, "invalid oauth state")
		return
	}
	// The binding secret (nonce / code_verifier) ties this login to the returned
	// token. Mandatory: a missing cookie must not silently skip the binding,
	// since the caller controls which cookies it presents.
	if cSecret == nil || cSecret.Value == "" {
		writeError(w, http.StatusUnauthorized, "missing oauth binding")
		return
	}
	secret := cSecret.Value

	// One-shot cookies: clear regardless of outcome.
	clearOIDCCookie(w, stateCookie)
	clearOIDCCookie(w, secretCookie)

	sess, err := h.oidc.Complete(r.Context(), provider, code, secret)
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

// randToken is a 128-bit URL-safe random value for state.
func randToken() string {
	var b [16]byte
	mustRand(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// randSecret is a 256-bit URL-safe random value: a 43-char string, valid both as
// an OIDC nonce and as a PKCE code_verifier (RFC 7636 requires 43–128 chars of
// the unreserved set, which base64url satisfies).
func randSecret() string {
	var b [32]byte
	mustRand(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// pkceChallenge derives the S256 code_challenge from a code_verifier.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
