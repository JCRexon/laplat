package recording

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jcrexon/laplat/internal/livekit"
	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/pkg/contracts"
	"github.com/jcrexon/laplat/pkg/token"
)

// Handler is the recording control HTTP surface. It self-authenticates via the
// access-token validator; the service enforces host-only control.
type Handler struct {
	svc              *Service
	validator        *token.Validator
	apiKey           string // LiveKit API key for webhook issuer check
	apiSecret        string // LiveKit API secret for webhook verification
	recordingsBase   string // public base URL for playback links (optional)
	filePrefix       string // file prefix to strip when building playback URLs
	recordingsSecret string // HMAC-MD5 key for nginx secure_link signing (optional)
	log              *slog.Logger
	mux              *http.ServeMux
}

// NewHandler wires the service, validator, and LiveKit credentials, then
// registers routes under /v1/recordings/ and /v1/webhooks/.
//
// recordingsBase (e.g. "http://localhost:9090") and filePrefix (e.g. "/out/")
// are used together to build playbackUrl values in the playback endpoint.
// Both are optional: when recordingsBase is empty no playbackUrl is produced.
// recordingsSecret is the HMAC-MD5 key shared with nginx's secure_link module;
// when non-empty, playbackUrls carry a signed expiry (see buildPlaybackURL).
func NewHandler(svc *Service, validator *token.Validator, apiKey, apiSecret, recordingsBase, filePrefix, recordingsSecret string, log *slog.Logger) *Handler {
	h := &Handler{
		svc: svc, validator: validator, apiKey: apiKey, apiSecret: apiSecret,
		recordingsBase: recordingsBase, filePrefix: filePrefix,
		recordingsSecret: recordingsSecret, log: log,
		mux: http.NewServeMux(),
	}
	// Host-only recording controls.
	h.mux.Handle("POST /v1/recordings/sessions/{sessionID}", h.auth(h.start))
	h.mux.Handle("DELETE /v1/recordings/sessions/{sessionID}", h.auth(h.stop))
	h.mux.Handle("GET /v1/recordings/sessions/{sessionID}", h.auth(h.list))
	// Playback: completed recordings for a session, accessible at the none tier.
	h.mux.Handle("GET /v1/recordings/sessions/{sessionID}/playback", h.auth(h.playback))
	// Webhook ingest: verified by LiveKit JWT, not by our access token.
	h.mux.HandleFunc("POST /v1/webhooks/livekit", h.liveKitWebhook)
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

// start begins recording the session (host only, consent gate enforced).
func (h *Handler) start(w http.ResponseWriter, r *http.Request, claims *contracts.AccessTokenClaims) {
	rec, err := h.svc.Start(r.Context(), claims, r.PathValue("sessionID"))
	if err != nil {
		writeServiceErr(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, recordingJSON(rec))
}

// stop stops the session's in-flight recording (host only).
func (h *Handler) stop(w http.ResponseWriter, r *http.Request, claims *contracts.AccessTokenClaims) {
	if err := h.svc.Stop(r.Context(), claims, r.PathValue("sessionID")); err != nil {
		writeServiceErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// list returns a session's recordings (host only).
func (h *Handler) list(w http.ResponseWriter, r *http.Request, claims *contracts.AccessTokenClaims) {
	recs, err := h.svc.List(r.Context(), claims, r.PathValue("sessionID"))
	if err != nil {
		writeServiceErr(w, err)
		return
	}
	out := make([]map[string]any, 0, len(recs))
	for _, rec := range recs {
		out = append(out, recordingJSON(rec))
	}
	writeJSON(w, http.StatusOK, map[string]any{"recordings": out})
}

// playback returns completed recordings for a session. Any authenticated user
// may call this (free-recording floor per ACCESS-MODEL.md).
func (h *Handler) playback(w http.ResponseWriter, r *http.Request, _ *contracts.AccessTokenClaims) {
	recs, err := h.svc.ListCompleted(r.Context(), r.PathValue("sessionID"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	out := make([]map[string]any, 0, len(recs))
	for _, rec := range recs {
		m := recordingJSON(rec)
		if u := h.buildPlaybackURL(rec.OutputURI); u != "" {
			m["playbackUrl"] = u
		}
		out = append(out, m)
	}
	writeJSON(w, http.StatusOK, map[string]any{"recordings": out})
}

// buildPlaybackURL converts an outputUri (e.g. "/out/room.mp4") to a public
// playback URL (e.g. "http://localhost:9090/room.mp4") by stripping filePrefix
// and prepending recordingsBase. Returns "" when recordingsBase is unset.
//
// When recordingsSecret is set, the URL is signed for nginx's secure_link
// module: ?md5=HASH&expires=UNIX is appended, where HASH is the base64url
// MD5 of "$expires$path $secret" (the format secure_link_md5 expects).
// nginx validates the signature in-process — no subrequest on every range
// request, which matters for video scrubbing.
func (h *Handler) buildPlaybackURL(outputURI string) string {
	if h.recordingsBase == "" || outputURI == "" {
		return ""
	}
	rel := strings.TrimPrefix(outputURI, h.filePrefix)
	if !strings.HasPrefix(rel, "/") {
		rel = "/" + rel
	}
	// Reject paths that traverse above the served directory.
	if strings.Contains(rel, "..") {
		return ""
	}
	base := h.recordingsBase + rel
	if h.recordingsSecret == "" {
		return base
	}
	expiry := time.Now().Add(time.Hour).Unix()
	sum := md5.Sum([]byte(fmt.Sprintf("%d%s %s", expiry, rel, h.recordingsSecret)))
	token := base64.RawURLEncoding.EncodeToString(sum[:])
	return fmt.Sprintf("%s?md5=%s&expires=%d", base, token, expiry)
}

// liveKitWebhook receives egress lifecycle events from the LiveKit server. The
// request is verified via the LiveKit JWT in the Authorization header; our
// access-token validator is not involved (LiveKit is a trusted server peer).
func (h *Handler) liveKitWebhook(w http.ResponseWriter, r *http.Request) {
	ev, err := livekit.ParseWebhook(r, h.apiKey, h.apiSecret)
	if err != nil {
		h.log.Warn("livekit webhook rejected", "err", err)
		writeErr(w, http.StatusUnauthorized, "webhook verification failed")
		return
	}
	if err := h.svc.HandleWebhookEvent(r.Context(), ev); err != nil {
		h.log.Error("livekit webhook: applying event failed", "event", ev.Event, "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func recordingJSON(r store.Recording) map[string]any {
	m := map[string]any{
		"id":        r.ID,
		"sessionId": r.SessionID,
		"status":    r.Status,
		"startedAt": r.StartedAt.Unix(),
	}
	if r.OutputURI != "" {
		m["outputUri"] = r.OutputURI
	}
	if r.EndedAt != nil {
		m["endedAt"] = r.EndedAt.Unix()
	}
	return m
}

func writeServiceErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrForbidden):
		writeErr(w, http.StatusForbidden, "host only")
	case errors.Is(err, ErrNotFound):
		writeErr(w, http.StatusNotFound, "session not found")
	case errors.Is(err, ErrSessionEnded):
		writeErr(w, http.StatusConflict, "session already ended")
	case errors.Is(err, ErrConsentRequired):
		writeErr(w, http.StatusForbidden, "not all present participants have consented")
	case errors.Is(err, ErrAlreadyRecording):
		writeErr(w, http.StatusConflict, "already recording")
	case errors.Is(err, ErrNotRecording):
		writeErr(w, http.StatusConflict, "no recording in flight")
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

func writeErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"` + msg + `"}`))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
