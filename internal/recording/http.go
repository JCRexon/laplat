package recording

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jcrexon/laplat/internal/entitlement"
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
	apiKey           string          // LiveKit API key for webhook issuer check
	apiSecret        string          // LiveKit API secret for webhook verification
	recordingsBase   string          // public base URL for playback links (optional)
	filePrefix       string          // file prefix to strip when building playback URLs
	recordingsSecret string          // HMAC-MD5 key for nginx secure_link signing (optional)
	playbackTTL      time.Duration   // validity window of a minted playback URL (ADR-011)
	entitlements     EntitlementGate // nil = free floor (any authed user)
	log              *slog.Logger
	mux              *http.ServeMux
	now              func() time.Time // injectable clock (token expiry / dedup)

	// playbackAudit dedups recording.played entries: the serving-authz check
	// fires per range request, but a view should audit once. Keyed by
	// subject|recordingID, guarded by playedMu.
	playedMu   sync.Mutex
	playedSeen map[string]time.Time

	// webhook replay dedupe (ADR-009 defence-in-depth): reject a redelivered
	// webhook outright, keyed by its DedupKey (jti/body-hash), within a TTL.
	// Process-local; the monotonic recording status is the authoritative guard.
	webhookMu   sync.Mutex
	seenWebhook map[string]time.Time
}

// webhookDedupeTTL bounds how long a delivered webhook key is remembered — long
// enough to cover the token's own validity window, after which ParseWebhook
// rejects a replay on expiry anyway.
const webhookDedupeTTL = 10 * time.Minute

// defaultPlaybackTTL bounds how long a signed playback URL stays valid — the
// leak window of the bearer-style URL until the auth_request identity binding
// lands (ADR-011). Kept short.
const defaultPlaybackTTL = 5 * time.Minute

// EntitlementGate gates recording playback by the entitlement of the session's
// class. *entitlement.Service satisfies it. Optional: when nil, playback stays on
// the free floor (any authenticated user, the pre-payments behaviour).
type EntitlementGate interface {
	EnsureRecordingAccess(ctx context.Context, subjectID, sessionID string) error
}

// Option configures a Handler.
type Option func(*Handler)

// WithEntitlements gates playback so paid-class recordings require ownership.
func WithEntitlements(g EntitlementGate) Option {
	return func(h *Handler) { h.entitlements = g }
}

// WithPlaybackTTL sets the validity window of minted playback URLs. A zero or
// negative value leaves the default (defaultPlaybackTTL).
func WithPlaybackTTL(d time.Duration) Option {
	return func(h *Handler) {
		if d > 0 {
			h.playbackTTL = d
		}
	}
}

// NewHandler wires the service, validator, and LiveKit credentials, then
// registers routes under /v1/recordings/ and /v1/webhooks/.
//
// recordingsBase (e.g. "http://localhost:9090") and filePrefix (e.g. "/out/")
// are used together to build playbackUrl values in the playback endpoint.
// Both are optional: when recordingsBase is empty no playbackUrl is produced.
// recordingsSecret is the HMAC-MD5 key shared with nginx's secure_link module;
// when non-empty, playbackUrls carry a signed expiry (see buildPlaybackURL).
func NewHandler(svc *Service, validator *token.Validator, apiKey, apiSecret, recordingsBase, filePrefix, recordingsSecret string, log *slog.Logger, opts ...Option) *Handler {
	h := &Handler{
		svc: svc, validator: validator, apiKey: apiKey, apiSecret: apiSecret,
		recordingsBase: recordingsBase, filePrefix: filePrefix,
		recordingsSecret: recordingsSecret, log: log,
		playbackTTL: defaultPlaybackTTL,
		mux:         http.NewServeMux(),
		now:         time.Now,
		playedSeen:  map[string]time.Time{},
		seenWebhook: map[string]time.Time{},
	}
	for _, opt := range opts {
		opt(h)
	}
	// Host-only recording controls.
	h.mux.Handle("POST /v1/recordings/sessions/{sessionID}", h.auth(h.start))
	h.mux.Handle("DELETE /v1/recordings/sessions/{sessionID}", h.auth(h.stop))
	h.mux.Handle("GET /v1/recordings/sessions/{sessionID}", h.auth(h.list))
	// Playback: completed recordings for a session (entitlement-gated).
	h.mux.Handle("GET /v1/recordings/sessions/{sessionID}/playback", h.auth(h.playback))
	// Serving-authz: nginx auth_request subrequest for a recording byte fetch.
	// Authenticated by the playback token in the URL, NOT the access token — the
	// browser fetches bytes cross-origin and carries no session cookie (ADR-011).
	h.mux.HandleFunc("GET /v1/recordings/authz", h.authz)
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

// playback returns completed recordings for a session. Free-class and direct
// sessions are on the free floor (any authenticated user); paid-class recordings
// require an active entitlement when the gate is wired.
func (h *Handler) playback(w http.ResponseWriter, r *http.Request, claims *contracts.AccessTokenClaims) {
	sessionID := r.PathValue("sessionID")
	if h.entitlements != nil {
		switch err := h.entitlements.EnsureRecordingAccess(r.Context(), claims.Subject, sessionID); {
		case err == nil:
			// access granted
		case errors.Is(err, entitlement.ErrPaymentRequired):
			writeErr(w, http.StatusPaymentRequired, "this recording requires purchase")
			return
		case errors.Is(err, entitlement.ErrSessionNotFound):
			writeErr(w, http.StatusNotFound, "session not found")
			return
		default:
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
	}
	recs, err := h.svc.ListCompleted(r.Context(), sessionID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	out := make([]map[string]any, 0, len(recs))
	for _, rec := range recs {
		m := recordingJSON(rec)
		if u := h.playbackURL(rec, claims.Subject); u != "" {
			m["playbackUrl"] = u
		}
		out = append(out, m)
	}
	writeJSON(w, http.StatusOK, map[string]any{"recordings": out})
}

// authz is nginx's auth_request subrequest: it decides whether a playback token
// may fetch a given recording file. It validates the token (signature + expiry),
// confirms the requested path is that recording's file, re-checks the viewer's
// entitlement live (so a mid-window revocation bites), and audits the access
// once per grant. 204 = allow, 401 = bad/expired token, 403 = wrong path or not
// entitled. Bytes are never proxied through authd.
func (h *Handler) authz(w http.ResponseWriter, r *http.Request) {
	// nginx forwards the ORIGINAL request line in X-Original-URI (its $request_uri);
	// the subrequest's own $uri/$arg_* do not reflect the parent, so we parse the
	// path and the playback token (?t=) out of this header.
	orig, err := url.ParseRequestURI(r.Header.Get("X-Original-URI"))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	path := orig.Path
	tok := orig.Query().Get("t")
	if tok == "" || path == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	subject, recID, err := parsePlaybackToken(tok, h.recordingsSecret, h.now())
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	rec, ok, err := h.svc.Recording(r.Context(), recID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// The token authorises one recording's file; the requested path must be it.
	if !ok || relPath(rec.OutputURI, h.filePrefix) != path {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	// Live entitlement re-check.
	if h.entitlements != nil {
		if err := h.entitlements.EnsureRecordingAccess(r.Context(), subject, rec.SessionID); err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
	}
	// Audit once per grant. Best-effort: a failed audit logs but does not block
	// playback (a read path should not hard-depend on the audit signer's liveness).
	if h.shouldAuditPlay(subject, recID) {
		if err := h.svc.AuditPlayback(r.Context(), subject, rec); err != nil {
			h.log.Error("recording.played audit failed", "err", err, "recording", recID)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// shouldAuditPlay reports whether a recording.played entry should be written for
// this (subject, recording) now — true at most once per playbackTTL window, so
// the per-range auth_request subrequests of one view collapse to a single audit.
func (h *Handler) shouldAuditPlay(subject, recID string) bool {
	key := subject + "|" + recID
	now := h.now()
	h.playedMu.Lock()
	defer h.playedMu.Unlock()
	if last, seen := h.playedSeen[key]; seen && now.Sub(last) < h.playbackTTL {
		return false
	}
	// Opportunistically evict stale entries so the map does not grow unbounded.
	for k, t := range h.playedSeen {
		if now.Sub(t) >= h.playbackTTL {
			delete(h.playedSeen, k)
		}
	}
	h.playedSeen[key] = now
	return true
}

// relPath maps a recording's outputURI to the path nginx serves it at (strip the
// egress file prefix, ensure a leading slash). Returns "" for a traversal path.
// playbackURL and the serving-authz check share it, so the URL that is minted and
// the path that is authorised agree exactly.
func relPath(outputURI, filePrefix string) string {
	rel := strings.TrimPrefix(outputURI, filePrefix)
	if !strings.HasPrefix(rel, "/") {
		rel = "/" + rel
	}
	if strings.Contains(rel, "..") {
		return ""
	}
	return rel
}

// playbackURL builds a public playback URL for rec, scoped to the viewer. Returns
// "" when no public base is configured. When recordingsSecret is set the URL
// carries a per-viewer, per-recording, short-lived token (ADR-011) that nginx
// forwards to the serving-authz check; without a secret the URL is unsigned
// (dev-only, with no nginx enforcement).
func (h *Handler) playbackURL(rec store.Recording, subject string) string {
	if h.recordingsBase == "" || rec.OutputURI == "" {
		return ""
	}
	rel := relPath(rec.OutputURI, h.filePrefix)
	if rel == "" {
		return ""
	}
	base := h.recordingsBase + rel
	if h.recordingsSecret == "" {
		return base
	}
	tok := mintPlaybackToken(h.recordingsSecret, subject, rec.ID, h.now().Add(h.playbackTTL))
	return base + "?t=" + tok
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
	// Replay dedupe (ADR-009 defence-in-depth): a redelivered webhook is ack'd
	// without reprocessing. The monotonic recording status is the authoritative
	// guard; this just avoids the redundant work.
	if h.webhookDuplicate(ev.DedupKey) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err := h.svc.HandleWebhookEvent(r.Context(), ev); err != nil {
		h.log.Error("livekit webhook: applying event failed", "event", ev.Event, "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	// Remember only after successful processing, so a failed delivery can be
	// retried (reprocessing is safe — the status transition is monotonic).
	h.rememberWebhook(ev.DedupKey)
	w.WriteHeader(http.StatusNoContent)
}

// webhookDuplicate reports whether a webhook with this key was already processed
// within the dedupe window (and opportunistically evicts stale keys). An empty
// key never dedupes (cannot identify the delivery).
func (h *Handler) webhookDuplicate(key string) bool {
	if key == "" {
		return false
	}
	now := h.now()
	h.webhookMu.Lock()
	defer h.webhookMu.Unlock()
	dup := false
	if t, ok := h.seenWebhook[key]; ok && now.Sub(t) < webhookDedupeTTL {
		dup = true
	}
	for k, t := range h.seenWebhook {
		if now.Sub(t) >= webhookDedupeTTL {
			delete(h.seenWebhook, k)
		}
	}
	return dup
}

// rememberWebhook records a successfully-processed webhook key.
func (h *Handler) rememberWebhook(key string) {
	if key == "" {
		return
	}
	h.webhookMu.Lock()
	defer h.webhookMu.Unlock()
	h.seenWebhook[key] = h.now()
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
	case errors.Is(err, ErrCapacity):
		w.Header().Set("Retry-After", "30")
		writeErr(w, http.StatusServiceUnavailable, "recording capacity reached, try again later")
	case errors.Is(err, ErrStartRateLimited):
		w.Header().Set("Retry-After", "60")
		writeErr(w, http.StatusTooManyRequests, "starting recordings too frequently, slow down")
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
