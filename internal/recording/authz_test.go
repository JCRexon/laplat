package recording

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/jcrexon/laplat/internal/entitlement"
	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/pkg/contracts"
)

// fakeGate is a stub EntitlementGate returning a canned decision.
type fakeGate struct{ err error }

func (g fakeGate) EnsureRecordingAccess(context.Context, string, string) error { return g.err }

func newAuthzHandler(t *testing.T, gate EntitlementGate, now time.Time) (*Handler, *fakeRepo) {
	t.Helper()
	repo := newFakeRepo()
	repo.recs["REC1"] = &store.Recording{
		ID: "REC1", SessionID: "S1", Status: StatusCompleted, OutputURI: "/out/room.mp4",
	}
	h := &Handler{
		svc:              newSvc(t, repo, &fakeEgress{}),
		entitlements:     gate,
		recordingsSecret: "secret",
		filePrefix:       "/out/",
		playbackTTL:      5 * time.Minute,
		now:              func() time.Time { return now },
		playedSeen:       map[string]time.Time{},
		log:              slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	return h, repo
}

// doAuthz mimics nginx's auth_request: the original request URI (path + ?t=token)
// is forwarded in X-Original-URI.
func doAuthz(h *Handler, token, path string) int {
	r := httptest.NewRequest(http.MethodGet, "/v1/recordings/authz", nil)
	r.Header.Set("X-Original-URI", path+"?t="+url.QueryEscape(token))
	w := httptest.NewRecorder()
	h.authz(w, r)
	return w.Code
}

func TestAuthz(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	mint := func(sub, rec string, exp time.Time) string { return mintPlaybackToken("secret", sub, rec, exp) }

	t.Run("valid allows, and audits once across range requests", func(t *testing.T) {
		h, repo := newAuthzHandler(t, fakeGate{}, now)
		tok := mint("viewer", "REC1", now.Add(time.Minute))
		if code := doAuthz(h, tok, "/room.mp4"); code != http.StatusNoContent {
			t.Fatalf("first request code=%d, want 204", code)
		}
		// A second (e.g. range) request with the same token must not re-audit.
		if code := doAuthz(h, tok, "/room.mp4"); code != http.StatusNoContent {
			t.Fatalf("second request code=%d, want 204", code)
		}
		if len(repo.audits) != 1 {
			t.Fatalf("recording.played entries = %d, want 1 (deduped)", len(repo.audits))
		}
		a := repo.audits[0]
		if a.ActorID != "viewer" || a.Action != contracts.ActionRecordingPlayed || a.TargetID != "REC1" {
			t.Fatalf("unexpected audit entry: %+v", a)
		}
	})

	t.Run("expired token -> 401", func(t *testing.T) {
		h, _ := newAuthzHandler(t, fakeGate{}, now)
		tok := mint("viewer", "REC1", now.Add(-time.Second))
		if code := doAuthz(h, tok, "/room.mp4"); code != http.StatusUnauthorized {
			t.Fatalf("code=%d, want 401", code)
		}
	})

	t.Run("token for a different file -> 403", func(t *testing.T) {
		h, _ := newAuthzHandler(t, fakeGate{}, now)
		tok := mint("viewer", "REC1", now.Add(time.Minute))
		if code := doAuthz(h, tok, "/someone-elses.mp4"); code != http.StatusForbidden {
			t.Fatalf("code=%d, want 403", code)
		}
	})

	t.Run("unentitled -> 403 and not audited", func(t *testing.T) {
		h, repo := newAuthzHandler(t, fakeGate{err: entitlement.ErrPaymentRequired}, now)
		tok := mint("viewer", "REC1", now.Add(time.Minute))
		if code := doAuthz(h, tok, "/room.mp4"); code != http.StatusForbidden {
			t.Fatalf("code=%d, want 403", code)
		}
		if len(repo.audits) != 0 {
			t.Fatal("a denied fetch must not be recorded as played")
		}
	})

	t.Run("unknown recording -> 403", func(t *testing.T) {
		h, _ := newAuthzHandler(t, fakeGate{}, now)
		tok := mint("viewer", "GHOST", now.Add(time.Minute))
		if code := doAuthz(h, tok, "/room.mp4"); code != http.StatusForbidden {
			t.Fatalf("code=%d, want 403", code)
		}
	})

	t.Run("missing params -> 401", func(t *testing.T) {
		h, _ := newAuthzHandler(t, fakeGate{}, now)
		if code := doAuthz(h, "", "/room.mp4"); code != http.StatusUnauthorized {
			t.Fatalf("code=%d, want 401", code)
		}
	})
}
