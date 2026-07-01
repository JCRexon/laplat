package recording

import (
	"net/url"
	"testing"
	"time"

	"github.com/jcrexon/laplat/internal/store"
)

// A minted playback URL carries a per-viewer, per-recording token whose expiry
// honours the configured TTL (ADR-011).
func TestPlaybackURL_TokenAndTTL(t *testing.T) {
	fixed := time.Unix(1_700_000_000, 0)
	h := &Handler{
		recordingsBase:   "http://rec.example",
		filePrefix:       "/out/",
		recordingsSecret: "s3cr3t",
		playbackTTL:      2 * time.Minute,
		now:              func() time.Time { return fixed },
	}
	rec := store.Recording{ID: "REC1", SessionID: "S1", OutputURI: "/out/room.mp4"}

	raw := h.playbackURL(rec, "viewer-1")
	if raw == "" {
		t.Fatal("expected a signed playback URL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if u.Path != "/room.mp4" {
		t.Errorf("path = %q, want /room.mp4", u.Path)
	}
	tok := u.Query().Get("t")
	if tok == "" {
		t.Fatal("URL missing playback token")
	}

	// The token round-trips to the viewer + recording and is valid at mint time.
	subject, recID, err := parsePlaybackToken(tok, "s3cr3t", fixed)
	if err != nil {
		t.Fatalf("token should verify: %v", err)
	}
	if subject != "viewer-1" || recID != "REC1" {
		t.Fatalf("token payload = (%q,%q), want (viewer-1, REC1)", subject, recID)
	}
	// It expires exactly playbackTTL later.
	if _, _, err := parsePlaybackToken(tok, "s3cr3t", fixed.Add(2*time.Minute+time.Second)); err == nil {
		t.Fatal("token past its TTL must be rejected")
	}
}

// WithPlaybackTTL applies a positive value and ignores a non-positive one (so
// the constructor default survives a 0).
func TestWithPlaybackTTL(t *testing.T) {
	h := &Handler{playbackTTL: defaultPlaybackTTL}
	WithPlaybackTTL(0)(h)
	if h.playbackTTL != defaultPlaybackTTL {
		t.Fatalf("zero TTL should be ignored, got %s", h.playbackTTL)
	}
	WithPlaybackTTL(90 * time.Second)(h)
	if h.playbackTTL != 90*time.Second {
		t.Fatalf("TTL = %s, want 90s", h.playbackTTL)
	}
}

// With no secret configured the URL is the dev fallback: unsigned, no token.
func TestPlaybackURL_NoSecretIsUnsigned(t *testing.T) {
	h := &Handler{recordingsBase: "http://rec.example", filePrefix: "/out/", now: time.Now}
	got := h.playbackURL(store.Recording{ID: "R", OutputURI: "/out/a.mp4"}, "v")
	if got != "http://rec.example/a.mp4" {
		t.Fatalf("unsigned URL = %q", got)
	}
}
