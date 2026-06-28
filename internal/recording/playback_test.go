package recording

import (
	"net/url"
	"strconv"
	"testing"
	"time"
)

// A minted playback URL's expiry honours the configured TTL (ADR-011: the leak
// window is short and configurable, not a hardcoded hour).
func TestBuildPlaybackURL_HonoursTTL(t *testing.T) {
	h := &Handler{
		recordingsBase:   "http://rec.example",
		filePrefix:       "/out/",
		recordingsSecret: "s3cr3t",
		playbackTTL:      2 * time.Minute,
	}
	lo := time.Now().Add(2 * time.Minute).Unix()
	raw := h.buildPlaybackURL("/out/room.mp4")
	hi := time.Now().Add(2 * time.Minute).Unix()

	if raw == "" {
		t.Fatal("expected a signed playback URL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("md5") == "" {
		t.Error("signed URL missing md5 token")
	}
	exp, err := strconv.ParseInt(u.Query().Get("expires"), 10, 64)
	if err != nil {
		t.Fatalf("bad expires param: %v", err)
	}
	if exp < lo || exp > hi {
		t.Fatalf("expiry %d not within [%d,%d] (now+TTL)", exp, lo, hi)
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
