package recording

import (
	"testing"
	"time"
)

func TestPlaybackToken_RoundTrip(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tok := mintPlaybackToken("secret", "sub-1", "rec-1", now.Add(5*time.Minute))
	sub, rec, err := parsePlaybackToken(tok, "secret", now)
	if err != nil || sub != "sub-1" || rec != "rec-1" {
		t.Fatalf("round-trip: sub=%q rec=%q err=%v", sub, rec, err)
	}
}

func TestPlaybackToken_Rejections(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	valid := mintPlaybackToken("secret", "sub-1", "rec-1", now.Add(time.Minute))

	t.Run("expired", func(t *testing.T) {
		if _, _, err := parsePlaybackToken(valid, "secret", now.Add(2*time.Minute)); err == nil {
			t.Fatal("expired token must be rejected")
		}
	})
	t.Run("wrong secret", func(t *testing.T) {
		if _, _, err := parsePlaybackToken(valid, "other", now); err == nil {
			t.Fatal("wrong-key token must be rejected")
		}
	})
	t.Run("tampered payload", func(t *testing.T) {
		bad := "z" + valid[1:] // flip the first payload char; MAC no longer matches
		if _, _, err := parsePlaybackToken(bad, "secret", now); err == nil {
			t.Fatal("tampered token must be rejected")
		}
	})
	t.Run("malformed", func(t *testing.T) {
		for _, s := range []string{"", "no-dot", "a.b.c"} {
			if _, _, err := parsePlaybackToken(s, "secret", now); err == nil {
				t.Fatalf("malformed %q must be rejected", s)
			}
		}
	})
}
