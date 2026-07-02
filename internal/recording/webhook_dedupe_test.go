package recording

import (
	"testing"
	"time"
)

// The webhook replay dedupe remembers a key for its TTL and forgets it after.
func TestWebhookDedupe(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	now := base
	h := &Handler{seenWebhook: map[string]time.Time{}, now: func() time.Time { return now }}

	if h.webhookDuplicate("k1") {
		t.Fatal("first sight of k1 must not be a duplicate")
	}
	h.rememberWebhook("k1")
	if !h.webhookDuplicate("k1") {
		t.Fatal("k1 within the TTL must be a duplicate")
	}
	if h.webhookDuplicate("k2") {
		t.Fatal("an unseen key must not be a duplicate")
	}

	// An empty key (no jti/hash) can't be identified, so it never dedupes.
	if h.webhookDuplicate("") {
		t.Fatal("empty key must never dedupe")
	}
	h.rememberWebhook("") // no-op
	if h.webhookDuplicate("") {
		t.Fatal("empty key still must not dedupe after a no-op remember")
	}

	// Past the TTL the key is forgotten (and evicted).
	now = base.Add(webhookDedupeTTL + time.Second)
	if h.webhookDuplicate("k1") {
		t.Fatal("k1 past its TTL must no longer be a duplicate")
	}
}
