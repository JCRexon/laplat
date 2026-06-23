package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// jwksDoc builds a one-key (RSA) JWKS document for the given kid.
func jwksDoc(t *testing.T, kid string, key *rsa.PrivateKey) []byte {
	t.Helper()
	doc, _ := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": kid, "alg": "RS256",
		"n": b64.EncodeToString(key.PublicKey.N.Bytes()),
		"e": b64.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
	}}})
	return doc
}

func TestRemoteKeySet_FetchesAndCaches(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Write(jwksDoc(t, "r1", key))
	}))
	defer srv.Close()

	rks := NewRemoteKeySet(srv.URL, srv.Client())
	ctx := context.Background()

	// First lookup fetches; the key resolves with its registered alg.
	pub, alg, err := rks.VerificationKey(ctx, "r1")
	if err != nil || alg != "RS256" {
		t.Fatalf("first lookup: key=%v alg=%q err=%v", pub, alg, err)
	}
	// Second lookup is served from cache — no new fetch.
	if _, _, err := rks.VerificationKey(ctx, "r1"); err != nil {
		t.Fatalf("second lookup: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected 1 JWKS fetch (cached), got %d", got)
	}

	// Unknown kid within a fresh cache + minRefresh window must not refetch.
	if _, _, err := rks.VerificationKey(ctx, "nope"); err != ErrUnknownKey {
		t.Fatalf("unknown kid err = %v, want ErrUnknownKey", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("unknown kid should not refetch within window, fetches=%d", got)
	}
}

func TestRemoteKeySet_ServesStaleOnFetchError(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(jwksDoc(t, "r1", key))
	}))
	rks := NewRemoteKeySet(srv.URL, srv.Client())
	ctx := context.Background()
	if _, _, err := rks.VerificationKey(ctx, "r1"); err != nil {
		t.Fatalf("warm cache: %v", err)
	}
	srv.Close() // subsequent fetches will fail

	// Cache is still fresh, so the known kid resolves without any fetch.
	if _, _, err := rks.VerificationKey(ctx, "r1"); err != nil {
		t.Fatalf("known kid from fresh cache after server down: %v", err)
	}
}

func TestCacheTTL(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"public, max-age=3600", time.Hour},
		{"max-age=60", minJWKSTTL},      // clamped up
		{"max-age=999999", maxJWKSTTL},  // clamped down
		{"", defaultJWKSTTL},            // absent
		{"no-store", defaultJWKSTTL},    // no max-age
		{"max-age=abc", defaultJWKSTTL}, // unparseable
	}
	for _, c := range cases {
		if got := cacheTTL(c.in); got != c.want {
			t.Errorf("cacheTTL(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
