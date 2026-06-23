package oidc

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RemoteKeySet fetches a provider's JWKS over HTTPS and caches it, implementing
// KeySet for production use (Google/Apple rotate signing keys). The cache TTL
// follows the response's Cache-Control max-age, bounded to a sane range; an
// unknown kid triggers at most one refetch per minRefresh window (key rotation
// publishes a new kid), and a fetch failure serves the last good keys if any.
type RemoteKeySet struct {
	url        string
	client     *http.Client
	minRefresh time.Duration

	mu        sync.Mutex
	keys      *StaticKeySet
	expiry    time.Time
	lastFetch time.Time
}

const (
	defaultJWKSTTL = time.Hour
	minJWKSTTL     = 5 * time.Minute
	maxJWKSTTL     = 24 * time.Hour
	jwksBodyLimit  = 1 << 20 // 1 MiB
)

// NewRemoteKeySet returns a KeySet backed by the given JWKS URL. A nil client
// gets a default with a 10s timeout.
func NewRemoteKeySet(jwksURL string, client *http.Client) *RemoteKeySet {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &RemoteKeySet{url: jwksURL, client: client, minRefresh: time.Minute}
}

// VerificationKey implements KeySet, fetching/refreshing the JWKS as needed.
func (r *RemoteKeySet) VerificationKey(ctx context.Context, kid string) (crypto.PublicKey, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	if r.keys != nil && now.Before(r.expiry) {
		if key, alg, err := r.keys.VerificationKey(ctx, kid); err == nil {
			return key, alg, nil
		}
		// Fresh cache without this kid: only refetch if we haven't recently, so a
		// barrage of tokens with a bogus kid can't hammer the JWKS endpoint.
		if now.Sub(r.lastFetch) < r.minRefresh {
			return nil, "", ErrUnknownKey
		}
	}

	if err := r.refresh(ctx, now); err != nil {
		if r.keys != nil { // serve stale rather than fail the login outright
			return r.keys.VerificationKey(ctx, kid)
		}
		return nil, "", err
	}
	return r.keys.VerificationKey(ctx, kid)
}

func (r *RemoteKeySet) refresh(ctx context.Context, now time.Time) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("oidc: fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oidc: fetch jwks: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, jwksBodyLimit))
	if err != nil {
		return fmt.Errorf("oidc: read jwks: %w", err)
	}
	ks, err := ParseJWKS(body)
	if err != nil {
		return err
	}
	r.keys = ks
	r.lastFetch = now
	r.expiry = now.Add(cacheTTL(resp.Header.Get("Cache-Control")))
	return nil
}

// cacheTTL extracts max-age from a Cache-Control header, clamped to
// [minJWKSTTL, maxJWKSTTL]; absent/unparseable falls back to the default.
func cacheTTL(cacheControl string) time.Duration {
	for _, part := range strings.Split(cacheControl, ",") {
		part = strings.TrimSpace(part)
		if v, ok := strings.CutPrefix(part, "max-age="); ok {
			if secs, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && secs > 0 {
				ttl := time.Duration(secs) * time.Second
				if ttl < minJWKSTTL {
					return minJWKSTTL
				}
				if ttl > maxJWKSTTL {
					return maxJWKSTTL
				}
				return ttl
			}
		}
	}
	return defaultJWKSTTL
}
