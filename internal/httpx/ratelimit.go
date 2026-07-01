package httpx

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

// RateLimiter is an in-memory token-bucket limiter keyed by a string (typically
// client IP). It is process-local — adequate for single-instance abuse control
// and as a first line of defense; a shared/distributed limiter is a later
// concern. Buckets idle past idleTTL are swept to bound memory.
type RateLimiter struct {
	rate  float64 // tokens added per second
	burst float64 // bucket capacity

	mu      sync.Mutex
	buckets map[string]*bucket
	now     func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

const (
	idleTTL      = 10 * time.Minute
	sweepEvery   = 1024 // sweep when the map grows past this between cleanups
	maxRetainAge = idleTTL
)

// NewRateLimiter builds a limiter allowing `rps` requests/sec per key with a
// burst capacity. Non-positive values fall back to permissive defaults.
func NewRateLimiter(rps float64, burst int) *RateLimiter {
	if rps <= 0 {
		rps = 20
	}
	if burst <= 0 {
		burst = int(rps) * 2
	}
	return &RateLimiter{
		rate:    rps,
		burst:   float64(burst),
		buckets: make(map[string]*bucket),
		now:     time.Now,
	}
}

// Allow reports whether a request for key may proceed, consuming a token.
func (rl *RateLimiter) Allow(key string) bool {
	now := rl.now()
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if len(rl.buckets) > sweepEvery {
		rl.sweepLocked(now)
	}

	b, ok := rl.buckets[key]
	if !ok {
		// New keys start full, minus the token for this request.
		rl.buckets[key] = &bucket{tokens: rl.burst - 1, last: now}
		return true
	}
	// Refill based on elapsed time, capped at burst.
	elapsed := now.Sub(b.last).Seconds()
	b.tokens = min(rl.burst, b.tokens+elapsed*rl.rate)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

func (rl *RateLimiter) sweepLocked(now time.Time) {
	for k, b := range rl.buckets {
		if now.Sub(b.last) > maxRetainAge {
			delete(rl.buckets, k)
		}
	}
}

// Limit is middleware that rejects over-limit requests (keyed by client IP)
// with 429 and a Retry-After hint.
func (rl *RateLimiter) Limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.Allow(ClientIP(r)) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// LimitExcept is Limit, but requests whose path has one of exemptPrefixes skip
// the per-IP check. It exists for server-to-server endpoints (the nginx
// auth_request for recording playback, LiveKit webhooks) that all arrive from a
// single source IP and are authenticated by their own token/signature — a
// per-user IP limit would wrongly throttle them (e.g. one auth_request fires per
// video range fetch, so scrubbing a recording would exhaust the bucket).
func (rl *RateLimiter) LimitExcept(next http.Handler, exemptPrefixes ...string) http.Handler {
	limited := rl.Limit(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, p := range exemptPrefixes {
			if strings.HasPrefix(r.URL.Path, p) {
				next.ServeHTTP(w, r)
				return
			}
		}
		limited.ServeHTTP(w, r)
	})
}
