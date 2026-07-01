package httpx

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestRequestID_GeneratesAndPropagates(t *testing.T) {
	var seen string
	h := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = RequestIDFromContext(r.Context())
	}))

	// No inbound id -> one is generated and echoed.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if seen == "" || rec.Header().Get(RequestIDHeader) != seen {
		t.Fatalf("generated id missing/mismatched: ctx=%q header=%q", seen, rec.Header().Get(RequestIDHeader))
	}

	// Inbound id is honored.
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set(RequestIDHeader, "abc123")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if seen != "abc123" {
		t.Fatalf("inbound id not honored: %q", seen)
	}
}

func TestRecover_TurnsPanicInto500(t *testing.T) {
	h := Chain(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }),
		Recover(discardLogger()),
	)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestRateLimiter_AllowsBurstThenBlocks(t *testing.T) {
	rl := NewRateLimiter(1, 3) // 1 rps, burst 3
	frozen := time.Unix(0, 0)
	rl.now = func() time.Time { return frozen }

	for i := 0; i < 3; i++ {
		if !rl.Allow("1.2.3.4") {
			t.Fatalf("request %d should be allowed within burst", i)
		}
	}
	if rl.Allow("1.2.3.4") {
		t.Fatal("4th request should be blocked (burst exhausted)")
	}
	// A different key has its own bucket.
	if !rl.Allow("5.6.7.8") {
		t.Fatal("distinct key should be allowed")
	}
	// After 2s, ~2 tokens refill (capped at burst), so 2 more succeed.
	frozen = frozen.Add(2 * time.Second)
	if !rl.Allow("1.2.3.4") || !rl.Allow("1.2.3.4") {
		t.Fatal("tokens should have refilled after elapsed time")
	}
	if rl.Allow("1.2.3.4") {
		t.Fatal("refill should be capped — 3rd post-refill request blocked")
	}
}

func TestRateLimiter_Middleware429(t *testing.T) {
	rl := NewRateLimiter(1, 1)
	h := rl.Limit(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	call := func() int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "9.9.9.9:1234"
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := call(); got != http.StatusOK {
		t.Fatalf("first call = %d, want 200", got)
	}
	if got := call(); got != http.StatusTooManyRequests {
		t.Fatalf("second call = %d, want 429", got)
	}
}

func TestRateLimiter_LimitExcept(t *testing.T) {
	rl := NewRateLimiter(1, 1) // 1 token, refills slowly
	h := rl.LimitExcept(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), "/v1/recordings/authz", "/v1/webhooks/")

	call := func(path string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", path, nil)
		req.RemoteAddr = "9.9.9.9:1234" // one IP, as nginx/LiveKit would be
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	// Exempt server-to-server paths never throttle, even from one IP in a burst.
	for i := 0; i < 10; i++ {
		if got := call("/v1/recordings/authz"); got != http.StatusOK {
			t.Fatalf("exempt authz call %d = %d, want 200", i, got)
		}
	}
	for i := 0; i < 10; i++ {
		if got := call("/v1/webhooks/livekit"); got != http.StatusOK {
			t.Fatalf("exempt webhook call %d = %d, want 200", i, got)
		}
	}

	// A non-exempt path is still limited (burst 1, then 429).
	if got := call("/v1/classes"); got != http.StatusOK {
		t.Fatalf("first limited call = %d, want 200", got)
	}
	if got := call("/v1/classes"); got != http.StatusTooManyRequests {
		t.Fatalf("second limited call = %d, want 429", got)
	}
}

func TestClientIP_StripsPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.7:55555"
	if got := ClientIP(req); got != "203.0.113.7" {
		t.Fatalf("ClientIP = %q, want 203.0.113.7", got)
	}
}
