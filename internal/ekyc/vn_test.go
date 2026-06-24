package ekyc

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeClient struct{ ref, url string }

func (f fakeClient) CreateVerification(_ context.Context, correlationID string) (string, string, error) {
	return f.ref, f.url + "?c=" + correlationID, nil
}

func sign(t *testing.T, secret string, body []byte) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func TestVN_BeginReturnsRedirect(t *testing.T) {
	v, err := NewVN(fakeClient{ref: "vref-1", url: "https://kyc.example/start"}, "secret")
	if err != nil {
		t.Fatal(err)
	}
	sr, err := v.Begin(context.Background(), "user-42")
	if err != nil {
		t.Fatal(err)
	}
	if sr.Provider != "vn-ekyc" || sr.Ref != "vref-1" || sr.RedirectURL == "" {
		t.Fatalf("start = %+v", sr)
	}
}

func TestVN_ParseCallback(t *testing.T) {
	v, _ := NewVN(fakeClient{}, "secret")

	approved, _ := json.Marshal(callback{CorrelationID: "user-42", Reference: "vref-1", Result: "approved", Over18: true})
	res, err := v.ParseCallback(approved, sign(t, "secret", approved))
	if err != nil {
		t.Fatalf("approved: %v", err)
	}
	if res.UserID != "user-42" || res.ProviderRef != "vref-1" || !res.Approved || !res.IsAdult {
		t.Fatalf("result = %+v", res)
	}

	// Underage approved: Approved true, IsAdult false (the service will refuse).
	under, _ := json.Marshal(callback{CorrelationID: "u2", Result: "approved", Over18: false})
	r2, _ := v.ParseCallback(under, sign(t, "secret", under))
	if !r2.Approved || r2.IsAdult {
		t.Fatalf("underage result = %+v", r2)
	}

	// Bad signature is rejected.
	if _, err := v.ParseCallback(approved, sign(t, "WRONG", approved)); err == nil {
		t.Fatal("expected signature mismatch error")
	}
	// Tampered body (valid-looking sig for different bytes) rejected.
	if _, err := v.ParseCallback([]byte(`{"correlationId":"x"}`), sign(t, "secret", approved)); err == nil {
		t.Fatal("expected tamper rejection")
	}
}

func TestHTTPClient_CreateVerification(t *testing.T) {
	var gotAuth, gotCorr string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		var in map[string]string
		json.NewDecoder(r.Body).Decode(&in)
		gotCorr = in["correlationId"]
		w.Write([]byte(`{"reference":"vref-9","redirectUrl":"https://kyc.example/s/9"}`))
	}))
	defer srv.Close()

	c, _ := NewHTTPClient(HTTPConfig{URL: srv.URL, Token: "tok"}, srv.Client())
	ref, redirect, err := c.CreateVerification(context.Background(), "user-7")
	if err != nil {
		t.Fatal(err)
	}
	if ref != "vref-9" || redirect == "" {
		t.Fatalf("ref=%q redirect=%q", ref, redirect)
	}
	if gotAuth != "Bearer tok" || gotCorr != "user-7" {
		t.Fatalf("auth=%q corr=%q", gotAuth, gotCorr)
	}
}

func TestNewVN_Validation(t *testing.T) {
	if _, err := NewVN(nil, "s"); err == nil {
		t.Fatal("nil client should error")
	}
	if _, err := NewVN(fakeClient{}, ""); err == nil {
		t.Fatal("empty secret should error")
	}
}
