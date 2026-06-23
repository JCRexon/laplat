package smssend

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPSender_PostsJSONWithToken(t *testing.T) {
	var gotAuth, gotTo, gotMsg string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		var m map[string]string
		json.Unmarshal(body, &m)
		gotTo, gotMsg = m["to"], m["message"]
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s, err := New(Config{URL: srv.URL, Token: "secret"}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SendLoginCode(context.Background(), "+84901234567", "123456"); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer secret" {
		t.Fatalf("auth = %q", gotAuth)
	}
	if gotTo != "+84901234567" {
		t.Fatalf("to = %q", gotTo)
	}
	if !strings.Contains(gotMsg, "123456") {
		t.Fatalf("message missing code: %q", gotMsg)
	}
}

func TestHTTPSender_Non2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	s, _ := New(Config{URL: srv.URL}, srv.Client())
	if err := s.SendLoginCode(context.Background(), "+84901234567", "123456"); err == nil {
		t.Fatal("expected error on non-2xx gateway response")
	}
}

func TestNew_RequiresURL(t *testing.T) {
	if _, err := New(Config{}, nil); err == nil {
		t.Fatal("expected error when URL is empty")
	}
}
