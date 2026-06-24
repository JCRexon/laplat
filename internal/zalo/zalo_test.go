package zalo

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExchanger_PostsPKCEWithSecretHeader(t *testing.T) {
	var gotSecret, gotCode, gotVerifier, gotGrant, gotAppID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSecret = r.Header.Get("secret_key")
		r.ParseForm()
		gotCode = r.PostForm.Get("code")
		gotVerifier = r.PostForm.Get("code_verifier")
		gotGrant = r.PostForm.Get("grant_type")
		gotAppID = r.PostForm.Get("app_id")
		io.WriteString(w, `{"access_token":"AT-123"}`)
	}))
	defer srv.Close()

	ex, err := NewExchanger("app-1", "shh", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	ex.tokenURL = srv.URL

	at, err := ex.Exchange(context.Background(), "the-code", "https://app/cb", "verifier-xyz")
	if err != nil {
		t.Fatal(err)
	}
	if at != "AT-123" {
		t.Fatalf("access token = %q", at)
	}
	if gotSecret != "shh" || gotCode != "the-code" || gotVerifier != "verifier-xyz" ||
		gotGrant != "authorization_code" || gotAppID != "app-1" {
		t.Fatalf("secret=%q code=%q verifier=%q grant=%q app=%q", gotSecret, gotCode, gotVerifier, gotGrant, gotAppID)
	}
}

func TestExchanger_MissingTokenIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"error":-201,"message":"bad code"}`)
	}))
	defer srv.Close()
	ex, _ := NewExchanger("a", "s", srv.Client())
	ex.tokenURL = srv.URL
	if _, err := ex.Exchange(context.Background(), "x", "y", "z"); err == nil {
		t.Fatal("expected error when access_token is missing")
	}
}

func TestUserInfo_ReturnsID(t *testing.T) {
	var gotToken, gotFields string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("access_token")
		gotFields = r.URL.Query().Get("fields")
		io.WriteString(w, `{"id":"zalo-user-42","name":"Nguyen"}`)
	}))
	defer srv.Close()

	ui := NewUserInfo(srv.Client())
	ui.meURL = srv.URL

	sub, err := ui.Subject(context.Background(), "AT-123")
	if err != nil {
		t.Fatal(err)
	}
	if sub != "zalo-user-42" {
		t.Fatalf("subject = %q", sub)
	}
	if gotToken != "AT-123" || gotFields != "id" {
		t.Fatalf("token=%q fields=%q", gotToken, gotFields)
	}
}

func TestUserInfo_ErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"error":190,"message":"invalid token"}`)
	}))
	defer srv.Close()
	ui := NewUserInfo(srv.Client())
	ui.meURL = srv.URL
	if _, err := ui.Subject(context.Background(), "bad"); err == nil {
		t.Fatal("expected error on error response")
	}
}

func TestNewExchanger_Validation(t *testing.T) {
	if _, err := NewExchanger("", "s", nil); err == nil {
		t.Fatal("empty app id should error")
	}
}
