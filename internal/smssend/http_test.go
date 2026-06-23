package smssend

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestGeneric_PostsJSONWithFieldsAndHeaders(t *testing.T) {
	var gotAuth, gotTo, gotMsg, gotFrom string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		var m map[string]string
		json.NewDecoder(r.Body).Decode(&m)
		gotTo, gotMsg, gotFrom = m["to"], m["message"], m["from"]
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s, err := NewGeneric(GenericConfig{
		URL:     srv.URL,
		Headers: map[string]string{"Authorization": "Bearer secret"},
		Fields:  map[string]string{"from": "laplat"},
	}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SendLoginCode(context.Background(), "+84901234567", "123456"); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer secret" || gotTo != "+84901234567" || gotFrom != "laplat" {
		t.Fatalf("auth=%q to=%q from=%q", gotAuth, gotTo, gotFrom)
	}
	if !strings.Contains(gotMsg, "123456") {
		t.Fatalf("message missing code: %q", gotMsg)
	}
}

func TestGeneric_FormEncodingAndCustomFields(t *testing.T) {
	var form url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		form = r.PostForm
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	s, _ := NewGeneric(GenericConfig{
		URL: srv.URL, Encoding: "form", ToField: "msisdn", MessageField: "text",
	}, srv.Client())
	if err := s.SendLoginCode(context.Background(), "+84901234567", "654321"); err != nil {
		t.Fatal(err)
	}
	if form.Get("msisdn") != "+84901234567" || !strings.Contains(form.Get("text"), "654321") {
		t.Fatalf("form = %v", form)
	}
}

func TestGeneric_Non2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	s, _ := NewGeneric(GenericConfig{URL: srv.URL}, srv.Client())
	if err := s.SendLoginCode(context.Background(), "+84901234567", "123456"); err == nil {
		t.Fatal("expected error on non-2xx")
	}
}

func TestNewGeneric_RequiresURL(t *testing.T) {
	if _, err := NewGeneric(GenericConfig{}, nil); err == nil {
		t.Fatal("expected error when URL is empty")
	}
}

func TestTwilio_BasicAuthFormPost(t *testing.T) {
	var user, pass, to, from, body string
	var okBasic bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, okBasic = r.BasicAuth()
		r.ParseForm()
		to, from, body = r.PostForm.Get("To"), r.PostForm.Get("From"), r.PostForm.Get("Body")
		// Path must include the account sid.
		if !strings.Contains(r.URL.Path, "/Accounts/AC123/Messages.json") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	tw, err := NewTwilio(TwilioConfig{AccountSID: "AC123", AuthToken: "tok", From: "+15550000000"}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	tw.baseURL = srv.URL // redirect to the test server

	if err := tw.SendLoginCode(context.Background(), "+84901234567", "246810"); err != nil {
		t.Fatal(err)
	}
	if !okBasic || user != "AC123" || pass != "tok" {
		t.Fatalf("basic auth = (%q,%q,%v)", user, pass, okBasic)
	}
	if to != "+84901234567" || from != "+15550000000" || !strings.Contains(body, "246810") {
		t.Fatalf("to=%q from=%q body=%q", to, from, body)
	}
}

func TestVonage_ParsesPerMessageStatus(t *testing.T) {
	// status "0" => success.
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.PostForm.Get("to") != "84901234567" { // '+' stripped
			t.Errorf("to = %q, want no leading +", r.PostForm.Get("to"))
		}
		io.WriteString(w, `{"messages":[{"status":"0"}]}`)
	}))
	defer ok.Close()
	v, _ := NewVonage(VonageConfig{APIKey: "k", APISecret: "s", From: "laplat"}, ok.Client())
	v.endpoint = ok.URL
	if err := v.SendLoginCode(context.Background(), "+84901234567", "111222"); err != nil {
		t.Fatalf("status 0 should succeed: %v", err)
	}

	// Non-zero status => error, even though HTTP is 200.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"messages":[{"status":"4","error-text":"bad credentials"}]}`)
	}))
	defer bad.Close()
	v2, _ := NewVonage(VonageConfig{APIKey: "k", APISecret: "s", From: "laplat"}, bad.Client())
	v2.endpoint = bad.URL
	if err := v2.SendLoginCode(context.Background(), "+84901234567", "111222"); err == nil {
		t.Fatal("non-zero vonage status should be an error")
	}
}
