package oidcprov

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// tokenServer returns an httptest server that records the posted form and
// replies with the given id_token.
func tokenServer(t *testing.T, idToken string, captured *url.Values) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		*captured = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"id_token": idToken})
	}))
}

func TestGoogleExchange_PostsCodeAndReturnsIDToken(t *testing.T) {
	var form url.Values
	srv := tokenServer(t, "the-id-token", &form)
	defer srv.Close()

	ex := NewGoogle("client-abc", "s3cret", srv.Client())
	ex.tokenURL = srv.URL // point at the test endpoint

	got, err := ex.Exchange(context.Background(), "auth-code", "https://app/cb")
	if err != nil {
		t.Fatal(err)
	}
	if got != "the-id-token" {
		t.Fatalf("id token = %q", got)
	}
	for k, want := range map[string]string{
		"grant_type":    "authorization_code",
		"code":          "auth-code",
		"client_id":     "client-abc",
		"client_secret": "s3cret",
		"redirect_uri":  "https://app/cb",
	} {
		if form.Get(k) != want {
			t.Errorf("form[%s] = %q, want %q", k, form.Get(k), want)
		}
	}
}

func TestExchange_NonOKStatusIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
	}))
	defer srv.Close()
	ex := NewGoogle("c", "s", srv.Client())
	ex.tokenURL = srv.URL
	if _, err := ex.Exchange(context.Background(), "x", "y"); err == nil {
		t.Fatal("expected error on non-200 token response")
	}
}

func TestAppleExchange_SignsValidClientSecretJWT(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	p8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	var form url.Values
	srv := tokenServer(t, "apple-id-token", &form)
	defer srv.Close()

	ex, err := NewApple(AppleConfig{
		ClientID: "com.laplat.app", TeamID: "TEAM123", KeyID: "KEY123", PrivateKey: p8,
	}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	ex.tokenURL = srv.URL

	if _, err := ex.Exchange(context.Background(), "code", "https://app/cb/apple"); err != nil {
		t.Fatal(err)
	}

	// The client_secret must be a well-formed, correctly-signed ES256 JWT.
	secret := form.Get("client_secret")
	parts := strings.Split(secret, ".")
	if len(parts) != 3 {
		t.Fatalf("client secret is not a JWT: %q", secret)
	}
	hdr, _ := b64.DecodeString(parts[0])
	var h map[string]string
	json.Unmarshal(hdr, &h)
	if h["alg"] != "ES256" || h["kid"] != "KEY123" {
		t.Fatalf("jwt header = %v", h)
	}
	body, _ := b64.DecodeString(parts[1])
	var claims map[string]any
	json.Unmarshal(body, &claims)
	if claims["iss"] != "TEAM123" || claims["sub"] != "com.laplat.app" || claims["aud"] != appleAudience {
		t.Fatalf("jwt claims = %v", claims)
	}
	// Verify the signature against the public key.
	sig, _ := b64.DecodeString(parts[2])
	if len(sig) != 64 {
		t.Fatalf("sig len = %d", len(sig))
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&key.PublicKey, digest[:], r, s) {
		t.Fatal("apple client-secret JWT signature did not verify")
	}
}
