package livekit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	testSecret = "testwebhooksecret"
	testAPIKey = "devkey"
)

// mintWebhookJWT builds a LiveKit-style webhook JWT signed with secret.
func mintWebhookJWT(t *testing.T, body []byte, apiKey, secret string) string {
	t.Helper()
	now := time.Now()
	sum := sha256.Sum256(body)
	claims := map[string]any{
		"iss":    apiKey,
		"sha256": hex.EncodeToString(sum[:]),
		"exp":    now.Add(60 * time.Second).Unix(),
		"nbf":    now.Unix(),
	}
	header, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	signingInput := b64.EncodeToString(header) + "." + b64.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	return signingInput + "." + b64.EncodeToString(mac.Sum(nil))
}

// mintWebhookJWTWithExp mints a JWT with a custom exp value for testing expiry.
func mintWebhookJWTWithExp(t *testing.T, body []byte, secret string, exp int64) string {
	t.Helper()
	sum := sha256.Sum256(body)
	claims := map[string]any{
		"iss":    testAPIKey,
		"sha256": hex.EncodeToString(sum[:]),
		"exp":    exp,
		"nbf":    time.Now().Add(-time.Minute).Unix(),
	}
	header, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	signingInput := b64.EncodeToString(header) + "." + b64.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	return signingInput + "." + b64.EncodeToString(mac.Sum(nil))
}

func webhookRequest(t *testing.T, body string, jwt string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/v1/webhooks/livekit", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+jwt)
	return r
}

func TestParseWebhook_EgressEnded(t *testing.T) {
	body := `{"event":"egress_ended","egressInfo":{"egressId":"EG1","roomName":"ses_42","status":"EGRESS_COMPLETE","file":{"filename":"ses_42-1234.mp4","location":"/out/ses_42-1234.mp4"}}}`
	jwt := mintWebhookJWT(t, []byte(body), testAPIKey, testSecret)
	r := webhookRequest(t, body, jwt)

	ev, err := ParseWebhook(r, testAPIKey, testSecret)
	if err != nil {
		t.Fatalf("ParseWebhook: %v", err)
	}
	if ev.Event != WebhookEgressEnded {
		t.Errorf("event = %q, want %q", ev.Event, WebhookEgressEnded)
	}
	if ev.EgressInfo == nil {
		t.Fatal("EgressInfo is nil")
	}
	if ev.EgressInfo.EgressID != "EG1" {
		t.Errorf("EgressID = %q, want EG1", ev.EgressInfo.EgressID)
	}
	if got := ev.EgressInfo.Output(); got != "/out/ses_42-1234.mp4" {
		t.Errorf("Output() = %q, want /out/ses_42-1234.mp4", got)
	}
}

func TestParseWebhook_WrongSecret(t *testing.T) {
	body := `{"event":"egress_started","egressInfo":{"egressId":"EG2","status":"EGRESS_STARTING"}}`
	jwt := mintWebhookJWT(t, []byte(body), testAPIKey, "wrongsecret")
	r := webhookRequest(t, body, jwt)

	_, err := ParseWebhook(r, testAPIKey, testSecret)
	if err == nil {
		t.Fatal("expected error for wrong secret, got nil")
	}
}

func TestParseWebhook_TamperedBody(t *testing.T) {
	body := `{"event":"egress_ended","egressInfo":{"egressId":"EG3","status":"EGRESS_COMPLETE"}}`
	jwt := mintWebhookJWT(t, []byte(body), testAPIKey, testSecret)
	// Tamper the body after signing.
	tampered := `{"event":"egress_ended","egressInfo":{"egressId":"EG99","status":"EGRESS_COMPLETE"}}`
	r := webhookRequest(t, tampered, jwt)

	_, err := ParseWebhook(r, testAPIKey, testSecret)
	if err == nil {
		t.Fatal("expected error for tampered body, got nil")
	}
}

func TestParseWebhook_MissingAuthorization(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/v1/webhooks/livekit", strings.NewReader("{}"))
	_, err := ParseWebhook(r, testAPIKey, testSecret)
	if err == nil {
		t.Fatal("expected error for missing auth, got nil")
	}
}

func TestParseWebhook_WrongIssuer(t *testing.T) {
	body := `{"event":"egress_started","egressInfo":{"egressId":"EG4","status":"EGRESS_STARTING"}}`
	jwt := mintWebhookJWT(t, []byte(body), "otherkey", testSecret)
	r := webhookRequest(t, body, jwt)

	_, err := ParseWebhook(r, testAPIKey, testSecret)
	if err == nil {
		t.Fatal("expected error for wrong issuer, got nil")
	}
	if !strings.Contains(err.Error(), "issuer") {
		t.Errorf("error should mention issuer, got: %v", err)
	}
}

func TestParseWebhook_ExpiredToken(t *testing.T) {
	body := `{"event":"egress_started","egressInfo":{"egressId":"EG5","status":"EGRESS_STARTING"}}`
	// Expired well outside the clock-skew window.
	exp := time.Now().Add(-5 * time.Minute).Unix()
	jwt := mintWebhookJWTWithExp(t, []byte(body), testSecret, exp)
	r := webhookRequest(t, body, jwt)

	_, err := ParseWebhook(r, testAPIKey, testSecret)
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error should mention expired, got: %v", err)
	}
}
