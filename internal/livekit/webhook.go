package livekit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// WebhookEvent is a LiveKit server webhook payload.
type WebhookEvent struct {
	Event      string      `json:"event"`
	EgressInfo *EgressInfo `json:"egressInfo"`
}

// Egress lifecycle webhook event names.
const (
	WebhookEgressStarted = "egress_started"
	WebhookEgressUpdated = "egress_updated"
	WebhookEgressEnded   = "egress_ended"
)

// ParseWebhook reads and verifies a LiveKit webhook request.
//
// LiveKit signs webhooks with a short-lived HS256 JWT in the Authorization
// header (Bearer). The JWT payload carries a sha256 field — a hex SHA-256 of
// the raw body — so both the signature and body integrity are verified before
// the payload is decoded. The body is consumed; the caller must not have read
// it beforehand.
func ParseWebhook(r *http.Request, apiSecret string) (*WebhookEvent, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("livekit webhook: reading body: %w", err)
	}

	auth := r.Header.Get("Authorization")
	const pfx = "Bearer "
	if len(auth) <= len(pfx) || !strings.EqualFold(auth[:len(pfx)], pfx) {
		return nil, errors.New("livekit webhook: missing or malformed Bearer token")
	}
	jwtTok := strings.TrimSpace(auth[len(pfx):])

	claims, err := verifyWebhookJWT(jwtTok, []byte(apiSecret))
	if err != nil {
		return nil, fmt.Errorf("livekit webhook: jwt: %w", err)
	}

	// Constant-time comparison prevents timing oracle on the claimed body hash.
	sum := sha256.Sum256(body)
	actual := hex.EncodeToString(sum[:])
	if !hmac.Equal([]byte(actual), []byte(claims.SHA256)) {
		return nil, errors.New("livekit webhook: body hash mismatch")
	}

	var ev WebhookEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		return nil, fmt.Errorf("livekit webhook: decoding payload: %w", err)
	}
	return &ev, nil
}

type webhookClaims struct {
	Issuer string `json:"iss"`
	SHA256 string `json:"sha256"`
}

// verifyWebhookJWT verifies an HS256 JWT signed with secret and returns its
// claims. The algorithm and typ headers are not validated beyond being present;
// the signature is the security gate.
func verifyWebhookJWT(token string, secret []byte) (*webhookClaims, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, errors.New("not a three-part JWT")
	}
	signingInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	expected := b64.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return nil, errors.New("signature mismatch")
	}
	claimsJSON, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding claims: %w", err)
	}
	var c webhookClaims
	if err := json.Unmarshal(claimsJSON, &c); err != nil {
		return nil, fmt.Errorf("parsing claims: %w", err)
	}
	return &c, nil
}
