// Package livekit mints LiveKit access tokens (room "grants"). A LiveKit token
// is a JWT signed HS256 with the project API secret, carrying a video grant
// that scopes the bearer to exactly one room with explicit publish/subscribe
// permissions. Per contracts §1, these per-room grants are minted at join time
// from session participation — they are NEVER carried in the platform access
// token (which holds only global capabilities). Stdlib-only, matching the
// pkg/token ethos.
package livekit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

var b64 = base64.RawURLEncoding

// VideoGrant is the LiveKit room grant. Booleans are always serialized so a
// permission is explicit rather than relying on server defaults.
type VideoGrant struct {
	Room           string `json:"room"`
	RoomJoin       bool   `json:"roomJoin"`
	CanPublish     bool   `json:"canPublish"`
	CanSubscribe   bool   `json:"canSubscribe"`
	CanPublishData bool   `json:"canPublishData"`
}

// Granter signs LiveKit access tokens for a project (apiKey/apiSecret).
type Granter struct {
	apiKey    string
	apiSecret []byte
	ttl       time.Duration
	Now       func() time.Time
}

// NewGranter validates credentials and builds a granter. ttl bounds how long a
// minted room token is valid (the join window); it should be short.
func NewGranter(apiKey, apiSecret string, ttl time.Duration) (*Granter, error) {
	if apiKey == "" || apiSecret == "" {
		return nil, errors.New("livekit: api key and secret are required")
	}
	if ttl <= 0 {
		return nil, errors.New("livekit: ttl must be positive")
	}
	return &Granter{apiKey: apiKey, apiSecret: []byte(apiSecret), ttl: ttl, Now: time.Now}, nil
}

// Token mints a room access token for participant `identity` (display `name`
// optional) with the given grant.
func (g *Granter) Token(identity, name string, grant VideoGrant) (string, error) {
	if identity == "" {
		return "", errors.New("livekit: identity is required")
	}
	now := g.now()
	claims := tokenClaims{
		Iss:   g.apiKey,
		Sub:   identity,
		Iat:   now.Unix(),
		Nbf:   now.Unix(),
		Exp:   now.Add(g.ttl).Unix(),
		Name:  name,
		Video: grant,
	}
	header, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64.EncodeToString(header) + "." + b64.EncodeToString(payload)
	mac := hmac.New(sha256.New, g.apiSecret)
	mac.Write([]byte(signingInput))
	return signingInput + "." + b64.EncodeToString(mac.Sum(nil)), nil
}

func (g *Granter) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

type tokenClaims struct {
	Iss   string     `json:"iss"`
	Sub   string     `json:"sub"`
	Iat   int64      `json:"iat"`
	Nbf   int64      `json:"nbf"`
	Exp   int64      `json:"exp"`
	Name  string     `json:"name,omitempty"`
	Video VideoGrant `json:"video"`
}
