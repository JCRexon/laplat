package livekit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestGranter_TokenSignsVerifiableGrant(t *testing.T) {
	g, err := NewGranter("APIkey", "secretsecret", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	fixed := time.Unix(1_700_000_000, 0)
	g.Now = func() time.Time { return fixed }

	tok, err := g.Token("user-1", "Alice", VideoGrant{
		Room: "ses_42", RoomJoin: true, CanPublish: true, CanSubscribe: true, CanPublishData: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", tok)
	}

	// Signature must verify with the secret (HS256).
	mac := hmac.New(sha256.New, []byte("secretsecret"))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if b64.EncodeToString(mac.Sum(nil)) != parts[2] {
		t.Fatal("signature does not verify")
	}

	// Claims carry the LiveKit video grant and standard fields.
	payload, _ := b64.DecodeString(parts[1])
	var c tokenClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatal(err)
	}
	if c.Iss != "APIkey" || c.Sub != "user-1" || c.Name != "Alice" {
		t.Fatalf("claims = %+v", c)
	}
	if c.Exp != fixed.Add(10*time.Minute).Unix() {
		t.Fatalf("exp = %d", c.Exp)
	}
	if c.Video.Room != "ses_42" || !c.Video.RoomJoin || !c.Video.CanPublish {
		t.Fatalf("grant = %+v", c.Video)
	}
}

func TestNewGranter_Validation(t *testing.T) {
	if _, err := NewGranter("", "s", time.Minute); err == nil {
		t.Fatal("empty key should error")
	}
	if _, err := NewGranter("k", "s", 0); err == nil {
		t.Fatal("non-positive ttl should error")
	}
}

func TestToken_RequiresIdentity(t *testing.T) {
	g, _ := NewGranter("k", "s", time.Minute)
	if _, err := g.Token("", "", VideoGrant{Room: "r"}); err == nil {
		t.Fatal("empty identity should error")
	}
}
