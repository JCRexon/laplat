package recording

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"
)

// Playback tokens bind a signed playback URL to a specific viewer AND a specific
// recording, so a leaked URL is scoped and short-lived (ADR-011). nginx forwards
// the token to authd's serving-authz check, which verifies it, re-checks the
// viewer's entitlement live, and audits the access. HMAC-SHA256 over the
// base64url payload; the key is the shared recordings secret.
//
// Wire form: base64url("<subject>|<recordingID>|<expUnix>") + "." + base64url(mac)

var errBadPlaybackToken = errors.New("recording: invalid playback token")

var tokEnc = base64.RawURLEncoding

func playbackMAC(secret, signingInput string) []byte {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(signingInput))
	return m.Sum(nil)
}

// mintPlaybackToken issues a token authorising subject to fetch recordingID
// until exp.
func mintPlaybackToken(secret, subject, recordingID string, exp time.Time) string {
	payload := subject + "|" + recordingID + "|" + strconv.FormatInt(exp.Unix(), 10)
	p := tokEnc.EncodeToString([]byte(payload))
	sig := tokEnc.EncodeToString(playbackMAC(secret, p))
	return p + "." + sig
}

// parsePlaybackToken verifies a token's signature and expiry against now, and
// returns the subject and recording id it authorises.
func parsePlaybackToken(token, secret string, now time.Time) (subject, recordingID string, err error) {
	p, sig, ok := strings.Cut(token, ".")
	if !ok {
		return "", "", errBadPlaybackToken
	}
	wantSig, err := tokEnc.DecodeString(sig)
	if err != nil {
		return "", "", errBadPlaybackToken
	}
	if !hmac.Equal(wantSig, playbackMAC(secret, p)) {
		return "", "", errBadPlaybackToken
	}
	raw, err := tokEnc.DecodeString(p)
	if err != nil {
		return "", "", errBadPlaybackToken
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 3 {
		return "", "", errBadPlaybackToken
	}
	exp, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return "", "", errBadPlaybackToken
	}
	if now.Unix() > exp {
		return "", "", errBadPlaybackToken
	}
	if parts[0] == "" || parts[1] == "" {
		return "", "", errBadPlaybackToken
	}
	return parts[0], parts[1], nil
}
