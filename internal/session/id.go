package session

import "crypto/rand"

// newID returns a 26-char Crockford-base32 opaque session id (ULID-shaped,
// identity only). Mirrors the id scheme used elsewhere in the platform.
func newID() string {
	const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var b [26]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("session: crypto/rand unavailable: " + err.Error())
	}
	for i := range b {
		b[i] = crockford[int(b[i])%len(crockford)]
	}
	return string(b[:])
}
