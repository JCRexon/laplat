// Package validate provides input validators used at the platform's trust
// boundary — HTTP handlers, NATS subject construction, object keys — to defend
// against malicious or malformed input (defence-in-depth layer 1).
//
// It is stdlib-only. NFC normalisation of Vietnamese text (a CLAUDE.md i18n
// requirement, and a normalisation-attack defence) requires
// golang.org/x/text/unicode/norm; that validator lands when that dependency is
// introduced. Until then, callers must not assume text is normalised.
package validate

import (
	"errors"
	"unicode"
)

// Length bounds prevent storage abuse / DoS while allowing real content.
const (
	MaxHandleLen   = 32
	MinHandleLen   = 3
	MaxDisplayName = 80
	MaxBioLen      = 500
	ULIDLen        = 26
)

var (
	ErrEmpty    = errors.New("validate: empty")
	ErrTooLong  = errors.New("validate: too long")
	ErrTooShort = errors.New("validate: too short")
	ErrCharset  = errors.New("validate: illegal characters")
	ErrNotInSet = errors.New("validate: value not allowed")
	ErrBadID    = errors.New("validate: malformed identifier")
)

// crockford is the Crockford base32 alphabet used by ULIDs (excludes I, L, O,
// U to avoid ambiguity).
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// ULID validates a Crockford-base32, 26-character, upper-case ULID. We use
// ULIDs as opaque identifiers everywhere, so accepting only well-formed ULIDs
// at the boundary rejects a large class of injection payloads up front.
func ULID(s string) error {
	if s == "" {
		return ErrEmpty
	}
	if len(s) != ULIDLen {
		return ErrBadID
	}
	for _, r := range s {
		if !containsRune(crockford, r) {
			return ErrBadID
		}
	}
	return nil
}

// SubjectToken validates a value that will be embedded into a NATS subject (or
// any dot-delimited routing key / object path). It rejects the subject
// metacharacters '.', '*', '>' plus whitespace and control characters, which
// is what stops a crafted id from escaping subject scoping (B-1 / B-2). Allowed
// set: ASCII letters, digits, '_' and '-'.
func SubjectToken(s string) error {
	if s == "" {
		return ErrEmpty
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_' || r == '-':
		default:
			return ErrCharset
		}
	}
	return nil
}

// BoundedText validates free text: non-empty, at most maxRunes runes, and free
// of control characters other than common whitespace (tab/newline/carriage
// return). Output encoding (XSS, B-3) is the renderer's job; this only bounds
// and sanitises structurally.
func BoundedText(s string, maxRunes int) error {
	if s == "" {
		return ErrEmpty
	}
	n := 0
	for _, r := range s {
		n++
		if n > maxRunes {
			return ErrTooLong
		}
		if unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r' {
			return ErrCharset
		}
	}
	return nil
}

// Handle validates a user handle: 3-32 chars of [a-z0-9_].
func Handle(s string) error {
	if len(s) < MinHandleLen {
		if s == "" {
			return ErrEmpty
		}
		return ErrTooShort
	}
	if len(s) > MaxHandleLen {
		return ErrTooLong
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
		default:
			return ErrCharset
		}
	}
	return nil
}

// Enum reports whether s is one of the allowed values. Boundary enum checks
// mirror the DB CHECK constraints (defence-in-depth) and reject bad input
// before it reaches the database.
func Enum(s string, allowed ...string) error {
	for _, a := range allowed {
		if s == a {
			return nil
		}
	}
	return ErrNotInSet
}

func containsRune(set string, r rune) bool {
	for _, c := range set {
		if c == r {
			return true
		}
	}
	return false
}
