package validate

import (
	"errors"
	"strings"
	"testing"
)

func TestULID(t *testing.T) {
	valid := "01ARZ3NDEKTSV4RRFFQ69G5FAV" // 26 chars, Crockford
	if err := ULID(valid); err != nil {
		t.Fatalf("valid ULID rejected: %v", err)
	}
	bad := map[string]string{
		"empty":      "",
		"too short":  "01ARZ3NDEK",
		"lowercase":  strings.ToLower(valid),
		"bad letter": "01ARZ3NDEKTSV4RRFFQ69G5FAI", // 'I' not in Crockford
		"with dot":   "01ARZ3NDEKTSV4RRFFQ69G5FA.",
	}
	for name, s := range bad {
		if err := ULID(s); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

// TestThreat_B2_SubjectTokenRejectsInjection: a value bound for a NATS subject
// must never carry subject metacharacters, or it could escape subject scoping
// (B-1 / B-2).
func TestThreat_B2_SubjectTokenRejectsInjection(t *testing.T) {
	for _, s := range []string{"a.b", "a*", ">", "a>b", "a b", "a\tb", "a\x00b", ""} {
		if err := SubjectToken(s); err == nil {
			t.Errorf("SubjectToken accepted dangerous value %q", s)
		}
	}
	for _, s := range []string{"abc123", "01ARZ3NDEKTSV4RRFFQ69G5FAV", "a_b-c"} {
		if err := SubjectToken(s); err != nil {
			t.Errorf("SubjectToken rejected safe value %q: %v", s, err)
		}
	}
}

func TestBoundedText(t *testing.T) {
	if err := BoundedText("hello\nworld", 50); err != nil {
		t.Errorf("expected ok, got %v", err)
	}
	if err := BoundedText("", 50); !errors.Is(err, ErrEmpty) {
		t.Errorf("want ErrEmpty, got %v", err)
	}
	if err := BoundedText(strings.Repeat("a", 51), 50); !errors.Is(err, ErrTooLong) {
		t.Errorf("want ErrTooLong, got %v", err)
	}
	if err := BoundedText("bad\x07bell", 50); !errors.Is(err, ErrCharset) {
		t.Errorf("want ErrCharset, got %v", err)
	}
	// Multibyte counts as runes, not bytes (Vietnamese diacritics).
	if err := BoundedText("ếệữằ", 4); err != nil {
		t.Errorf("rune-counted text wrongly rejected: %v", err)
	}
}

func TestHandle(t *testing.T) {
	if err := Handle("nguyen_an"); err != nil {
		t.Errorf("valid handle rejected: %v", err)
	}
	for _, s := range []string{"ab", "", "UpperCase", "has space", "emoji😀", strings.Repeat("a", 33)} {
		if err := Handle(s); err == nil {
			t.Errorf("expected rejection of %q", s)
		}
	}
}

func TestEnum(t *testing.T) {
	if err := Enum("direct", "class", "direct"); err != nil {
		t.Errorf("expected member, got %v", err)
	}
	if err := Enum("admin", "subscriber", "publisher"); !errors.Is(err, ErrNotInSet) {
		t.Errorf("want ErrNotInSet, got %v", err)
	}
}

// Fuzzing the subject-token validator: anything it ACCEPTS must be free of
// subject metacharacters and whitespace, and it must never panic.
func FuzzSubjectToken(f *testing.F) {
	for _, s := range []string{"", "abc", "a.b", "a*", ">", "01ARZ3NDEK", "a_b-c", "\n"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if err := SubjectToken(s); err == nil {
			for _, r := range s {
				switch r {
				case '.', '*', '>', ' ', '\t', '\n', '\r':
					t.Fatalf("accepted dangerous rune %q in %q", r, s)
				}
			}
		}
	})
}
