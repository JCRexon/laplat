package auth

import (
	"net/http/httptest"
	"testing"

	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/pkg/contracts"
)

func TestCapabilities(t *testing.T) {
	tests := []struct {
		name string
		user store.User
		want []contracts.Capability
	}{
		{"none", store.User{}, []contracts.Capability{}},
		{"instructor", store.User{CanInstruct: true}, []contracts.Capability{contracts.CapCanInstruct}},
		{"moderator", store.User{IsPlatformModerator: true}, []contracts.Capability{contracts.CapPlatformModerator}},
		{"both", store.User{CanInstruct: true, IsPlatformModerator: true},
			[]contracts.Capability{contracts.CapCanInstruct, contracts.CapPlatformModerator}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := capabilities(tc.user)
			if len(got) != len(tc.want) {
				t.Fatalf("caps = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("caps = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestIdentityState(t *testing.T) {
	tests := []struct {
		status   string
		declared bool
		phone    bool
		want     contracts.IdentityVerificationState
	}{
		{"verified", false, false, contracts.IdentityVerified},
		{"verified", true, true, contracts.IdentityVerified},  // eKYC outranks all
		{"none", true, true, contracts.IdentityPhoneVerified}, // declared + phone
		{"none", false, true, contracts.IdentityNone},         // phone alone is not adulthood
		{"pending", false, true, contracts.IdentityPending},   // phone alone, eKYC pending
		{"pending", true, true, contracts.IdentityPhoneVerified},
		{"pending", true, false, contracts.IdentityDeclared}, // declared keeps tier while pending
		{"none", true, false, contracts.IdentityDeclared},
		{"none", false, false, contracts.IdentityNone},
		{"garbage", false, false, contracts.IdentityNone},
		{"", true, false, contracts.IdentityDeclared},
	}
	for _, tc := range tests {
		got := identityState(store.Identity{VerificationStatus: tc.status}, tc.declared, tc.phone)
		if got != tc.want {
			t.Fatalf("identityState(%q, declared=%v, phone=%v) = %q, want %q", tc.status, tc.declared, tc.phone, got, tc.want)
		}
	}
}

func TestBearerToken(t *testing.T) {
	tests := []struct {
		header string
		want   string
		wantOK bool
	}{
		{"Bearer abc.def.ghi", "abc.def.ghi", true},
		{"bearer abc", "abc", true}, // scheme is case-insensitive
		{"Bearer    spaced   ", "spaced", true},
		{"", "", false},
		{"Basic abc", "", false},
		{"Bearer ", "", false},
		{"Bearer", "", false},
	}
	for _, tc := range tests {
		r := httptest.NewRequest("GET", "/", nil)
		if tc.header != "" {
			r.Header.Set("Authorization", tc.header)
		}
		got, ok := bearerToken(r)
		if ok != tc.wantOK || got != tc.want {
			t.Fatalf("bearerToken(%q) = (%q,%v), want (%q,%v)", tc.header, got, ok, tc.want, tc.wantOK)
		}
	}
}

func TestSecretGeneration(t *testing.T) {
	// Refresh secrets are URL-safe and unique; opaque ids are 26-char Crockford.
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		s := newRefreshSecret()
		if s == "" || seen[s] {
			t.Fatalf("non-unique or empty secret: %q", s)
		}
		seen[s] = true

		id := newOpaqueID()
		if len(id) != 26 {
			t.Fatalf("opaque id length = %d, want 26", len(id))
		}
		for _, r := range id {
			if !((r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z')) {
				t.Fatalf("opaque id has illegal char %q in %q", r, id)
			}
		}
	}
	// Hashing is deterministic and 32 bytes (sha256).
	if a, b := hashSecret("x"), hashSecret("x"); string(a) != string(b) || len(a) != 32 {
		t.Fatalf("hashSecret not deterministic/32-byte")
	}
}
