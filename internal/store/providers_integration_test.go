//go:build integration

package store_test

import (
	"testing"
)

// The reference table is seeded with the providers the old CHECK constraint
// hard-coded.
func TestAuthProviders_Seeded(t *testing.T) {
	st, ctx := newStore(t)
	got, err := st.ListAuthProviders(ctx)
	if err != nil {
		t.Fatalf("ListAuthProviders: %v", err)
	}
	want := map[string]bool{"apple": true, "google": true, "zalo": true}
	if len(got) != len(want) {
		t.Fatalf("providers = %v, want %v", got, want)
	}
	for _, p := range got {
		if !want[p] {
			t.Fatalf("unexpected provider %q in %v", p, got)
		}
	}
}

// The federated_identities FK enforces the provider set: a registered provider
// links, an unregistered one is rejected at write time (no CHECK, no Go map).
func TestFederatedIdentity_FKEnforcesProviders(t *testing.T) {
	st, ctx := newStore(t)

	if err := st.LinkFederatedIdentity(ctx, "google", "sub-1", userA); err != nil {
		t.Fatalf("registered provider should link: %v", err)
	}
	if err := st.LinkFederatedIdentity(ctx, "facebook", "sub-2", userA); err == nil {
		t.Fatal("unregistered provider should be rejected by the FK")
	}
}
