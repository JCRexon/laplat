package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/jcrexon/laplat/pkg/contracts"
)

// The default policy maps built-in signals to exactly the historical ladder.
func TestDefaultPolicy_BuiltinSignals(t *testing.T) {
	cases := []struct {
		name     string
		status   string
		declared bool
		phone    bool
		want     contracts.IdentityVerificationState
	}{
		{"nothing", "none", false, false, contracts.IdentityNone},
		{"attested only", "none", true, false, contracts.IdentityDeclared},
		{"phone without attestation stays none", "none", false, true, contracts.IdentityNone},
		{"phone + attested", "none", true, true, contracts.IdentityPhoneVerified},
		{"ekyc outranks all", "verified", false, false, contracts.IdentityVerified},
		{"pending below declared", "pending", true, false, contracts.IdentityDeclared},
		{"pending alone", "pending", false, false, contracts.IdentityPending},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := defaultAssurancePolicy.Tier(builtinSignals(tc.status, tc.declared, tc.phone))
			if got != tc.want {
				t.Fatalf("Tier = %q, want %q", got, tc.want)
			}
		})
	}
}

// A new signal + one policy row lifts the tier — no change to the derivation.
// This is the snap-in property (Brick 2).
func TestPolicy_SnapInNewSignal(t *testing.T) {
	const SignalBiometricLiveness Signal = "biometric_liveness"

	// Liveness as an alternative path to verified, prepended so it is considered.
	policy := append(assurancePolicy{
		{contracts.IdentityVerified, []Signal{SignalBiometricLiveness}},
	}, defaultAssurancePolicy...)

	held := SignalSet{}
	held.Add(SignalBiometricLiveness)
	if got := policy.Tier(held); got != contracts.IdentityVerified {
		t.Fatalf("Tier with biometric signal = %q, want verified", got)
	}
	// Without the signal the same policy falls through to the built-in ladder.
	if got := policy.Tier(builtinSignals("none", true, false)); got != contracts.IdentityDeclared {
		t.Fatalf("Tier without biometric = %q, want declared", got)
	}
}

type fakeSource struct {
	sigs []Signal
	err  error
}

func (f fakeSource) Signals(context.Context, string) ([]Signal, error) { return f.sigs, f.err }

// A registered source's signals are unioned into the held set.
func TestGatherInto_UnionsRegisteredSource(t *testing.T) {
	const SignalBiometricLiveness Signal = "biometric_liveness"
	held := builtinSignals("none", true, false) // adult_attested
	sources := []SignalSource{fakeSource{sigs: []Signal{SignalBiometricLiveness}}}

	if err := gatherInto(context.Background(), held, sources, "u1"); err != nil {
		t.Fatalf("gatherInto: %v", err)
	}
	if !held[SignalBiometricLiveness] || !held[SignalAdultAttested] {
		t.Fatalf("held set missing signals: %v", held)
	}
}

// A source error aborts gathering — an assurance read must not silently
// under-report and downgrade a user.
func TestGatherInto_SourceErrorPropagates(t *testing.T) {
	boom := errors.New("source down")
	held := SignalSet{}
	err := gatherInto(context.Background(), held, []SignalSource{fakeSource{err: boom}}, "u1")
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
}
