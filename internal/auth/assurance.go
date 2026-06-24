package auth

import (
	"context"

	"github.com/jcrexon/laplat/pkg/contracts"
)

// Signal is a discrete, verified fact about a user's identity assurance. Signals
// are an OPEN set: a new assurance mechanism (an eKYC variant, biometric
// liveness, ...) introduces a new Signal and a policy row without touching the
// tier derivation or a schema enum. See AUTH-EXTENSIBILITY.md (Brick 2).
type Signal string

const (
	// SignalAdultAttested — the user self-declared 18+ (a current-version ToS
	// acceptance). Proves a claim, not an identity.
	SignalAdultAttested Signal = "adult_attested"
	// SignalPhoneVerified — the user holds a verified phone binding (the Decree
	// 147 interaction floor). Proves account-control via phone, not adulthood.
	SignalPhoneVerified Signal = "phone_verified"
	// SignalEKYCVerified — national-ID eKYC cleared (a verified adult).
	SignalEKYCVerified Signal = "ekyc_verified"
	// SignalEKYCPending — an eKYC check is in flight (orthogonal; never a
	// downgrade of an already-held tier).
	SignalEKYCPending Signal = "ekyc_pending"
)

// SignalSet is the set of signals a user currently holds.
type SignalSet map[Signal]bool

// Add records a held signal.
func (s SignalSet) Add(sig Signal) { s[sig] = true }

// HasAll reports whether every required signal is held (an empty requirement is
// trivially satisfied).
func (s SignalSet) HasAll(required []Signal) bool {
	for _, r := range required {
		if !s[r] {
			return false
		}
	}
	return true
}

// tierRule grants a tier when all of its required signals are held.
type tierRule struct {
	tier     contracts.IdentityVerificationState
	requires []Signal
}

// assurancePolicy maps held signals to an assurance tier. Rules are evaluated in
// order and the FIRST satisfied rule wins, so rules are listed highest-tier
// first. This is the assurance policy as DATA — adding a tier or letting a new
// signal contribute is a row here, not a branch in control flow.
type assurancePolicy []tierRule

// Tier returns the highest tier whose required signals are all held, or
// IdentityNone if no rule matches.
func (p assurancePolicy) Tier(held SignalSet) contracts.IdentityVerificationState {
	for _, rule := range p {
		if held.HasAll(rule.requires) {
			return rule.tier
		}
	}
	return contracts.IdentityNone
}

// defaultAssurancePolicy is the live ladder. Order matters: verified outranks
// everything; phone_verified requires BOTH a verified phone and the 18+
// attestation (a phone binding alone proves account-control, not adulthood);
// declared is attestation alone; pending sits below declared so an attested user
// with an eKYC check in flight keeps the declared tier rather than dropping to
// pending (never a downgrade).
var defaultAssurancePolicy = assurancePolicy{
	{contracts.IdentityVerified, []Signal{SignalEKYCVerified}},
	{contracts.IdentityPhoneVerified, []Signal{SignalPhoneVerified, SignalAdultAttested}},
	{contracts.IdentityDeclared, []Signal{SignalAdultAttested}},
	{contracts.IdentityPending, []Signal{SignalEKYCPending}},
}

// builtinSignals maps the assurance facts mint() already reads (the eKYC
// verification status plus the attestation/phone booleans) onto signals. These
// derive from data already in hand, so they add no database reads.
func builtinSignals(verificationStatus string, declaredAdult, phoneVerified bool) SignalSet {
	held := SignalSet{}
	if declaredAdult {
		held.Add(SignalAdultAttested)
	}
	if phoneVerified {
		held.Add(SignalPhoneVerified)
	}
	switch verificationStatus {
	case string(contracts.IdentityVerified):
		held.Add(SignalEKYCVerified)
	case string(contracts.IdentityPending):
		held.Add(SignalEKYCPending)
	}
	return held
}

// SignalSource reports the assurance signals a user currently holds from one
// backing store. Registering a SignalSource is how a NEW assurance mechanism
// snaps in: the source emits its signal, a policy row consumes it, and neither
// mint() nor the built-in derivation changes. Built-in signals do not go through
// a source (they ride on data mint already holds); sources are for additional
// mechanisms that own their own storage.
type SignalSource interface {
	Signals(ctx context.Context, userID string) ([]Signal, error)
}

// gatherInto unions each source's signals into held. A source error aborts (an
// assurance read must not silently under-report and downgrade a user).
func gatherInto(ctx context.Context, held SignalSet, sources []SignalSource, userID string) error {
	for _, src := range sources {
		sigs, err := src.Signals(ctx, userID)
		if err != nil {
			return err
		}
		for _, sig := range sigs {
			held.Add(sig)
		}
	}
	return nil
}
