// Package consent is the recording-consent ledger: an append-only, hash-chained,
// server-signed record of who consented (or withdrew consent) to recording a
// session. Decree 147 / PDPL require demonstrable consent before recording and
// that a withdrawal can stop it; this provides the gate (RecordingAllowed) the
// egress pipeline must honour, and a tamper-evident trail (VerifyChain).
package consent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/pkg/contracts"
)

// Repo is the persistence the service needs (*store.Store satisfies it).
type Repo interface {
	AppendConsent(ctx context.Context, in store.ConsentInput) error
	EffectiveConsent(ctx context.Context, subjectID, sessionID string, purpose contracts.ConsentPurpose) (bool, error)
	RecordingAllowed(ctx context.Context, sessionID string) (bool, error)
}

// Service records and reports recording consent. A subject only ever acts on
// their own consent (the HTTP layer passes the authenticated subject).
type Service struct {
	repo  Repo
	newID func() string
}

// NewService wires the repo.
func NewService(repo Repo) (*Service, error) {
	if repo == nil {
		return nil, errors.New("consent: repo is required")
	}
	return &Service{repo: repo, newID: newID}, nil
}

// Grant appends a granted consent for the subject to record the session.
func (s *Service) Grant(ctx context.Context, subjectID, sessionID string) error {
	return s.append(ctx, subjectID, sessionID, true)
}

// Withdraw appends a withdrawal (a new granted=false record; never a delete).
func (s *Service) Withdraw(ctx context.Context, subjectID, sessionID string) error {
	return s.append(ctx, subjectID, sessionID, false)
}

func (s *Service) append(ctx context.Context, subjectID, sessionID string, granted bool) error {
	return s.repo.AppendConsent(ctx, store.ConsentInput{
		ID:        s.newID(),
		SessionID: sessionID,
		SubjectID: subjectID,
		Purpose:   contracts.ConsentPurposeSessionRecording,
		Granted:   granted,
	})
}

// Effective reports the subject's latest recording-consent decision for the
// session (false if none).
func (s *Service) Effective(ctx context.Context, subjectID, sessionID string) (bool, error) {
	return s.repo.EffectiveConsent(ctx, subjectID, sessionID, contracts.ConsentPurposeSessionRecording)
}

// RecordingAllowed reports whether every active participant has consented.
func (s *Service) RecordingAllowed(ctx context.Context, sessionID string) (bool, error) {
	return s.repo.RecordingAllowed(ctx, sessionID)
}

// --- chain verification ------------------------------------------------------

// GenesisHash is the prev_hash of the first record: SHA-256-length zero bytes.
func GenesisHash() []byte { return make([]byte, sha256.Size) }

// Verifier checks the ledger chain against a set of public keys, keyed by id so
// rotated-out keys still verify their historical records.
type Verifier struct {
	keys map[string]ed25519.PublicKey
}

// NewVerifier builds a verifier over the given key set.
func NewVerifier(keys map[string]ed25519.PublicKey) *Verifier {
	return &Verifier{keys: keys}
}

// VerifyChain verifies records in chain order: each PrevHash must equal the
// prior record's Hash, and each signature must verify (over the canonical
// SignedPayload, which includes PrevHash — so any altered field or reordering
// is caught). An empty ledger verifies.
func (v *Verifier) VerifyChain(records []contracts.ConsentRecord) error {
	prev := GenesisHash()
	for _, r := range records {
		if !bytes.Equal(r.PrevHash, prev) {
			return fmt.Errorf("consent: broken chain at %q (prev_hash mismatch)", r.ID)
		}
		pub, ok := v.keys[r.SigningKeyID]
		if !ok {
			return fmt.Errorf("consent: unknown signing key %q at %q", r.SigningKeyID, r.ID)
		}
		if !ed25519.Verify(pub, r.SignedPayload(), r.Signature) {
			return fmt.Errorf("consent: bad signature at %q", r.ID)
		}
		prev = r.Hash()
	}
	return nil
}

// newID returns a 26-char Crockford-base32 record id (ULID-shaped, identity
// only), matching the opaque-id style used elsewhere.
func newID() string {
	const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var b [26]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("consent: crypto/rand unavailable: " + err.Error())
	}
	for i := range b {
		b[i] = crockford[int(b[i])%len(crockford)]
	}
	return string(b[:])
}
