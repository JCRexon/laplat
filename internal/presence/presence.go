// Package presence implements the tamper-evidence half of session-presence
// auditing (ADR-010 stage 2): a checkpoint worker that periodically folds a
// Vault-signed Merkle root over new presence_events into the global audit_log,
// and a verifier that proves a given presence event is included under a signed
// root.
//
// The hot path (recording join/leave) lives in the session domain and writes
// rows cheaply; this package adds the cryptographic anchor out-of-band so the
// join path pays no signing cost.
package presence

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"

	"github.com/jcrexon/laplat/internal/audit"
	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/pkg/contracts"
	"github.com/jcrexon/laplat/pkg/merkle"
)

// defaultBatch caps how many presence rows one checkpoint covers, bounding the
// tree size and the work per tick.
const defaultBatch = 10000

var (
	// ErrNotCheckpointed means no checkpoint yet covers the event (it is still in
	// the pre-checkpoint window; its DB-level immutability still protects it).
	ErrNotCheckpointed = errors.New("presence: event not yet covered by a checkpoint")
	// ErrEventNotFound means the seq is not in its checkpoint's range.
	ErrEventNotFound = errors.New("presence: event not found in checkpoint range")
	// ErrNoVerifier means the service was built without an audit verifier.
	ErrNoVerifier = errors.New("presence: no audit verifier configured")
)

// Repo is the persistence the service needs (*store.Store satisfies it).
type Repo interface {
	LatestPresenceCheckpointSeq(ctx context.Context) (int64, error)
	PresenceEventsAfter(ctx context.Context, afterSeq int64, limit int) ([]store.PresenceEvent, error)
	WritePresenceCheckpoint(ctx context.Context, id string, root []byte, fromSeq, toSeq int64, count int) error
	PresenceCheckpointCovering(ctx context.Context, seq int64) (store.PresenceCheckpoint, bool, error)
	PresenceEventsInRange(ctx context.Context, fromSeq, toSeq int64) ([]store.PresenceEvent, error)
	AuditEntryBySeq(ctx context.Context, seq int64) (contracts.AuditEntry, error)
}

// Service runs presence checkpointing and verification.
type Service struct {
	repo     Repo
	verifier *audit.Verifier // nil unless verification is needed
	batch    int
	newID    func() string
}

// NewService wires the repo. verifier may be nil if only checkpointing is needed;
// Verify requires it.
func NewService(repo Repo, verifier *audit.Verifier) (*Service, error) {
	if repo == nil {
		return nil, errors.New("presence: repo required")
	}
	return &Service{repo: repo, verifier: verifier, batch: defaultBatch, newID: newID}, nil
}

// Checkpoint folds all presence events since the last checkpoint into one signed
// Merkle root in the audit chain. Reports whether a checkpoint was written (false
// when there was nothing new). Idempotent and resumable: it resumes from the last
// covered seq, and the write is atomic, so a crash never double-covers a range.
func (s *Service) Checkpoint(ctx context.Context) (bool, error) {
	last, err := s.repo.LatestPresenceCheckpointSeq(ctx)
	if err != nil {
		return false, err
	}
	evs, err := s.repo.PresenceEventsAfter(ctx, last, s.batch)
	if err != nil {
		return false, err
	}
	if len(evs) == 0 {
		return false, nil
	}
	leaves := make([][]byte, len(evs))
	for i, e := range evs {
		leaves[i] = leafBytes(e)
	}
	root := merkle.Root(leaves)
	from, to := evs[0].Seq, evs[len(evs)-1].Seq
	if err := s.repo.WritePresenceCheckpoint(ctx, s.newID(), root, from, to, len(evs)); err != nil {
		return false, err
	}
	return true, nil
}

// Verify proves that the presence event at seq is tamper-evidently recorded: it is
// included (Merkle proof) under a root that the rebuilt range reproduces, and that
// root is committed in a validly-signed audit_log entry. Any mismatch — altered
// row, wrong root, bad signature — is an error.
func (s *Service) Verify(ctx context.Context, seq int64) error {
	if s.verifier == nil {
		return ErrNoVerifier
	}
	cp, ok, err := s.repo.PresenceCheckpointCovering(ctx, seq)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotCheckpointed
	}

	rows, err := s.repo.PresenceEventsInRange(ctx, cp.FromSeq, cp.ToSeq)
	if err != nil {
		return err
	}
	leaves := make([][]byte, len(rows))
	idx := -1
	for i, e := range rows {
		leaves[i] = leafBytes(e)
		if e.Seq == seq {
			idx = i
		}
	}
	if idx < 0 {
		return ErrEventNotFound
	}

	// The rebuilt root must match the indexed checkpoint root (no row in the range
	// was altered/added/removed).
	if root := merkle.Root(leaves); !bytes.Equal(root, cp.MerkleRoot) {
		return errors.New("presence: rebuilt root does not match checkpoint (range tampered)")
	}
	proof, err := merkle.Proof(leaves, idx)
	if err != nil {
		return err
	}
	if !merkle.VerifyProof(leaves[idx], idx, len(leaves), proof, cp.MerkleRoot) {
		return errors.New("presence: inclusion proof failed")
	}

	// The checkpoint root must be the one committed in a validly-signed audit entry.
	entry, err := s.repo.AuditEntryBySeq(ctx, cp.AuditSeq)
	if err != nil {
		return err
	}
	if err := s.verifier.VerifyEntry(entry); err != nil {
		return err
	}
	meta, err := store.ParsePresenceCheckpointTarget(entry.TargetID)
	if err != nil {
		return err
	}
	if !bytes.Equal(meta.MerkleRoot, cp.MerkleRoot) {
		return errors.New("presence: signed root does not match checkpoint root")
	}
	return nil
}

// leafBytes is the canonical, length-prefixed encoding of a presence event — the
// Merkle leaf data. Mirrors the audit/consent SignedPayload discipline so no two
// distinct events can collide. Seq is included so leaves are unique and ordered.
func leafBytes(e store.PresenceEvent) []byte {
	var b []byte
	putU64 := func(n uint64) {
		var x [8]byte
		binary.BigEndian.PutUint64(x[:], n)
		b = append(b, x[:]...)
	}
	putField := func(p string) {
		var x [4]byte
		binary.BigEndian.PutUint32(x[:], uint32(len(p)))
		b = append(b, x[:]...)
		b = append(b, p...)
	}
	putU64(uint64(e.Seq))
	putField(e.ID)
	putField(e.SessionID)
	putField(e.UserID)
	putField(e.Action)
	putField(e.Role)
	putU64(uint64(e.OccurredAt.Unix()))
	return b
}

// newID returns a 26-char Crockford-base32 opaque id (ULID-shaped, identity only).
func newID() string {
	const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var b [26]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("presence: crypto/rand unavailable: " + err.Error())
	}
	for i := range b {
		b[i] = crockford[int(b[i])%len(crockford)]
	}
	return string(b[:])
}
