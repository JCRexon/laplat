package contracts

import "encoding/binary"

// AuditSchemaVersion versions the canonical encoding of an audit entry. Bump it
// only with a corresponding change to AuditEntry.SignedPayload.
const AuditSchemaVersion = 1

// AuditHashLen is the length of an entry hash / prev_hash (SHA-256).
const AuditHashLen = 32

// AuditAction names a privileged action. Actions are an open set: a new audited
// action is a new constant here plus a call to the audited store method — no
// schema or infrastructure change. See AUDIT.md.
type AuditAction string

const (
	ActionUserSuspended       AuditAction = "user.suspended"
	ActionUserReinstated      AuditAction = "user.reinstated"
	ActionInstructorGranted   AuditAction = "instructor.granted"
	ActionInstructorRevoked   AuditAction = "instructor.revoked"
	ActionInstructorSelfGrant AuditAction = "instructor.self_granted"
	// ActionPresenceCheckpoint records a Merkle root over a range of presence
	// events, anchoring the high-volume presence trail into this signed chain
	// (ADR-010). A system action; target_id carries the root and covered range.
	ActionPresenceCheckpoint AuditAction = "presence.checkpoint"
	// ActionRecordingPlayed records that a user was authorised to fetch a
	// recording's bytes (ADR-011) — the "who accessed which recording" trail.
	// Written at the serving-authz check, deduped to once per playback grant.
	// actor = the viewer (role "self"); target = the recording.
	ActionRecordingPlayed AuditAction = "recording.played"
	// ActionEntitlementGranted / ...Revoked record a change to who owns access to
	// paid content (ADR-013) — the money-path trail (comp/support today, a payment
	// provider later). actor = the grantor/revoker; target_id encodes the grantee
	// and resource as "<subject>:<resourceType>:<resourceID>".
	ActionEntitlementGranted AuditAction = "entitlement.granted"
	ActionEntitlementRevoked AuditAction = "entitlement.revoked"
)

// Audit actor roles — the authority under which an action was taken.
const (
	AuditRoleModerator = "platform_moderator"
	AuditRoleSelf      = "self"
	AuditRoleSystem    = "system"
)

// AuditEntry is one tamper-evident record in the audit log. It is append-only,
// chained to its predecessor by PrevHash, and server-signed over EntryHash.
// Effective ordering is by Seq (assigned by the store on insert).
//
// The discipline mirrors ConsentRecord: every meaningful field is length-
// prefixed into SignedPayload so no two distinct entries can produce the same
// signed bytes, and the signature covers the hash of that payload.
type AuditEntry struct {
	SchemaVersion int         `json:"sver"`
	Seq           int64       `json:"seq"`
	OccurredAt    int64       `json:"occurredAt"` // unix seconds
	ActorID       string      `json:"actorId"`    // "" for system actions
	ActorRole     string      `json:"actorRole"`
	Action        AuditAction `json:"action"`
	TargetType    string      `json:"targetType"`
	TargetID      string      `json:"targetId"`
	Metadata      []byte      `json:"metadata"` // canonical JSON ("{}" when empty)

	PrevHash     []byte `json:"prevHash"`
	EntryHash    []byte `json:"entryHash"`
	SigningKeyID string `json:"kid"`
	Signature    []byte `json:"signature"`
}

// SignedPayload returns the canonical bytes that EntryHash is computed over and
// that the server signature (indirectly, via the hash) authenticates. Every
// field is length-prefixed; PrevHash is included so the hash chains. Seq,
// EntryHash and Signature are excluded: Seq is storage-assigned, and the latter
// two are derived from these bytes.
func (e AuditEntry) SignedPayload() []byte {
	var b []byte
	putUint32 := func(n uint32) {
		var x [4]byte
		binary.BigEndian.PutUint32(x[:], n)
		b = append(b, x[:]...)
	}
	putUint64 := func(n uint64) {
		var x [8]byte
		binary.BigEndian.PutUint64(x[:], n)
		b = append(b, x[:]...)
	}
	putField := func(p []byte) {
		putUint32(uint32(len(p)))
		b = append(b, p...)
	}

	putUint32(uint32(e.SchemaVersion))
	putUint64(uint64(e.OccurredAt))
	putField([]byte(e.ActorID))
	putField([]byte(e.ActorRole))
	putField([]byte(e.Action))
	putField([]byte(e.TargetType))
	putField([]byte(e.TargetID))
	putField(e.Metadata)
	putField(e.PrevHash)
	putField([]byte(e.SigningKeyID))
	return b
}
