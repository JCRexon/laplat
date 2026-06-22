package contracts

import "encoding/binary"

// ConsentSchemaVersion versions the canonical encoding of a consent record.
const ConsentSchemaVersion = 1

// ConsentPurpose enumerates the lawful processing purposes a consent record
// can cover. Each purpose is consented separately.
type ConsentPurpose string

const ConsentPurposeSessionRecording ConsentPurpose = "session_recording"

// ConsentRecord is an append-only, hash-chained, server-signed consent entry
// (contracts §3; A-2 / D-2 / X-4).
//
// Security-first decisions encoded here:
//   - The signature covers EVERY meaningful field — crucially Granted. The
//     earlier spec signed a tuple that omitted Granted, leaving the actual
//     consent boolean unauthenticated.
//   - The signed bytes use a canonical, length-prefixed encoding
//     (SignedPayload) rather than delimiter concatenation, which would be
//     vulnerable to field-injection / canonicalisation forgery.
//   - The record is keyed by SessionID only; there is no room_id (a consent is
//     for recording a session; the LiveKit room is just a handle).
//   - SigningKeyID records the key used, so rotation does not break
//     verification of older records (A-2 / G-2).
//
// Effective consent is the LATEST record per (SubjectID, SessionID, Purpose).
// Withdrawal (PDPL) is a new Granted=false record, never an UPDATE or DELETE;
// storage is insert-only. The Egress recording gate must not start — and must
// stop — when the latest effective record is Granted=false (D-2).
type ConsentRecord struct {
	SchemaVersion int            `json:"sver"`
	ID            string         `json:"id"`       // ULID
	PrevHash      []byte         `json:"prevHash"` // hash of the previous record (chain)
	SessionID     string         `json:"sessionId"`
	SubjectID     string         `json:"subjectId"` // the consenting user
	Purpose       ConsentPurpose `json:"purpose"`
	Granted       bool           `json:"granted"`
	GrantedAt     int64          `json:"grantedAt"` // unix
	SigningKeyID  string         `json:"kid"`       // key id for rotation-safe verify
	Signature     []byte         `json:"signature"` // server sig over SignedPayload()
}

// SignedPayload returns the canonical bytes the server signs and that the
// chain hashes. Every field is length-prefixed so no combination of field
// values can be re-partitioned into a different record with the same bytes.
// The Signature field itself is excluded (it signs this payload).
func (c ConsentRecord) SignedPayload() []byte {
	var b []byte
	putUint32 := func(n uint32) {
		var x [4]byte
		binary.BigEndian.PutUint32(x[:], n)
		b = append(b, x[:]...)
	}
	putField := func(p []byte) {
		putUint32(uint32(len(p)))
		b = append(b, p...)
	}

	putUint32(uint32(c.SchemaVersion))
	putField([]byte(c.ID))
	putField(c.PrevHash)
	putField([]byte(c.SessionID))
	putField([]byte(c.SubjectID))
	putField([]byte(c.Purpose))
	if c.Granted {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	var t [8]byte
	binary.BigEndian.PutUint64(t[:], uint64(c.GrantedAt))
	b = append(b, t[:]...)
	putField([]byte(c.SigningKeyID))
	return b
}
