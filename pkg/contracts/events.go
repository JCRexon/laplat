package contracts

// EventSchemaVersion versions the NATS event payloads below (contracts §4).
const EventSchemaVersion = 1

// SessionStarted is emitted by the room service when a session goes live.
// Consumed asynchronously by the Egress worker (C and D never call each other
// synchronously).
type SessionStarted struct {
	SchemaVersion int      `json:"sver"`
	Event         string   `json:"event"` // "session.started"
	SessionID     string   `json:"sessionId"`
	StartedAt     int64    `json:"startedAt"`
	Participants  []string `json:"participants"`

	// ConsentSatisfied is ADVISORY only. The Egress worker MUST re-verify the
	// consent ledger directly (contracts §3) before recording and must not
	// trust this flag alone (D-2 / X-4).
	ConsentSatisfied bool `json:"consentSatisfied"`
}

// SessionEnded is emitted when a session ends.
type SessionEnded struct {
	SchemaVersion int    `json:"sver"`
	Event         string `json:"event"` // "session.ended"
	SessionID     string `json:"sessionId"`
	EndedAt       int64  `json:"endedAt"`
}

// RecordingAvailable is emitted by the Egress worker after a recording is
// written to object storage.
type RecordingAvailable struct {
	SchemaVersion int    `json:"sver"`
	SessionID     string `json:"sessionId"`
	ObjectRef     string `json:"objectRef"` // s3://... (in-country MinIO)
	DurationS     int    `json:"durationS"`
	CreatedAt     int64  `json:"createdAt"`
}
