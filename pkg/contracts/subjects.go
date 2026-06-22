package contracts

import "fmt"

// NATS subject taxonomy (contracts §5). Clients NEVER connect to NATS (B-1);
// only backend services connect, each with subject-scoped NATS-account
// permissions. No service is granted a full wildcard (`>`).
//
// Pattern: <domain>.<entity>[.<id>].<action>
const (
	SubjectSessionStarted          = "room.session.started"
	SubjectSessionEnded            = "room.session.ended"
	SubjectRecordingAvailable      = "recording.available"
	SubjectModerationReportCreated = "moderation.report.created"
)

// ChatMessageSubject is keyed by CONVERSATION id (the persistent-messaging
// axis of the entity map), not by room/session. This matches
// messages.conversation_id in the data model. The Go chat-gateway is the only
// bridge between browser WebSockets and NATS and authorises conversation
// membership before subscribing a socket (prevents B-2 cross-room reads).
func ChatMessageSubject(conversationID string) string {
	return fmt.Sprintf("chat.conversation.%s.message", conversationID)
}

// ChatPresenceSubject is the presence subject for a conversation. Presence is
// ephemeral and never stored.
func ChatPresenceSubject(conversationID string) string {
	return fmt.Sprintf("chat.conversation.%s.presence", conversationID)
}
