package contracts

// GrantScope is the privilege level of a session (LiveKit room) grant. The
// default is the least-privilege Subscriber; Publisher/Admin are minted only
// for an authorised role, derived server-side (A-3). The server is the sole
// grant issuer.
type GrantScope string

const (
	ScopeSubscriber GrantScope = "subscriber"
	ScopePublisher  GrantScope = "publisher"
	ScopeAdmin      GrantScope = "admin"
)

// GrantRequest is the body of POST /v1/sessions/{sessionId}/grants
// (contracts §2). Note the path is keyed by sessionId: the LiveKit "room" is
// the media realisation of a session (canonical entity map), so there is no
// separate room_id.
type GrantRequest struct {
	TargetUserID string     `json:"targetUserId"`
	Scope        GrantScope `json:"scope"`
	TTLSeconds   int        `json:"ttlSeconds"` // small
}

// GrantResponse carries the minted LiveKit room token.
type GrantResponse struct {
	RoomToken string `json:"roomToken"`
	ExpiresAt int64  `json:"expiresAt"`
}

// VideoGrant mirrors the LiveKit access-token video grant minted server-side
// and consumed by LiveKit. It is short-lived and session-bound.
type VideoGrant struct {
	RoomJoin       bool   `json:"roomJoin"`
	Room           string `json:"room"` // = session id (the LiveKit room handle)
	CanSubscribe   bool   `json:"canSubscribe"`
	CanPublish     bool   `json:"canPublish"`
	CanPublishData bool   `json:"canPublishData"`
}

// VideoGrantForScope builds a least-privilege LiveKit video grant for a scope.
// Subscriber can only subscribe; Publisher/Admin may publish media and data.
// Never widen beyond what the caller's authorised scope permits (A-3).
func VideoGrantForScope(scope GrantScope, sessionRoom string) VideoGrant {
	g := VideoGrant{
		RoomJoin:     true,
		Room:         sessionRoom,
		CanSubscribe: true,
	}
	switch scope {
	case ScopePublisher, ScopeAdmin:
		g.CanPublish = true
		g.CanPublishData = true
	case ScopeSubscriber:
		// least privilege: subscribe only.
	}
	return g
}
