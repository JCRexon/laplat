package contracts

import (
	"encoding/hex"
	"encoding/json"
	"sort"
	"testing"
)

// These golden tests lock the WIRE SHAPE of the frozen contracts. If a change
// to a contract type alters the JSON keys, the canonical consent encoding, or a
// NATS subject string, one of these fails loudly — operationalising the
// "ask before changing a frozen contract" rule. Update a golden only as a
// deliberate, reviewed contract change.

// The access-token claim key set is frozen. Note `caps` (global capabilities),
// NOT `roles`, and no PII-bearing keys.
func TestGolden_AccessTokenClaimKeys(t *testing.T) {
	b, err := json.Marshal(AccessTokenClaims{})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(m))
	for k := range m {
		got = append(got, k)
	}
	sort.Strings(got)

	want := []string{"caps", "exp", "iat", "idv", "iss", "jti", "sub", "sver", "tver"}
	if len(got) != len(want) {
		t.Fatalf("claim key set changed:\n got=%v\nwant=%v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("claim key set changed:\n got=%v\nwant=%v", got, want)
		}
	}
}

// The canonical, length-prefixed consent encoding is frozen — it is what the
// server signature and the hash chain cover (A-2). A change here would silently
// invalidate every previously signed record.
func TestGolden_ConsentSignedPayload(t *testing.T) {
	r := ConsentRecord{
		SchemaVersion: 1,
		ID:            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		PrevHash:      []byte{0xde, 0xad, 0xbe, 0xef},
		SessionID:     "01BX5ZZKBKACTAV9WEVGEMMVRZ",
		SubjectID:     "01CX5ZZKBKACTAV9WEVGEMMVRZ",
		Purpose:       ConsentPurposeSessionRecording,
		Granted:       true,
		GrantedAt:     1700000000,
		SigningKeyID:  "k1",
	}
	const want = "000000010000001a303141525a334e44454b5453563452524646513639473546415600000004deadbeef0000001a30314258355a5a4b424b41435441563957455647454d4d56525a0000001a30314358355a5a4b424b41435441563957455647454d4d56525a0000001173657373696f6e5f7265636f7264696e6701000000006553f100000000026b31"
	if got := hex.EncodeToString(r.SignedPayload()); got != want {
		t.Fatalf("canonical consent encoding changed:\n got=%s\nwant=%s", got, want)
	}
}

// NATS subject strings are frozen: chat is keyed by conversation id (entity
// map), and ids embedded in subjects must be subject-safe (validated by the
// caller — see pkg/validate.SubjectToken).
func TestGolden_Subjects(t *testing.T) {
	cases := map[string]string{
		ChatMessageSubject("CONV"):     "chat.conversation.CONV.message",
		ChatPresenceSubject("CONV"):    "chat.conversation.CONV.presence",
		SubjectSessionStarted:          "room.session.started",
		SubjectSessionEnded:            "room.session.ended",
		SubjectRecordingAvailable:      "recording.available",
		SubjectModerationReportCreated: "moderation.report.created",
	}
	for got, want := range cases {
		if got != want {
			t.Fatalf("subject changed: got=%q want=%q", got, want)
		}
	}
}
