package contracts

import (
	"bytes"
	"testing"
)

// The consent boolean MUST be covered by the signature — flipping Granted must
// change the signed bytes (the flaw in the earlier spec was signing a tuple
// that omitted Granted).
func TestThreat_A2_ConsentSignatureCoversGranted(t *testing.T) {
	base := ConsentRecord{
		SchemaVersion: ConsentSchemaVersion,
		ID:            "01JCONSENT",
		PrevHash:      []byte{0x01, 0x02},
		SessionID:     "sess-1",
		SubjectID:     "user-1",
		Purpose:       ConsentPurposeSessionRecording,
		Granted:       true,
		GrantedAt:     1700000000,
		SigningKeyID:  "kid-1",
	}
	flipped := base
	flipped.Granted = false
	if bytes.Equal(base.SignedPayload(), flipped.SignedPayload()) {
		t.Fatal("signed payload must change when Granted flips (consent integrity)")
	}
}

func TestConsentSignedPayloadDeterministic(t *testing.T) {
	r := ConsentRecord{
		ID:        "x",
		SessionID: "s",
		SubjectID: "u",
		Purpose:   ConsentPurposeSessionRecording,
		Granted:   true,
		GrantedAt: 1,
	}
	if !bytes.Equal(r.SignedPayload(), r.SignedPayload()) {
		t.Fatal("canonical encoding must be deterministic")
	}
}

// Length-prefixing must prevent two different field partitions producing the
// same bytes (field-injection / canonicalisation forgery).
func TestThreat_A2_ConsentEncodingNoFieldInjection(t *testing.T) {
	a := ConsentRecord{SessionID: "ab", SubjectID: "c"}
	b := ConsentRecord{SessionID: "a", SubjectID: "bc"}
	if bytes.Equal(a.SignedPayload(), b.SignedPayload()) {
		t.Fatal("length-prefixed encoding must prevent field-boundary ambiguity")
	}
}

func TestThreat_A3_GrantLeastPrivilege(t *testing.T) {
	sub := VideoGrantForScope(ScopeSubscriber, "sess-1")
	if sub.CanPublish || sub.CanPublishData {
		t.Error("subscriber must not be able to publish media or data (A-3 least privilege)")
	}
	if !sub.CanSubscribe || !sub.RoomJoin {
		t.Error("subscriber must be able to join and subscribe")
	}
	pub := VideoGrantForScope(ScopePublisher, "sess-1")
	if !pub.CanPublish {
		t.Error("publisher must be able to publish")
	}
}

func TestHasCapability(t *testing.T) {
	c := AccessTokenClaims{Capabilities: []Capability{CapCanInstruct}}
	if !c.HasCapability(CapCanInstruct) {
		t.Error("expected can_instruct capability")
	}
	if c.HasCapability(CapPlatformModerator) {
		t.Error("did not expect platform_moderator capability")
	}
}
