//go:build integration

package session_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jcrexon/laplat/internal/dbtest"
	"github.com/jcrexon/laplat/internal/livekit"
	"github.com/jcrexon/laplat/internal/session"
	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/pkg/contracts"
)

func newSvc(t *testing.T) (*session.Service, *store.Store, context.Context) {
	t.Helper()
	pg := dbtest.New(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pg.ConnString())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	st := store.New(pool)
	granter, _ := livekit.NewGranter("APIkey", "secret", 10*time.Minute)
	svc, err := session.NewService(st, granter, "wss://media.test")
	if err != nil {
		t.Fatal(err)
	}
	return svc, st, ctx
}

// mkUser inserts a user so participant FKs resolve, and returns claims at the
// given tier with optional capabilities.
func mkUser(t *testing.T, st *store.Store, ctx context.Context, id string, idv contracts.IdentityVerificationState, caps ...contracts.Capability) *contracts.AccessTokenClaims {
	t.Helper()
	if _, err := st.CreateUser(ctx, store.NewUser{ID: id, Handle: id, DisplayName: id, CanInstruct: hasCap(caps, contracts.CapCanInstruct)}); err != nil {
		t.Fatal(err)
	}
	return &contracts.AccessTokenClaims{Subject: id, IdentityVerification: idv, Capabilities: caps}
}

// mkClass inserts a class owned by instructorID and returns its id.
func mkClass(t *testing.T, st *store.Store, ctx context.Context, id, instructorID string) string {
	t.Helper()
	if _, err := st.CreateClass(ctx, store.NewClass{ID: id, InstructorID: instructorID, Title: "C"}); err != nil {
		t.Fatal(err)
	}
	return id
}

func hasCap(caps []contracts.Capability, want contracts.Capability) bool {
	for _, c := range caps {
		if c == want {
			return true
		}
	}
	return false
}

// canPublish decodes the LiveKit token and reports its grant's canPublish.
func canPublish(t *testing.T, tok string) bool {
	t.Helper()
	parts := strings.Split(tok, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c struct {
		Video struct {
			CanPublish bool `json:"canPublish"`
		} `json:"video"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatal(err)
	}
	return c.Video.CanPublish
}

// An instructor (phone_verified + can_instruct) creates a class, joins as host
// with publish rights, and can start it; a phone_verified learner joins as a
// subscribe-only participant.
func TestSession_ClassHostAndParticipant(t *testing.T) {
	svc, st, ctx := newSvc(t)
	host := mkUser(t, st, ctx, "host1", contracts.IdentityPhoneVerified, contracts.CapCanInstruct)
	learner := mkUser(t, st, ctx, "learner1", contracts.IdentityPhoneVerified)
	classID := mkClass(t, st, ctx, "class-1", "host1")

	sess, err := svc.CreateSession(ctx, host, "class", &classID, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	hj, err := svc.Join(ctx, host, sess.ID)
	if err != nil {
		t.Fatalf("host join: %v", err)
	}
	if hj.Role != session.RoleHost || !canPublish(t, hj.Token) {
		t.Fatalf("host: role=%q canPublish=%v", hj.Role, canPublish(t, hj.Token))
	}
	if err := svc.Start(ctx, host, sess.ID); err != nil {
		t.Fatalf("host start: %v", err)
	}

	lj, err := svc.Join(ctx, learner, sess.ID)
	if err != nil {
		t.Fatalf("learner join: %v", err)
	}
	if lj.Role != session.RoleParticipant || canPublish(t, lj.Token) {
		t.Fatalf("learner should be subscribe-only participant: role=%q canPublish=%v", lj.Role, canPublish(t, lj.Token))
	}
	// A learner cannot start/end the class.
	if err := svc.Start(ctx, learner, sess.ID); err != session.ErrForbidden {
		t.Fatalf("learner start err = %v, want ErrForbidden", err)
	}
}

// Tier gating: a declared-only user cannot create a class/direct or join.
func TestSession_TierGating(t *testing.T) {
	svc, st, ctx := newSvc(t)
	instructor := mkUser(t, st, ctx, "host2", contracts.IdentityPhoneVerified, contracts.CapCanInstruct)
	declared := mkUser(t, st, ctx, "declared2", contracts.IdentityDeclared)
	classID := mkClass(t, st, ctx, "class-2", "host2")

	sess, _ := svc.CreateSession(ctx, instructor, "class", &classID, nil)

	if _, err := svc.CreateSession(ctx, declared, "direct", nil, nil); err != session.ErrForbidden {
		t.Fatalf("declared create direct err = %v, want ErrForbidden", err)
	}
	if _, err := svc.Join(ctx, declared, sess.ID); err != session.ErrForbidden {
		t.Fatalf("declared join err = %v, want ErrForbidden", err)
	}

	// A phone-verified but non-instructor user cannot host a class...
	noInstruct := mkUser(t, st, ctx, "noinstr2", contracts.IdentityPhoneVerified)
	if _, err := svc.CreateSession(ctx, noInstruct, "class", &classID, nil); err != session.ErrForbidden {
		t.Fatalf("non-instructor class err = %v, want ErrForbidden", err)
	}
	// ...but can create a 1:1 direct session.
	if _, err := svc.CreateSession(ctx, noInstruct, "direct", nil, nil); err != nil {
		t.Fatalf("non-instructor direct create: %v", err)
	}
}

// A scheduled class session is discoverable via ListForClass (declared tier),
// carrying its scheduled start; a none-tier user cannot list.
func TestSession_ScheduleAndDiscover(t *testing.T) {
	svc, st, ctx := newSvc(t)
	host := mkUser(t, st, ctx, "host4", contracts.IdentityPhoneVerified, contracts.CapCanInstruct)
	classID := mkClass(t, st, ctx, "class-4", "host4")
	when := time.Now().Add(24 * time.Hour).Truncate(time.Second)

	if _, err := svc.CreateSession(ctx, host, "class", &classID, &when); err != nil {
		t.Fatalf("create scheduled: %v", err)
	}

	// A declared (browsing) learner can discover the class's sessions.
	learner := mkUser(t, st, ctx, "learner4", contracts.IdentityDeclared)
	list, err := svc.ListForClass(ctx, learner, classID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || list[0].ScheduledStart == nil || !list[0].ScheduledStart.Equal(when) {
		t.Fatalf("scheduled session not listed correctly: %+v", list)
	}

	// A none-tier user (no attestation) cannot list.
	none := mkUser(t, st, ctx, "none4", contracts.IdentityNone)
	if _, err := svc.ListForClass(ctx, none, classID); err != session.ErrForbidden {
		t.Fatalf("none-tier list err = %v, want ErrForbidden", err)
	}
}

// In a direct (1:1) session both peers publish, and the DB caps occupancy at two.
func TestSession_DirectPublishAndCap(t *testing.T) {
	svc, st, ctx := newSvc(t)
	a := mkUser(t, st, ctx, "a3", contracts.IdentityPhoneVerified)
	b := mkUser(t, st, ctx, "b3", contracts.IdentityPhoneVerified)
	c := mkUser(t, st, ctx, "c3", contracts.IdentityPhoneVerified)

	sess, err := svc.CreateSession(ctx, a, "direct", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	aj, _ := svc.Join(ctx, a, sess.ID)
	if !canPublish(t, aj.Token) {
		t.Fatal("direct peer A should publish")
	}
	bj, err := svc.Join(ctx, b, sess.ID)
	if err != nil || !canPublish(t, bj.Token) {
		t.Fatalf("direct peer B: err=%v canPublish=%v", err, canPublish(t, bj.Token))
	}
	// Third participant exceeds the 1:1 cap (enforced by the DB trigger).
	if _, err := svc.Join(ctx, c, sess.ID); err == nil {
		t.Fatal("third participant should be rejected by the direct-session cap")
	}
}
