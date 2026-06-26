package recording

import (
	"context"
	"errors"
	"testing"

	"github.com/jcrexon/laplat/internal/livekit"
	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/pkg/contracts"
)

// fakeRepo is an in-memory Repo tracking enough state to exercise the gate and
// the single-in-flight invariant.
type fakeRepo struct {
	session store.Session
	parts   []store.SessionParticipant
	allowed bool
	recs    map[string]*store.Recording // by id
	seq     int
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		session: store.Session{ID: "S1", LivekitRoom: "ses_S1", Status: "live"},
		parts: []store.SessionParticipant{
			{SessionID: "S1", UserID: "host-1", Role: "host"},
		},
		recs: map[string]*store.Recording{},
	}
}

func (f *fakeRepo) GetSession(_ context.Context, id string) (store.Session, error) {
	if f.session.ID == id {
		return f.session, nil
	}
	return store.Session{}, errors.New("not found")
}
func (f *fakeRepo) ListActiveParticipants(_ context.Context, _ string) ([]store.SessionParticipant, error) {
	return f.parts, nil
}
func (f *fakeRepo) RecordingAllowed(_ context.Context, _ string) (bool, error) {
	return f.allowed, nil
}
func (f *fakeRepo) CreateRecording(_ context.Context, id, sessionID, status string) error {
	for _, r := range f.recs {
		if r.SessionID == sessionID && isInFlight(r.Status) {
			return errors.New("unique violation: one active per session")
		}
	}
	f.seq++
	f.recs[id] = &store.Recording{ID: id, SessionID: sessionID, Status: status}
	return nil
}
func (f *fakeRepo) SetRecordingEgress(_ context.Context, id, egressID, status string) error {
	r := f.recs[id]
	r.EgressID, r.Status = egressID, status
	return nil
}
func (f *fakeRepo) UpdateRecordingStatus(_ context.Context, id, status string, _ bool, outputURI, errMsg *string) error {
	r := f.recs[id]
	r.Status = status
	if outputURI != nil {
		r.OutputURI = *outputURI
	}
	if errMsg != nil {
		r.Error = *errMsg
	}
	return nil
}
func (f *fakeRepo) ActiveRecording(_ context.Context, sessionID string) (store.Recording, bool, error) {
	for _, r := range f.recs {
		if r.SessionID == sessionID && isInFlight(r.Status) {
			return *r, true, nil
		}
	}
	return store.Recording{}, false, nil
}
func (f *fakeRepo) RecordingsBySession(_ context.Context, sessionID string) ([]store.Recording, error) {
	var out []store.Recording
	for _, r := range f.recs {
		if r.SessionID == sessionID {
			out = append(out, *r)
		}
	}
	return out, nil
}

func isInFlight(s string) bool {
	return s == StatusStarting || s == StatusActive || s == StatusStopping
}

// fakeEgress records calls and returns a canned status.
type fakeEgress struct {
	started, stopped int
	startStatus      string
	startErr         error
	stopStatus       string
}

func (e *fakeEgress) StartRoomComposite(_ context.Context, _ string) (*livekit.EgressInfo, error) {
	e.started++
	if e.startErr != nil {
		return nil, e.startErr
	}
	return &livekit.EgressInfo{EgressID: "EG_1", Status: e.startStatus}, nil
}
func (e *fakeEgress) StopEgress(_ context.Context, _ string) (*livekit.EgressInfo, error) {
	e.stopped++
	return &livekit.EgressInfo{EgressID: "EG_1", Status: e.stopStatus}, nil
}

func hostClaims() *contracts.AccessTokenClaims {
	return &contracts.AccessTokenClaims{Subject: "host-1"}
}
func otherClaims() *contracts.AccessTokenClaims {
	return &contracts.AccessTokenClaims{Subject: "rando"}
}

func newSvc(t *testing.T, repo *fakeRepo, eg *fakeEgress) *Service {
	t.Helper()
	s, err := NewService(repo, eg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Start is blocked by the consent gate and never reaches egress.
func TestStart_BlockedWithoutConsent(t *testing.T) {
	repo := newFakeRepo()
	repo.allowed = false
	eg := &fakeEgress{startStatus: livekit.EgressActive}
	svc := newSvc(t, repo, eg)

	_, err := svc.Start(context.Background(), hostClaims(), "S1")
	if !errors.Is(err, ErrConsentRequired) {
		t.Fatalf("err = %v, want ErrConsentRequired", err)
	}
	if eg.started != 0 {
		t.Fatal("egress must not be called when consent gate fails")
	}
}

// Start succeeds when the gate passes: egress is started and the row goes active.
func TestStart_Records(t *testing.T) {
	repo := newFakeRepo()
	repo.allowed = true
	eg := &fakeEgress{startStatus: livekit.EgressActive}
	svc := newSvc(t, repo, eg)

	rec, err := svc.Start(context.Background(), hostClaims(), "S1")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if eg.started != 1 {
		t.Fatalf("egress started %d times, want 1", eg.started)
	}
	if rec.EgressID != "EG_1" || rec.Status != StatusActive {
		t.Fatalf("rec = %+v", rec)
	}
}

// Only the host may start a recording.
func TestStart_HostOnly(t *testing.T) {
	repo := newFakeRepo()
	repo.allowed = true
	svc := newSvc(t, repo, &fakeEgress{startStatus: livekit.EgressActive})
	if _, err := svc.Start(context.Background(), otherClaims(), "S1"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
}

// A second start while one is in flight is rejected.
func TestStart_AlreadyRecording(t *testing.T) {
	repo := newFakeRepo()
	repo.allowed = true
	svc := newSvc(t, repo, &fakeEgress{startStatus: livekit.EgressActive})
	if _, err := svc.Start(context.Background(), hostClaims(), "S1"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Start(context.Background(), hostClaims(), "S1"); !errors.Is(err, ErrAlreadyRecording) {
		t.Fatalf("err = %v, want ErrAlreadyRecording", err)
	}
}

// If egress refuses, the row is marked failed so the session is recordable again.
func TestStart_EgressFailureMarksFailed(t *testing.T) {
	repo := newFakeRepo()
	repo.allowed = true
	eg := &fakeEgress{startErr: errors.New("egress down")}
	svc := newSvc(t, repo, eg)

	if _, err := svc.Start(context.Background(), hostClaims(), "S1"); err == nil {
		t.Fatal("expected egress error")
	}
	if _, ok, _ := repo.ActiveRecording(context.Background(), "S1"); ok {
		t.Fatal("a failed start must leave no in-flight recording")
	}
}

// Stop asks egress to stop and records the terminal status.
func TestStop(t *testing.T) {
	repo := newFakeRepo()
	repo.allowed = true
	eg := &fakeEgress{startStatus: livekit.EgressActive, stopStatus: livekit.EgressComplete}
	svc := newSvc(t, repo, eg)
	if _, err := svc.Start(context.Background(), hostClaims(), "S1"); err != nil {
		t.Fatal(err)
	}
	if err := svc.Stop(context.Background(), hostClaims(), "S1"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if eg.stopped != 1 {
		t.Fatalf("egress stopped %d times, want 1", eg.stopped)
	}
	if _, ok, _ := repo.ActiveRecording(context.Background(), "S1"); ok {
		t.Fatal("after stop there should be no in-flight recording")
	}
}

// Stop with nothing recording is a conflict, not a crash.
func TestStop_NotRecording(t *testing.T) {
	repo := newFakeRepo()
	svc := newSvc(t, repo, &fakeEgress{})
	if err := svc.Stop(context.Background(), hostClaims(), "S1"); !errors.Is(err, ErrNotRecording) {
		t.Fatalf("err = %v, want ErrNotRecording", err)
	}
}

// D-2: when consent is withdrawn (gate flips false), reconciliation stops the
// in-flight recording — and it is NOT host-gated.
func TestReconcile_StopsOnWithdrawal(t *testing.T) {
	repo := newFakeRepo()
	repo.allowed = true
	eg := &fakeEgress{startStatus: livekit.EgressActive, stopStatus: livekit.EgressComplete}
	svc := newSvc(t, repo, eg)
	if _, err := svc.Start(context.Background(), hostClaims(), "S1"); err != nil {
		t.Fatal(err)
	}

	// Someone withdraws — gate now fails.
	repo.allowed = false
	if err := svc.ReconcileForSession(context.Background(), "S1"); err != nil {
		t.Fatalf("ReconcileForSession: %v", err)
	}
	if eg.stopped != 1 {
		t.Fatalf("egress stopped %d times, want 1 (D-2 withdrawal)", eg.stopped)
	}
	if _, ok, _ := repo.ActiveRecording(context.Background(), "S1"); ok {
		t.Fatal("reconciliation must stop the in-flight recording")
	}
}

// Reconcile is a no-op when consent still holds.
func TestReconcile_NoopWhenAllowed(t *testing.T) {
	repo := newFakeRepo()
	repo.allowed = true
	eg := &fakeEgress{startStatus: livekit.EgressActive}
	svc := newSvc(t, repo, eg)
	if _, err := svc.Start(context.Background(), hostClaims(), "S1"); err != nil {
		t.Fatal(err)
	}
	if err := svc.ReconcileForSession(context.Background(), "S1"); err != nil {
		t.Fatal(err)
	}
	if eg.stopped != 0 {
		t.Fatal("reconcile must not stop a still-consented recording")
	}
}
