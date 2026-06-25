//go:build integration

package store_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jcrexon/laplat/internal/audit"
	"github.com/jcrexon/laplat/internal/consent"
	"github.com/jcrexon/laplat/internal/dbtest"
	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/pkg/contracts"
)

// newConsentStore boots Postgres, a signer-enabled store, a verifier over the
// same key, and seeds the users the consent tests act on.
func newConsentStore(t *testing.T) (*store.Store, *pgxpool.Pool, *consent.Verifier, context.Context) {
	t.Helper()
	pg := dbtest.New(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pg.ConnString())
	if err != nil {
		t.Fatalf("connect pool: %v", err)
	}
	t.Cleanup(pool.Close)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := audit.NewSigner("kid-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	v := consent.NewVerifier(map[string]ed25519.PublicKey{"kid-1": pub})
	st := store.New(pool, store.WithAuditSigner(signer))

	for _, id := range []string{userA, userB} {
		if _, err := st.CreateUser(ctx, store.NewUser{ID: id, Handle: "h" + id[:4], DisplayName: "n"}); err != nil {
			t.Fatalf("seed user %s: %v", id, err)
		}
	}
	return st, pool, v, ctx
}

func grant(t *testing.T, st *store.Store, ctx context.Context, id, subject string, granted bool) {
	t.Helper()
	if err := st.AppendConsent(ctx, store.ConsentInput{
		ID: id, SessionID: "S1", SubjectID: subject,
		Purpose: contracts.ConsentPurposeSessionRecording, Granted: granted,
	}); err != nil {
		t.Fatalf("AppendConsent: %v", err)
	}
}

// Appends build a chained, signed, verifiable ledger and effective consent is
// latest-wins (a withdrawal flips it back off).
func TestConsent_AppendsChainAndLatestWins(t *testing.T) {
	st, _, v, ctx := newConsentStore(t)

	grant(t, st, ctx, "rec-1", userA, true)
	if ok, err := st.EffectiveConsent(ctx, userA, "S1", contracts.ConsentPurposeSessionRecording); err != nil || !ok {
		t.Fatalf("after grant: ok=%v err=%v, want true", ok, err)
	}

	grant(t, st, ctx, "rec-2", userA, false) // withdrawal
	if ok, err := st.EffectiveConsent(ctx, userA, "S1", contracts.ConsentPurposeSessionRecording); err != nil || ok {
		t.Fatalf("after withdrawal: ok=%v err=%v, want false", ok, err)
	}

	// No record at all reads as not-consented.
	if ok, _ := st.EffectiveConsent(ctx, userB, "S1", contracts.ConsentPurposeSessionRecording); ok {
		t.Fatal("userB never consented, want false")
	}

	records, err := st.ConsentRecords(ctx)
	if err != nil {
		t.Fatalf("ConsentRecords: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}
	if err := v.VerifyChain(records); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
}

// RecordingAllowed requires every present participant's latest consent granted;
// one non-consenting active participant blocks it, and leaving unblocks it.
func TestConsent_RecordingAllowed(t *testing.T) {
	st, _, _, ctx := newConsentStore(t)
	if _, err := st.CreateSession(ctx, store.NewSession{ID: "S1", Kind: "direct", LivekitRoom: "room-1"}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddParticipant(ctx, "S1", userA, "participant"); err != nil {
		t.Fatal(err)
	}
	if err := st.AddParticipant(ctx, "S1", userB, "participant"); err != nil {
		t.Fatal(err)
	}

	// Nobody has consented yet.
	if ok, err := st.RecordingAllowed(ctx, "S1"); err != nil || ok {
		t.Fatalf("no consent: ok=%v err=%v, want false", ok, err)
	}

	// Only A consents — B is still present and silent, so still blocked.
	grant(t, st, ctx, "rec-1", userA, true)
	if ok, _ := st.RecordingAllowed(ctx, "S1"); ok {
		t.Fatal("one participant silent, want false")
	}

	// Both consent — allowed.
	grant(t, st, ctx, "rec-2", userB, true)
	if ok, err := st.RecordingAllowed(ctx, "S1"); err != nil || !ok {
		t.Fatalf("both consented: ok=%v err=%v, want true", ok, err)
	}

	// B withdraws while present — must stop (D-2).
	grant(t, st, ctx, "rec-3", userB, false)
	if ok, _ := st.RecordingAllowed(ctx, "S1"); ok {
		t.Fatal("withdrawal must block, want false")
	}

	// B leaves — only consenting A remains, so allowed again.
	if err := st.RemoveParticipant(ctx, "S1", userB); err != nil {
		t.Fatal(err)
	}
	if ok, err := st.RecordingAllowed(ctx, "S1"); err != nil || !ok {
		t.Fatalf("after B leaves: ok=%v err=%v, want true", ok, err)
	}
}

// The consent ledger is append-only at the database boundary.
func TestConsent_ImmutableAtDB(t *testing.T) {
	st, pool, _, ctx := newConsentStore(t)
	grant(t, st, ctx, "rec-1", userA, true)

	if _, err := pool.Exec(ctx, `UPDATE consent_records SET granted = false WHERE seq = 1`); err == nil {
		t.Fatal("UPDATE on consent_records should be blocked")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM consent_records WHERE seq = 1`); err == nil {
		t.Fatal("DELETE on consent_records should be blocked")
	}
}

// Without a signer, AppendConsent refuses rather than writing an unsigned row.
func TestConsent_RequiresSigner(t *testing.T) {
	pg := dbtest.New(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pg.ConnString())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	pg.MustExec(`INSERT INTO users (id, handle, display_name) VALUES ('` + userA + `', 'an', 'An');`)

	st := store.New(pool) // no WithAuditSigner
	err = st.AppendConsent(ctx, store.ConsentInput{
		ID: "rec-1", SessionID: "S1", SubjectID: userA,
		Purpose: contracts.ConsentPurposeSessionRecording, Granted: true,
	})
	if err == nil {
		t.Fatal("expected ErrNoAuditSigner, got nil")
	}
}
