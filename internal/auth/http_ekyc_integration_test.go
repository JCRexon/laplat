//go:build integration

package auth_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jcrexon/laplat/internal/auth"
	"github.com/jcrexon/laplat/internal/dbtest"
	"github.com/jcrexon/laplat/internal/ekyc"
	"github.com/jcrexon/laplat/internal/identity"
	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/pkg/contracts"
	"github.com/jcrexon/laplat/pkg/token"
)

// fakeKYCClient is a stand-in eKYC vendor: Begin always succeeds.
type fakeKYCClient struct{}

func (fakeKYCClient) CreateVerification(_ context.Context, _ string) (string, string, error) {
	return "vref-1", "https://kyc.example/start", nil
}

// testEKYCBridge mirrors cmd/authd's bridge: it adapts identity.Service +
// VNVerifier to auth.EKYCService.
type testEKYCBridge struct {
	id *identity.Service
	vn *ekyc.VNVerifier
}

func (b *testEKYCBridge) BeginVerification(ctx context.Context, userID, region string) (string, string, string, error) {
	sr, err := b.id.Begin(ctx, userID, region)
	return sr.Provider, sr.Ref, sr.RedirectURL, err
}

func (b *testEKYCBridge) ApplyCallback(ctx context.Context, body []byte, sig string) error {
	res, err := b.vn.ParseCallback(body, sig)
	if err != nil {
		return auth.ErrWebhookSignature
	}
	return b.id.Apply(ctx, res)
}

// Full eKYC HTTP flow: a pending user begins verification, the vendor posts a
// signed approved-adult callback, and the user then mints a token at the
// verified tier. A bad signature is rejected.
func TestHTTP_EKYC_BeginCallbackToVerified(t *testing.T) {
	pg := dbtest.New(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pg.ConnString())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	st := store.New(pool)

	const uid = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	if _, err := st.CreateUser(ctx, store.NewUser{ID: uid, Handle: "kycer", DisplayName: "K"}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateIdentityRecord(ctx, uid); err != nil {
		t.Fatal(err)
	}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := token.NewSigner("kid-1", priv)
	minter, _ := auth.NewMinter(signer, contracts.TokenIssuer, 15*time.Minute)
	validator := token.NewValidator(token.NewVerifier(map[string]ed25519.PublicKey{"kid-1": pub}), st)
	svc, _ := auth.NewService(minter, st, 720*time.Hour)

	const secret = "wh-secret"
	vn, _ := ekyc.NewVN(fakeKYCClient{}, secret)
	idSvc, _ := identity.NewService(st, map[string]identity.Verifier{
		"default": identity.ManualVerifier{}, "VN": vn,
	})
	bridge := &testEKYCBridge{id: idSvc, vn: vn}

	h := auth.NewHandler(svc, validator)
	h.RegisterIdentity(idSvc, bridge)

	// The user holds a (pending, idv none) session token.
	sess, _ := svc.IssueSession(ctx, uid)

	// Begin verification.
	beginBody, _ := json.Marshal(map[string]string{"region": "VN"})
	req, _ := http.NewRequest("POST", "/v1/identity/verify/begin", bytes.NewReader(beginBody))
	req.Header.Set("Authorization", "Bearer "+sess.AccessToken)
	rec := newRecorder()
	h.ServeHTTP(rec, req)
	if rec.status != http.StatusOK {
		t.Fatalf("begin status = %d, want 200", rec.status)
	}

	// Vendor posts a signed approved-adult callback.
	cb, _ := json.Marshal(map[string]any{
		"correlationId": uid, "reference": "vref-1", "result": "approved", "over18": true,
	})
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(cb)
	sig := hex.EncodeToString(mac.Sum(nil))

	// A bad signature is rejected.
	bad, _ := http.NewRequest("POST", "/v1/identity/verify/callback", bytes.NewReader(cb))
	bad.Header.Set(auth.EKYCSignatureHeader, "deadbeef")
	br := newRecorder()
	h.ServeHTTP(br, bad)
	if br.status != http.StatusUnauthorized {
		t.Fatalf("bad-signature callback status = %d, want 401", br.status)
	}

	// The correctly-signed callback is accepted.
	ok, _ := http.NewRequest("POST", "/v1/identity/verify/callback", bytes.NewReader(cb))
	ok.Header.Set(auth.EKYCSignatureHeader, sig)
	okr := newRecorder()
	h.ServeHTTP(okr, ok)
	if okr.status != http.StatusNoContent {
		t.Fatalf("callback status = %d, want 204", okr.status)
	}

	// The user is now a verified adult and active; a fresh token is at the
	// verified tier.
	if u, _ := st.GetUser(ctx, uid); u.Status != "active" {
		t.Fatalf("status after verify = %q, want active", u.Status)
	}
	next, _ := svc.IssueSession(ctx, uid)
	if !next.AccessClaims.IsVerifiedAdult() {
		t.Fatalf("post-eKYC idv = %q, want verified", next.AccessClaims.IdentityVerification)
	}
}
