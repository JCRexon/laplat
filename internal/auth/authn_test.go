package auth_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/jcrexon/laplat/internal/auth"
	"github.com/jcrexon/laplat/pkg/contracts"
	"github.com/jcrexon/laplat/pkg/token"
)

// stubRepo satisfies SessionRepo with no behaviour; any method call panics
// (nil embedded interface), which lets a test assert IssueSession was NOT
// reached on the paths that should short-circuit before it.
type stubRepo struct{ auth.SessionRepo }

func newAuthenticator(t *testing.T) *auth.Authenticator {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := token.NewSigner("k1", priv)
	if err != nil {
		t.Fatal(err)
	}
	minter, err := auth.NewMinter(signer, contracts.TokenIssuer, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := auth.NewService(minter, stubRepo{}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	a, err := auth.NewAuthenticator(svc)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// A principal whose kind has no registered resolver is refused before any
// session work — the dispatch guard.
func TestAuthenticate_UnknownKind(t *testing.T) {
	a := newAuthenticator(t)
	_, err := a.Authenticate(context.Background(), auth.Principal{Kind: "passkey", Subject: "x"}, "")
	if !errors.Is(err, auth.ErrUnknownAuthMethod) {
		t.Fatalf("err = %v, want ErrUnknownAuthMethod", err)
	}
}

type fakeResolver struct {
	userID string
	err    error
}

func (f fakeResolver) Resolve(context.Context, auth.Principal, string) (string, error) {
	return f.userID, f.err
}

// A registered resolver's error propagates and short-circuits before
// IssueSession (which would panic on the stub repo if reached). This also
// demonstrates the snap-in: a new kind is just a Register call.
func TestAuthenticate_ResolverErrorShortCircuits(t *testing.T) {
	a := newAuthenticator(t)
	boom := errors.New("resolver down")
	a.Register("passkey", fakeResolver{err: boom})

	_, err := a.Authenticate(context.Background(), auth.Principal{Kind: "passkey", Subject: "x"}, "")
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
}
