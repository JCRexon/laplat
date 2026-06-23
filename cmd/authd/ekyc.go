package main

import (
	"context"
	"errors"

	"github.com/jcrexon/laplat/internal/auth"
	"github.com/jcrexon/laplat/internal/ekyc"
	"github.com/jcrexon/laplat/internal/identity"
)

// ekycBridge adapts the identity service + VN verifier to auth.EKYCService,
// keeping the auth package free of the identity/ekyc packages.
type ekycBridge struct {
	id *identity.Service
	vn *ekyc.VNVerifier
}

// BeginVerification starts a hosted eKYC session for the user in their region.
func (b *ekycBridge) BeginVerification(ctx context.Context, userID, region string) (provider, ref, redirectURL string, err error) {
	sr, err := b.id.Begin(ctx, userID, region)
	if err != nil {
		return "", "", "", err
	}
	return sr.Provider, sr.Ref, sr.RedirectURL, nil
}

// ApplyCallback validates the vendor webhook and applies the result. A bad
// signature/body maps to auth.ErrWebhookSignature; a validly-processed but
// not-approved/under-age outcome is acknowledged (nil) without changing state.
func (b *ekycBridge) ApplyCallback(ctx context.Context, body []byte, signature string) error {
	res, err := b.vn.ParseCallback(body, signature)
	if err != nil {
		return auth.ErrWebhookSignature
	}
	err = b.id.Apply(ctx, res)
	if errors.Is(err, identity.ErrUnderage) || errors.Is(err, identity.ErrNotApproved) {
		return nil
	}
	return err
}
