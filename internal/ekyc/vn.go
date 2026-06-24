// Package ekyc holds adult identity-verification (eKYC) provider adapters. The
// VN adapter is shaped for a C06-licensed Vietnamese vendor (FPT.AI / VNeID
// style): it implements identity.Verifier (start a hosted check) and parses the
// vendor's signed completion webhook into the MINIMAL verified facts — an
// over-18 assertion plus opaque references. Name, DOB, and the national-ID
// number are never extracted or stored (data minimisation; the vendor retains
// the documents, the platform keeps only "verified adult" + a reference).
package ekyc

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/jcrexon/laplat/internal/identity"
)

// Client starts a hosted verification session at the vendor. correlationID is
// our opaque user id, which the vendor echoes back in the completion webhook so
// we can map the result to a user without storing any mapping ourselves.
type Client interface {
	CreateVerification(ctx context.Context, correlationID string) (ref, redirectURL string, err error)
}

// VNVerifier is the Vietnamese eKYC adapter.
type VNVerifier struct {
	name          string
	client        Client
	webhookSecret []byte
}

// NewVN builds the adapter. webhookSecret is the HMAC key the vendor signs
// completion callbacks with.
func NewVN(client Client, webhookSecret string) (*VNVerifier, error) {
	if client == nil || webhookSecret == "" {
		return nil, errors.New("ekyc: vn verifier requires a client and webhook secret")
	}
	return &VNVerifier{name: "vn-ekyc", client: client, webhookSecret: []byte(webhookSecret)}, nil
}

// Name implements identity.Verifier.
func (v *VNVerifier) Name() string { return v.name }

// Begin starts a verification session for the user and returns the hosted
// redirect the client sends the user to.
func (v *VNVerifier) Begin(ctx context.Context, userID string) (identity.StartResult, error) {
	ref, redirect, err := v.client.CreateVerification(ctx, userID)
	if err != nil {
		return identity.StartResult{}, err
	}
	return identity.StartResult{Provider: v.name, Ref: ref, RedirectURL: redirect}, nil
}

// callback is the minimal subset of the vendor webhook we read. Any PII fields
// the vendor may also send are deliberately ignored.
type callback struct {
	CorrelationID string `json:"correlationId"` // our user id
	Reference     string `json:"reference"`     // vendor's opaque verification ref
	Result        string `json:"result"`        // "approved" | "rejected" | ...
	Over18        bool   `json:"over18"`
}

// ParseCallback verifies the webhook HMAC (constant-time) and maps the payload
// to the minimal identity.Result. A bad signature is rejected; nothing about
// the underlying identity is extracted.
func (v *VNVerifier) ParseCallback(body []byte, signatureHex string) (identity.Result, error) {
	want, err := hex.DecodeString(signatureHex)
	if err != nil {
		return identity.Result{}, errors.New("ekyc: malformed signature")
	}
	mac := hmac.New(sha256.New, v.webhookSecret)
	mac.Write(body)
	if !hmac.Equal(mac.Sum(nil), want) {
		return identity.Result{}, errors.New("ekyc: webhook signature mismatch")
	}

	var c callback
	if err := json.Unmarshal(body, &c); err != nil {
		return identity.Result{}, errors.New("ekyc: malformed callback body")
	}
	if c.CorrelationID == "" {
		return identity.Result{}, errors.New("ekyc: callback missing correlation id")
	}
	return identity.Result{
		UserID:      c.CorrelationID,
		ProviderRef: c.Reference,
		Approved:    c.Result == "approved",
		IsAdult:     c.Over18,
	}, nil
}
