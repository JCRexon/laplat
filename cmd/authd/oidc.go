package main

import (
	"github.com/jcrexon/laplat/internal/auth"
	"github.com/jcrexon/laplat/internal/config"
	"github.com/jcrexon/laplat/internal/oidc"
	"github.com/jcrexon/laplat/internal/oidcprov"
	"github.com/jcrexon/laplat/internal/store"
)

// Pinned provider endpoints (issuer, authorize, JWKS). These are protocol
// constants, not operator configuration.
const (
	googleIssuer  = "https://accounts.google.com"
	googleAuthURL = "https://accounts.google.com/o/oauth2/v2/auth"
	googleJWKSURL = "https://www.googleapis.com/oauth2/v3/certs"

	appleIssuer  = "https://appleid.apple.com"
	appleAuthURL = "https://appleid.apple.com/auth/authorize"
	appleJWKSURL = "https://appleid.apple.com/auth/keys"
)

// buildFederation wires the configured OIDC providers into an auth.Federation,
// or returns (nil, nil) when no provider is configured. Each provider gets a
// cached remote JWKS verifier and a real token-endpoint exchanger.
func buildFederation(cfg config.Config, st *store.Store, svc *auth.Service) (*auth.Federation, error) {
	oc := cfg.OIDC
	if !oc.Enabled() {
		return nil, nil
	}
	providers := map[string]*auth.OIDCProvider{}

	if g := oc.Google; g != nil {
		providers["google"] = &auth.OIDCProvider{
			Verifier: &oidc.Provider{
				Name:     "google",
				Issuer:   googleIssuer,
				Audience: g.ClientID,
				Keys:     oidc.NewRemoteKeySet(googleJWKSURL, nil),
			},
			Exchanger:   oidcprov.NewGoogle(g.ClientID, g.ClientSecret, nil),
			AuthURL:     googleAuthURL,
			ClientID:    g.ClientID,
			RedirectURL: oc.RedirectBase + "/v1/auth/oidc/google/callback",
			Scopes:      []string{"openid", "email"},
		}
	}

	if a := oc.Apple; a != nil {
		exch, err := oidcprov.NewApple(oidcprov.AppleConfig{
			ClientID:   a.ClientID,
			TeamID:     a.TeamID,
			KeyID:      a.KeyID,
			PrivateKey: a.PrivateKey,
		}, nil)
		if err != nil {
			return nil, err
		}
		providers["apple"] = &auth.OIDCProvider{
			Verifier: &oidc.Provider{
				Name:     "apple",
				Issuer:   appleIssuer,
				Audience: a.ClientID,
				Keys:     oidc.NewRemoteKeySet(appleJWKSURL, nil),
			},
			Exchanger:   exch,
			AuthURL:     appleAuthURL,
			ClientID:    a.ClientID,
			RedirectURL: oc.RedirectBase + "/v1/auth/oidc/apple/callback",
			// openid only: requesting name/email would make Apple use
			// response_mode=form_post (a POST callback). We link by subject, never
			// email, so the minimal scope keeps the GET callback uniform.
			Scopes: []string{"openid"},
		}
	}

	return auth.NewFederation(st, svc, providers)
}
