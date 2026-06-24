package main

import (
	"context"
	"fmt"

	"github.com/jcrexon/laplat/internal/auth"
	"github.com/jcrexon/laplat/internal/config"
	"github.com/jcrexon/laplat/internal/oidc"
	"github.com/jcrexon/laplat/internal/oidcprov"
	"github.com/jcrexon/laplat/internal/store"
	"github.com/jcrexon/laplat/internal/zalo"
)

// Pinned provider endpoints. Protocol constants, not operator configuration.
const (
	googleIssuer  = "https://accounts.google.com"
	googleAuthURL = "https://accounts.google.com/o/oauth2/v2/auth"
	googleJWKSURL = "https://www.googleapis.com/oauth2/v3/certs"

	appleIssuer  = "https://appleid.apple.com"
	appleAuthURL = "https://appleid.apple.com/auth/authorize"
	appleJWKSURL = "https://appleid.apple.com/auth/keys"

	zaloAuthURL = "https://oauth.zaloapp.com/v4/permission"
)

// buildFederation wires the configured federated-login providers into an
// auth.Federation, or returns (nil, nil) when none is configured. Google/Apple
// are OIDC connectors (cached remote JWKS verifier + token exchanger); Zalo is
// an OAuth2+PKCE connector (token exchange + userinfo).
func buildFederation(cfg config.Config, st *store.Store, svc *auth.Service) (*auth.Federation, error) {
	oc := cfg.OIDC
	if !oc.Enabled() {
		return nil, nil
	}
	connectors := map[string]auth.Connector{}

	if g := oc.Google; g != nil {
		conn, err := auth.NewOIDCConnector(
			&oidc.Provider{Name: "google", Issuer: googleIssuer, Audience: g.ClientID, Keys: oidc.NewRemoteKeySet(googleJWKSURL, nil)},
			oidcprov.NewGoogle(g.ClientID, g.ClientSecret, nil),
			googleAuthURL, g.ClientID, oc.RedirectBase+"/v1/auth/oidc/google/callback",
			[]string{"openid", "email"},
		)
		if err != nil {
			return nil, err
		}
		connectors["google"] = conn
	}

	if a := oc.Apple; a != nil {
		exch, err := oidcprov.NewApple(oidcprov.AppleConfig{
			ClientID: a.ClientID, TeamID: a.TeamID, KeyID: a.KeyID, PrivateKey: a.PrivateKey,
		}, nil)
		if err != nil {
			return nil, err
		}
		// openid only: name/email would make Apple use response_mode=form_post (a
		// POST callback). We link by subject, never email.
		conn, err := auth.NewOIDCConnector(
			&oidc.Provider{Name: "apple", Issuer: appleIssuer, Audience: a.ClientID, Keys: oidc.NewRemoteKeySet(appleJWKSURL, nil)},
			exch, appleAuthURL, a.ClientID, oc.RedirectBase+"/v1/auth/oidc/apple/callback",
			[]string{"openid"},
		)
		if err != nil {
			return nil, err
		}
		connectors["apple"] = conn
	}

	if z := oc.Zalo; z != nil {
		exch, err := zalo.NewExchanger(z.AppID, z.AppSecret, nil)
		if err != nil {
			return nil, err
		}
		conn, err := auth.NewZaloConnector(
			exch, zalo.NewUserInfo(nil),
			zaloAuthURL, z.AppID, oc.RedirectBase+"/v1/auth/oidc/zalo/callback",
		)
		if err != nil {
			return nil, err
		}
		connectors["zalo"] = conn
	}

	// Fail fast: every configured connector's provider must be registered in the
	// auth_providers reference table (Brick 3 — the data-driven replacement for a
	// hardcoded allowlist). The federated_identities FK would otherwise only
	// reject an unregistered provider at first login.
	registered, err := st.ListAuthProviders(context.Background())
	if err != nil {
		return nil, err
	}
	valid := make(map[string]bool, len(registered))
	for _, p := range registered {
		valid[p] = true
	}
	for name := range connectors {
		if !valid[name] {
			return nil, fmt.Errorf("auth: provider %q is configured but not registered in auth_providers", name)
		}
	}

	return auth.NewFederation(st, svc, connectors)
}
