// Package zalo holds the production network adapters for "Sign in with Zalo".
// Zalo Login is OAuth 2.0 with PKCE (not OIDC): there is no id_token, so the
// code is exchanged for an access token and a userinfo call yields the stable
// Zalo user id. These satisfy auth.PKCEExchanger and auth.UserInfoFetcher
// structurally, keeping the auth package free of any Zalo dependency.
package zalo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Well-known Zalo endpoints.
const (
	tokenEndpoint = "https://oauth.zaloapp.com/v4/access_token"
	meEndpoint    = "https://graph.zalo.me/v2.0/me"
)

func httpClient(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// Exchanger swaps an authorization code (+ PKCE verifier) for a Zalo access
// token. The app secret is sent in the `secret_key` header (Zalo's scheme).
type Exchanger struct {
	tokenURL  string // overridable in tests
	appID     string
	appSecret string
	client    *http.Client
}

// NewExchanger builds the Zalo token-exchange client.
func NewExchanger(appID, appSecret string, client *http.Client) (*Exchanger, error) {
	if appID == "" || appSecret == "" {
		return nil, errors.New("zalo: app id and secret are required")
	}
	return &Exchanger{tokenURL: tokenEndpoint, appID: appID, appSecret: appSecret, client: httpClient(client)}, nil
}

// Exchange implements auth.PKCEExchanger. redirectURI is accepted for interface
// parity but Zalo's token endpoint does not require it.
func (e *Exchanger) Exchange(ctx context.Context, code, _ /*redirectURI*/, codeVerifier string) (string, error) {
	form := url.Values{
		"code":          {code},
		"app_id":        {e.appID},
		"grant_type":    {"authorization_code"},
		"code_verifier": {codeVerifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("secret_key", e.appSecret)

	resp, err := e.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("zalo: token exchange: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("zalo: token status %d", resp.StatusCode)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		Error       int    `json:"error"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("zalo: decode token response: %w", err)
	}
	if tr.AccessToken == "" {
		return "", errors.New("zalo: token response missing access_token")
	}
	return tr.AccessToken, nil
}

// UserInfo resolves a Zalo access token to the user's stable id via the Graph
// /me endpoint. The access token is sent in the `access_token` header.
type UserInfo struct {
	meURL  string // overridable in tests
	client *http.Client
}

// NewUserInfo builds the Zalo userinfo client.
func NewUserInfo(client *http.Client) *UserInfo {
	return &UserInfo{meURL: meEndpoint, client: httpClient(client)}
}

// Subject implements auth.UserInfoFetcher. It requests only the id field.
func (u *UserInfo) Subject(ctx context.Context, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.meURL+"?fields=id", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("access_token", accessToken)

	resp, err := u.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("zalo: userinfo: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("zalo: userinfo status %d", resp.StatusCode)
	}
	var mr struct {
		ID    string `json:"id"`
		Error int    `json:"error"`
	}
	if err := json.Unmarshal(body, &mr); err != nil {
		return "", fmt.Errorf("zalo: decode userinfo: %w", err)
	}
	if mr.Error != 0 || mr.ID == "" {
		return "", errors.New("zalo: userinfo returned no id")
	}
	return mr.ID, nil
}
