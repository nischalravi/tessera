package workday

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// tokenSource gets and caches OAuth access tokens for a Workday API client:
// the refresh-token grant when a refresh token is configured, else client
// credentials, with the client authenticating by HTTP Basic. The secret, the
// refresh token and the access token are never logged or put in an error.
type tokenSource struct {
	form     url.Values
	basic    string
	tokenURL string
	api      *connsync.Client // without Authorize, for the token endpoint
	now      func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

func newTokenSource(cfg Config, tokenURL *url.URL, api *connsync.Client, now func() time.Time) *tokenSource {
	tokenAPI := *api
	tokenAPI.Authorize, tokenAPI.OnUnauthorized = nil, nil
	form := url.Values{"grant_type": {"client_credentials"}}
	if !cfg.RefreshToken.Empty() {
		form = url.Values{"grant_type": {"refresh_token"}, "refresh_token": {cfg.RefreshToken.Reveal()}}
	}
	return &tokenSource{form: form, tokenURL: tokenURL.String(), api: &tokenAPI, now: now,
		basic: "Basic " + base64.StdEncoding.EncodeToString([]byte(cfg.ClientID+":"+cfg.ClientSecret.Reveal()))}
}

func (t *tokenSource) authorization(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.token != "" && t.now().Before(t.expires.Add(-time.Minute)) {
		return "Bearer " + t.token, nil
	}
	resp, err := t.api.Do(ctx, http.MethodPost, t.tokenURL, http.Header{
		"Content-Type": {"application/x-www-form-urlencoded"}, "Authorization": {t.basic}}, []byte(t.form.Encode()))
	if err != nil {
		return "", fmt.Errorf("workday: token request: %w", err)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := connsync.DecodeJSON(resp.Body, &tr); err != nil {
		return "", fmt.Errorf("workday: token response: %w", err)
	}
	if tr.AccessToken == "" || !strings.EqualFold(tr.TokenType, "Bearer") {
		return "", errors.New("workday: token response has no bearer token")
	}
	if tr.ExpiresIn <= 0 || tr.ExpiresIn > 86400 {
		tr.ExpiresIn = 3600
	}
	t.token, t.expires = tr.AccessToken, t.now().Add(time.Duration(tr.ExpiresIn)*time.Second)
	return "Bearer " + t.token, nil
}

func (t *tokenSource) invalidate() {
	t.mu.Lock()
	t.token = ""
	t.mu.Unlock()
}
