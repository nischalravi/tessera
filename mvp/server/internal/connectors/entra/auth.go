package entra

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// tokenSource gets and caches client-credentials access tokens. The secret and
// the token are never logged or put in an error.
type tokenSource struct {
	form     url.Values
	tokenURL string
	api      *connsync.Client // without Authorize, for the token endpoint
	now      func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

func newTokenSource(cfg Config, authority, graph *url.URL, api *connsync.Client, now func() time.Time) *tokenSource {
	tokenAPI := *api
	tokenAPI.Authorize, tokenAPI.OnUnauthorized = nil, nil
	u := *authority
	u.Path = strings.TrimRight(u.Path, "/") + "/" + url.PathEscape(cfg.TenantID) + "/oauth2/v2.0/token"
	scope := *graph
	scope.Path = "/.default"
	return &tokenSource{tokenURL: u.String(), api: &tokenAPI, now: now, form: url.Values{
		"grant_type": {"client_credentials"}, "client_id": {cfg.ClientID}, "client_secret": {cfg.ClientSecret.Reveal()},
		"scope": {scope.String()}}}
}

func (t *tokenSource) authorization(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.token != "" && t.now().Before(t.expires.Add(-time.Minute)) {
		return "Bearer " + t.token, nil
	}
	resp, err := t.api.Do(ctx, http.MethodPost, t.tokenURL, http.Header{
		"Content-Type": {"application/x-www-form-urlencoded"}}, []byte(t.form.Encode()))
	if err != nil {
		return "", fmt.Errorf("entra: token request: %w", err)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := connsync.DecodeJSON(resp.Body, &tr); err != nil {
		return "", fmt.Errorf("entra: token response: %w", err)
	}
	if tr.AccessToken == "" || !strings.EqualFold(tr.TokenType, "Bearer") {
		return "", errors.New("entra: token response has no bearer token")
	}
	if tr.ExpiresIn <= 0 || tr.ExpiresIn > 86400 {
		tr.ExpiresIn = 600
	}
	t.token, t.expires = tr.AccessToken, t.now().Add(time.Duration(tr.ExpiresIn)*time.Second)
	return "Bearer " + t.token, nil
}

func (t *tokenSource) invalidate() {
	t.mu.Lock()
	t.token = ""
	t.mu.Unlock()
}
