package erp

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

// Paging bounds.
const (
	pageSize = 100
	maxPages = 5000
)

// Config configures one ERP.
type Config struct {
	System  string
	BaseURL string
	// ClientID and ClientSecret are the OAuth client of the integration (client credentials).
	ClientID     string
	ClientSecret connsync.Secret
	// APIRoot and TokenPath override the vendor's defaults.
	APIRoot, TokenPath string
}

// session is a retrying JSON client with an OAuth client-credentials login.
type session struct {
	api      *connsync.Client
	base     *url.URL
	root     string
	token    string
	basic    string
	tokenURL string
	now      func() time.Time

	mu      sync.Mutex
	access  string
	expires time.Time
}

func newSession(cfg Config, base *url.URL, root, tokenPath string, hc *http.Client, now func() time.Time) (*session, error) {
	if hc == nil {
		return nil, errors.New("erp: an internal/safehttp client is required")
	}
	tu := *base
	tu.Path = tokenPath
	s := &session{base: base, root: root, now: now, tokenURL: tu.String(),
		basic: "Basic " + base64.StdEncoding.EncodeToString([]byte(cfg.ClientID+":"+cfg.ClientSecret.Reveal()))}
	s.api = &connsync.Client{HC: hc, Now: now, Header: http.Header{"Accept": {"application/json"}, "User-Agent": {"tessera-connector/erp"}}}
	s.api.Authorize = s.authorize
	s.api.OnUnauthorized = func() { s.mu.Lock(); s.access = ""; s.mu.Unlock() }
	return s, nil
}

func (s *session) authorize(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.access != "" && s.now().Before(s.expires.Add(-time.Minute)) {
		return "Bearer " + s.access, nil
	}
	plain := *s.api
	plain.Authorize, plain.OnUnauthorized = nil, nil
	resp, err := plain.Do(ctx, http.MethodPost, s.tokenURL, http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Authorization": {s.basic}},
		[]byte(url.Values{"grant_type": {"client_credentials"}}.Encode()))
	if err != nil {
		return "", fmt.Errorf("erp: token request: %w", err)
	}
	var tr struct {
		Access  string `json:"access_token"`
		Type    string `json:"token_type"`
		Expires int    `json:"expires_in"`
	}
	if err := connsync.DecodeJSON(resp.Body, &tr); err != nil {
		return "", fmt.Errorf("erp: token response: %w", err)
	}
	if tr.Access == "" || !strings.EqualFold(tr.Type, "bearer") {
		return "", errors.New("erp: token response has no bearer token")
	}
	if tr.Expires <= 0 || tr.Expires > 86400 {
		tr.Expires = 3600
	}
	s.access, s.expires = tr.Access, s.now().Add(time.Duration(tr.Expires)*time.Second)
	return "Bearer " + s.access, nil
}

func (s *session) u(path string, q url.Values) string {
	x := *s.base
	x.Path = s.root + path
	x.RawQuery = q.Encode()
	return x.String()
}

func (s *session) getJSON(ctx context.Context, path string, q url.Values, v any) error {
	_, err := s.api.GetJSON(ctx, s.u(path, q), nil, v)
	return err
}

// call makes a write and ignores any body.
func (s *session) call(ctx context.Context, method, path string, body []byte) error {
	h := http.Header{}
	if body != nil {
		h.Set("Content-Type", "application/json")
	}
	_, err := s.api.Do(ctx, method, s.u(path, nil), h, body)
	return err
}

func forPages(fetch func(offset int) (more bool, err error)) error {
	for i := 0; i < maxPages; i++ {
		more, err := fetch(i * pageSize)
		if err != nil || !more {
			return err
		}
	}
	return fmt.Errorf("erp: more than %d pages; stopping", maxPages)
}

func tparse(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	for _, l := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.ParseInLocation(l, s, time.UTC); err == nil {
			t = t.UTC()
			return &t
		}
	}
	return nil
}
