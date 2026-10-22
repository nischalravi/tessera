package pam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sync"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// Paging bounds: a vault that never stops paging cannot keep a sync running.
const (
	pageSize = 100
	maxPages = 5000
)

// Config configures one vault.
type Config struct {
	Vendor  string
	BaseURL string // https://pvwa.example.com
	// Username and Secret: CyberArk and Delinea user and password; BeyondTrust
	// run-as user and API key.
	Username string
	Secret   connsync.Secret
	// Path overrides of the vendor's API roots (defaults in each vendor file).
	APIRoot string
}

// session is a retrying JSON client with the vendor's login.
type session struct {
	api  *connsync.Client
	base *url.URL
	root string

	mu     sync.Mutex
	header string
	login  func(ctx context.Context) (string, error)
}

func newSession(hc *http.Client, base *url.URL, root string, now func() time.Time, cookies bool) (*session, error) {
	if hc == nil {
		return nil, errors.New("pam: an internal/safehttp client is required")
	}
	if cookies {
		jar, err := cookiejar.New(nil)
		if err != nil {
			return nil, err
		}
		cp := *hc // the transport (and so safehttp's dial guard) is shared
		cp.Jar = jar
		hc = &cp
	}
	s := &session{base: base, root: root}
	s.api = &connsync.Client{HC: hc, Now: now, Header: http.Header{"Accept": {"application/json"}, "User-Agent": {"tessera-connector/pam"}}}
	s.api.Authorize = s.authorize
	s.api.OnUnauthorized = func() { s.mu.Lock(); s.header = ""; s.mu.Unlock() }
	return s, nil
}

func (s *session) authorize(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.header == "" && s.login != nil {
		h, err := s.login(ctx)
		if err != nil {
			return "", err
		}
		s.header = h
	}
	return s.header, nil
}

// u builds a URL under the vendor's API root.
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

// send makes a write with a JSON body (nil: none) and ignores a response body.
func (s *session) send(ctx context.Context, method, path string, body any) error {
	var b []byte
	h := http.Header{}
	if body != nil {
		var err error
		if b, err = json.Marshal(body); err != nil {
			return err
		}
		h.Set("Content-Type", "application/json")
	}
	_, err := s.api.Do(ctx, method, s.u(path, nil), h, b)
	return err
}

// forPages calls fetch with each offset until it reports no more.
func forPages(fetch func(offset int) (more bool, err error)) error {
	for i := 0; i < maxPages; i++ {
		more, err := fetch(i * pageSize)
		if err != nil || !more {
			return err
		}
	}
	return fmt.Errorf("pam: more than %d pages; stopping", maxPages)
}

func epoch(sec int64) *time.Time {
	if sec <= 0 || sec > 1<<40 {
		return nil
	}
	t := time.Unix(sec, 0).UTC()
	return &t
}
