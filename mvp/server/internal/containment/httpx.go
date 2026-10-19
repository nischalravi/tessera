package containment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/obs"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// maxAttempts is how often a call is tried when the provider answers 429.
const maxAttempts = 4

// maxRetryWait caps a Retry-After so one provider cannot hold a request open.
const maxRetryWait = 3 * time.Second

// sleepFunc waits d or until ctx ends (tests replace it).
type sleepFunc func(ctx context.Context, d time.Duration) error

// api is a small JSON client for one provider. hc must come from
// internal/safehttp.
type api struct {
	hc    *http.Client
	base  *url.URL
	auth  string // Authorization header value
	sleep sleepFunc
}

func newAPI(hc *http.Client, baseURL, def, scheme, token string, sleep sleepFunc) (*api, error) {
	if baseURL == "" {
		baseURL = def
	}
	if baseURL == "" {
		return nil, errors.New("containment: no base_url configured for this provider")
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("containment: base_url is not a valid URL")
	}
	u.RawQuery, u.Fragment = "", ""
	if token == "" {
		return nil, errors.New("containment: no token configured for this provider")
	}
	if sleep == nil {
		sleep = sleepCtx
	}
	// the connection's base_url may name its own port (safehttp allows only
	// 443 and 8443 otherwise)
	return &api{hc: safehttp.WithConfiguredPorts(hc, u.String()), base: u, auth: scheme + " " + token, sleep: sleep}, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// do sends one request. A 2xx body is decoded into out (when non-nil and the
// body is not empty). 429 is retried after Retry-After; a 404 returns an
// error wrapping ErrNotFound; other non-2xx answers return a *StatusError.
// path must already be escaped (esc).
func (a *api) do(ctx context.Context, method, path string, q url.Values, body, out any) (err error) {
	// one observation per logical call (retries on 429 included); a 404 is an
	// answer, not a failure of the provider
	done := obs.StartCall(obs.ConnContainment, "api")
	defer func() { done(notFoundIsOK(err)) }()
	u := *a.base
	u.Path = strings.TrimRight(u.Path, "/") + path
	u.RawPath = ""
	if q != nil {
		u.RawQuery = q.Encode()
	}
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return err
		}
	}
	for attempt := 1; ; attempt++ {
		var rd io.Reader
		if payload != nil {
			rd = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", a.auth)
		req.Header.Set("Accept", "application/json")
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := a.hc.Do(req) // #nosec G704 -- hc is an internal/safehttp client
		if err != nil {
			return fmt.Errorf("%s %s: %w", method, path, scrub(err))
		}
		raw, rerr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if rerr != nil {
			return fmt.Errorf("%s %s: %w", method, path, scrub(rerr))
		}
		switch {
		case resp.StatusCode == http.StatusTooManyRequests:
			if attempt >= maxAttempts {
				return fmt.Errorf("%s %s: %w", method, path, ErrRateLimited)
			}
			if err := a.sleep(ctx, retryWait(resp.Header.Get("Retry-After"), attempt)); err != nil {
				return err
			}
			continue
		case resp.StatusCode == http.StatusNotFound:
			return fmt.Errorf("%w: %w", ErrNotFound, &StatusError{method, path, resp.StatusCode})
		case resp.StatusCode < 200 || resp.StatusCode > 299:
			return &StatusError{method, path, resp.StatusCode}
		}
		if out != nil && len(bytes.TrimSpace(raw)) > 0 {
			if err := json.Unmarshal(raw, out); err != nil {
				return fmt.Errorf("%s %s: unreadable answer", method, path)
			}
		}
		return nil
	}
}

// scrub drops the request URL (and any query string in it) from a transport error.
func scrub(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// retryWait honors Retry-After seconds, else backs off 250ms, 500ms, 1s.
func retryWait(h string, attempt int) time.Duration {
	if s, err := strconv.Atoi(strings.TrimSpace(h)); err == nil && s >= 0 {
		return min(time.Duration(s)*time.Second, maxRetryWait)
	}
	return min(250*time.Millisecond<<(attempt-1), maxRetryWait)
}

func esc(s string) string { return url.PathEscape(s) }

// notFoundIsOK maps a provider's 404 answer to success for the call metrics.
func notFoundIsOK(err error) error {
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}
