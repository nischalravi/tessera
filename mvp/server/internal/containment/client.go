package containment

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// Client is the provider JSON client of the revokers (safehttp transport, 429
// retry, errors without bodies or tokens), exported for internal/oauthapps,
// which reads and revokes per app with the same credentials.
type Client struct{ a *api }

// NewClient returns a client for one provider. hc must come from
// internal/safehttp; baseURL falls back to def; scheme is the Authorization
// scheme (Bearer, SSWS). sleep waits between 429 retries (nil: real time).
func NewClient(hc *http.Client, baseURL, def, scheme, token string, sleep func(context.Context, time.Duration) error) (*Client, error) {
	a, err := newAPI(hc, baseURL, def, scheme, token, sleep)
	if err != nil {
		return nil, err
	}
	return &Client{a}, nil
}

// Do sends one request: see api.do. path must already be escaped (Esc).
func (c *Client) Do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	return c.a.do(ctx, method, path, q, body, out)
}

// Host is the host (with port) every request goes to.
func (c *Client) Host() string { return c.a.base.Host }

// BasePath is the path prefix of the base URL, without a trailing slash.
func (c *Client) BasePath() string { return c.a.base.Path }

// Esc escapes one path segment.
func Esc(s string) string { return esc(s) }

// Outbound returns the service's outbound HTTP client and rate-limit sleep.
func (s *Service) Outbound() (*http.Client, func(context.Context, time.Duration) error) {
	return s.HTTP, s.Sleep
}
