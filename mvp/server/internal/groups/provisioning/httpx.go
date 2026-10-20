package provisioning

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// doHTTP sends req through the safehttp client of the deps and returns the
// status and the whole (size-limited) body. The error never carries the URL: a
// webhook URL can hold a token, and the client's own errors quote it.
func doHTTP(c *http.Client, req *http.Request) (int, []byte, error) {
	if c == nil {
		return 0, nil, errors.New("no outbound HTTP client is configured")
	}
	resp, err := c.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("reading the response: %w", err)
	}
	return resp.StatusCode, body, nil
}

// httpURL parses and checks a target URL: absolute, a host, no user info, no
// fragment. The scheme rules (https only, plain http to loopback in dev) are
// the safehttp client's, applied on every request and redirect.
func httpURL(field, raw string, allowQuery bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	switch {
	case raw == "" || len(raw) > 512:
		return nil, cfgErr("%s is required and at most 512 bytes", field)
	case err != nil || u.Host == "" || u.Hostname() == "":
		return nil, cfgErr("%s must be an absolute URL", field)
	case u.Scheme != "https" && u.Scheme != "http":
		return nil, cfgErr("%s must be an https URL", field)
	case u.User != nil:
		return nil, cfgErr("%s must not contain user info", field)
	case u.Fragment != "" || (!allowQuery && u.RawQuery != ""):
		return nil, cfgErr("%s must not have a fragment or a query", field)
	}
	return u, nil
}

// statusErr describes a non-success status without the response body, which a
// target may fill with details about other tenants' objects or secrets.
func statusErr(what string, status int) error {
	return fmt.Errorf("%s: the target answered %d %s", what, status, strings.ToLower(http.StatusText(status)))
}

// ctxReq builds a request with a context.
func ctxReq(ctx context.Context, method, rawURL string, body io.Reader) (*http.Request, error) {
	return http.NewRequestWithContext(ctx, method, rawURL, body)
}
