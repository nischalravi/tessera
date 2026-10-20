package rotation

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// maxResponse caps what an adapter reads from a provider (safehttp caps it
// too; this is the adapter's own bound).
const maxResponse = 1 << 20

// send runs req on c (a client from internal/safehttp) and returns the status
// and body. Transport failures are transient unless safehttp refused the
// destination, which retrying cannot fix.
func send(c *http.Client, op string, req *http.Request) (int, []byte, error) {
	resp, err := c.Do(req) // #nosec G704 -- c is an internal/safehttp client (SSRF guard)
	if err != nil {
		for _, refused := range []error{safehttp.ErrScheme, safehttp.ErrURL, safehttp.ErrBlockedAddress,
			safehttp.ErrRedirect, safehttp.ErrTooLarge} {
			if errors.Is(err, refused) {
				return 0, nil, fail(op, "destination_refused", refused.Error(), false)
			}
		}
		if errors.Is(err, context.Canceled) {
			return 0, nil, err
		}
		return 0, nil, fail(op, "network", "request failed", true)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		if errors.Is(err, safehttp.ErrTooLarge) {
			return 0, nil, fail(op, "response_too_large", "", false)
		}
		return 0, nil, fail(op, "network", "reading the response failed", true)
	}
	return resp.StatusCode, body, nil
}

// transientStatus: retrying may succeed.
func transientStatus(code int) bool {
	return code == http.StatusTooManyRequests || code == http.StatusRequestTimeout || code >= 500
}

func isHTTPS(u string) bool { return strings.HasPrefix(strings.ToLower(u), "https://") }
