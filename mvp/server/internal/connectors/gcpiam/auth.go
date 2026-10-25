package gcpiam

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// Auth is the service account sign-in of this package (a signed JWT exchanged for an access token) for another
// Google API connector, such as Vertex AI. The key, the assertion and the token are never logged or put in an error.
type Auth struct {
	ts *tokenSource
}

// NewAuth parses the service account key and returns its token source. tokenURL is the token endpoint ("" for
// Google's); an override is a dev setting and is refused outside dev. hc must be the shared safehttp client.
func NewAuth(key connsync.Secret, tokenURL string, rt connsync.Runtime, hc *http.Client, now func() time.Time) (*Auth, error) {
	if hc == nil {
		return nil, errors.New("gcpiam: an internal/safehttp client is required")
	}
	k, err := parseKey(key.Reveal())
	if err != nil {
		return nil, err
	}
	u, err := endpoint(tokenURL, DefaultTokenURL, "token URL", rt)
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	hc = safehttp.WithConfiguredPorts(hc, u.String())
	api := &connsync.Client{HC: hc, Now: now, Header: http.Header{"Accept": {"application/json"}, "User-Agent": {"tessera-connector/gcp-auth"}}}
	return &Auth{&tokenSource{key: k, tokenURL: u.String(), now: now, api: api}}, nil
}

// Authorize returns the Authorization header value (connsync.Client.Authorize).
func (a *Auth) Authorize(ctx context.Context) (string, error) { return a.ts.authorization(ctx) }

// Invalidate drops the cached token (connsync.Client.OnUnauthorized).
func (a *Auth) Invalidate() { a.ts.invalidate() }

// Identity is the service account's e-mail address.
func (a *Auth) Identity() string { return a.ts.key.email }
