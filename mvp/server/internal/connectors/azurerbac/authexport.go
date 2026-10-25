package azurerbac

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// Auth is the Entra client-credentials sign-in of this package (a client secret, or a certificate assertion)
// for another Microsoft API connector, such as Azure AI Foundry or Dataverse. The secret, the assertion and the
// token are never logged or put in an error.
type Auth struct {
	ts   *tokenSource
	mode string
}

// NewAuth validates the application and returns its token source for scope (for example
// "https://ai.azure.com/.default"). authorityURL is the login endpoint ("" for the public cloud); an override
// is a dev setting and is refused outside dev. hc must be the shared safehttp client.
func NewAuth(tenantID, clientID string, cred connsync.Secret, scope, authorityURL string, rt connsync.Runtime, hc *http.Client, now func() time.Time) (*Auth, error) {
	if !guidRE.MatchString(tenantID) {
		return nil, errors.New("azurerbac: tenant id must be the directory GUID")
	}
	if !guidRE.MatchString(clientID) {
		return nil, errors.New("azurerbac: client id must be the application GUID")
	}
	if cred.Empty() {
		return nil, errors.New("azurerbac: a client secret or certificate is required")
	}
	if hc == nil {
		return nil, errors.New("azurerbac: an internal/safehttp client is required")
	}
	authority, err := endpoint(authorityURL, DefaultAuthorityURL, "authority URL", rt)
	if err != nil {
		return nil, err
	}
	signer, err := parseCredential(cred.Reveal())
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	hc = safehttp.WithConfiguredPorts(hc, authority.String())
	api := &connsync.Client{HC: hc, Now: now, Header: http.Header{"Accept": {"application/json"}, "User-Agent": {"tessera-connector/entra-auth"}}}
	cfg := Config{TenantID: tenantID, ClientID: clientID, Credential: cred}
	ts := newTokenSource(cfg, authority, authority, signer, api, now)
	ts.scope = scope
	a := &Auth{ts: ts, mode: "client_secret"}
	if signer != nil {
		a.mode = "certificate"
	}
	return a, nil
}

// Authorize returns the Authorization header value (connsync.Client.Authorize).
func (a *Auth) Authorize(ctx context.Context) (string, error) { return a.ts.authorization(ctx) }

// Invalidate drops the cached token (connsync.Client.OnUnauthorized).
func (a *Auth) Invalidate() { a.ts.invalidate() }

// Mode is client_secret or certificate.
func (a *Auth) Mode() string { return a.mode }
