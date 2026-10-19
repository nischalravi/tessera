package readiness

import (
	"errors"
	"net/http"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/scim"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// SCIMLiveOptions wire the real prober for generic SCIM applications (DR-18).
// The zero value is safe: without a Client a real scim_app connection has no
// prober, so every live check reports an error rather than running
// unguarded or unauthenticated.
type SCIMLiveOptions struct {
	// Client is the outbound client (safehttp.ForConfig): every request is
	// SSRF-guarded. The connection's configured port is added per revision
	// (safehttp.WithConfiguredPorts).
	Client *http.Client
	// Token overrides how a revision's bearer token is found. Nil: the opened
	// sealed credential (the same one LDAP connections use).
	Token func(b *Bundle) (scim.Secret, error)
}

// scimLive reports whether a revision's checks run against the real
// application (a non-demo scim_app connection) rather than a simulation.
func scimLive(b *Bundle) bool { return !b.Simulated() && b.Template.ID == "scim_app" }

// prober returns the real SCIM prober for a non-demo scim_app revision, or
// ok=false for any other revision.
func (o SCIMLiveOptions) prober(b *Bundle, _ time.Time) (p connectors.Prober, ok bool, err error) {
	if !scimLive(b) {
		return nil, false, nil
	}
	if o.Client == nil {
		return nil, true, errors.New("readiness: no outbound HTTP client for the SCIM connection")
	}
	tok := scim.Secret(b.cred)
	if o.Token != nil {
		var err error
		if tok, err = o.Token(b); err != nil {
			return nil, true, err
		}
	}
	if tok == "" {
		return nil, true, errors.New("readiness: no stored credential for the SCIM connection")
	}
	sp, err := scim.New(scim.Config{BaseURL: b.Config.BaseURL, Token: tok,
		Client: safehttp.WithConfiguredPorts(o.Client, b.Config.BaseURL)})
	if err != nil {
		return nil, true, err
	}
	return sp, true, nil
}
