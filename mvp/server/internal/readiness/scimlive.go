package readiness

import (
	"errors"
	"net/http"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/scim"
)

// SCIMLiveOptions wire the real prober for generic SCIM applications (DR-18).
// The zero value is safe: Env defaults to prod (no loopback, https only) and
// without a Token source a real scim_app connection has no prober, so every
// live check reports an error rather than running unauthenticated.
type SCIMLiveOptions struct {
	// Env is TESSERA_ENV; only "dev" may allow loopback.
	Env string
	// AllowLoopback lets the client reach 127.0.0.1 in dev (a local SCIM app).
	AllowLoopback bool
	// Token returns the opened bearer token of a revision. The sealed
	// connection credential store is not on this branch yet; until it is,
	// this is nil and a real SCIM connection cannot run live checks.
	Token func(b *Bundle) (scim.Secret, error)
	// Client replaces the safehttp client. Tests only: production code leaves
	// it nil so every request is SSRF-guarded.
	Client *http.Client
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
	if o.Token == nil {
		return nil, true, errors.New("readiness: no stored credential for the SCIM connection")
	}
	tok, err := o.Token(b)
	if err != nil {
		return nil, true, err
	}
	if tok == "" {
		return nil, true, errors.New("readiness: no stored credential for the SCIM connection")
	}
	hc := o.Client
	if hc == nil {
		env, loop := o.Env, o.AllowLoopback
		if env != config.Dev {
			env, loop = config.Prod, false
		}
		if hc, err = scim.NewClient(scim.ClientOptions{Env: env, AllowLoopback: loop}); err != nil {
			return nil, true, err
		}
	}
	sp, err := scim.New(scim.Config{BaseURL: b.Config.BaseURL, Token: tok, Client: hc})
	if err != nil {
		return nil, true, err
	}
	return sp, true, nil
}
