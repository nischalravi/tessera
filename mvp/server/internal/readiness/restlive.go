package readiness

import (
	"errors"
	"net/http"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/restgen"
)

// RESTLiveOptions wire the real prober for generic REST connections (issue
// #552). The zero value is safe: without a Client a real rest_generic
// connection has no prober, so every live check reports an error rather than
// running unguarded.
type RESTLiveOptions struct {
	// Client is the outbound client (safehttp.ForConfig): every request is
	// SSRF-guarded.
	Client *http.Client
	// Env is TESSERA_ENV: only "dev" accepts plain http to loopback.
	Env string
	// Secret overrides how a revision's credential is found. Nil: the opened sealed credential
	// (the same one LDAP and SCIM connections use).
	Secret func(b *Bundle) (string, error)
}

// restLive reports whether a revision's checks run against the real system
// (a non-demo rest_generic connection) rather than a simulation.
func restLive(b *Bundle) bool { return !b.Simulated() && b.Template.ID == "rest_generic" }

// prober returns the real REST prober for a non-demo rest_generic revision, or
// ok=false for any other revision.
func (o RESTLiveOptions) prober(b *Bundle, _ time.Time) (p connectors.Prober, ok bool, err error) {
	if !restLive(b) {
		return nil, false, nil
	}
	if o.Client == nil {
		return nil, true, errors.New("readiness: no outbound HTTP client for the REST connection")
	}
	spec := b.Config.Rest
	if spec == nil {
		return nil, true, errors.New("readiness: the REST connection has no spec")
	}
	cred := string(b.cred)
	if o.Secret != nil {
		if cred, err = o.Secret(b); err != nil {
			return nil, true, err
		}
	}
	if cred == "" {
		return nil, true, errors.New("readiness: no stored credential for the REST connection")
	}
	sec, err := restgen.ParseSecrets(spec.Auth.Type, cred)
	if err != nil {
		return nil, true, err
	}
	rt := connsync.Runtime{Env: o.Env, AllowLoopback: o.Env == config.Dev}
	rp, err := restgen.NewProber(spec, sec, rt, o.Client)
	if err != nil {
		return nil, true, err
	}
	return rp, true, nil
}
