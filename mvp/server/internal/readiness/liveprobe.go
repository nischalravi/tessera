package readiness

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/ldap"
	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// LiveOptions wire the real (non-simulated) probers. The zero value is safe:
// no Sealer means no stored credential can be opened, so a real connection
// reports that no prober is available rather than guessing.
type LiveOptions struct {
	// Env is TESSERA_ENV; only "dev" may use Allow.
	Env string
	// Sealer opens the sealed connection credentials.
	Sealer *seal.Sealer
	// Allow is the dev-only private-target allowlist (TESSERA_SAFEDIAL_ALLOW).
	Allow []safedial.AllowEntry
	// Agent carries connections to private directories (the Directory Agent,
	// DR-11; not built yet). Nil today.
	Agent safedial.Transport
}

// connectionSecretAAD binds a sealed credential to its tenant and reference,
// so a blob copied to another row or tenant does not open.
func connectionSecretAAD(t tenancy.ID, ref string) []byte {
	return seal.AAD(t, "connection_secrets", "sealed", ref)
}

// loadCredential opens the sealed credential of a real revision into the
// bundle, inside the transaction that loaded it. Demo connections and
// revisions without a stored secret (a vault or agent reference, or no
// Sealer) get none. A secret that cannot be opened is an error: it fails
// closed rather than binding with something else.
func (s *Service) loadCredential(c *store.TenantTx, b *Bundle) error {
	if b.Simulated() || b.Rev.SecretRef == nil || !strings.HasPrefix(*b.Rev.SecretRef, "sealed:") || s.Runner.Live.Sealer == nil {
		return nil
	}
	blob, err := c.ConnectionSecret(*b.Rev.SecretRef)
	if errors.Is(err, store.ErrNotFound) {
		return nil // acknowledged but never stored (no Sealer when it was set)
	}
	if err != nil {
		return err
	}
	pt, err := s.Runner.Live.Sealer.Open(blob, connectionSecretAAD(c.Tenant(), *b.Rev.SecretRef))
	if err != nil {
		return fmt.Errorf("readiness: the stored credential cannot be opened: %w", err)
	}
	b.cred = ldap.Secret(pt)
	return nil
}

// liveCapable reports whether a revision's checks run against the real
// system (a real LDAP connection) rather than a simulation.
func liveCapable(b *Bundle) bool { return !b.Simulated() && b.Template.ID == "ldap" }

// liveProber returns the real prober for a non-demo revision, or ok=false
// for a type that has none yet (those keep their simulated prober, whose
// results can never gate a real type).
func (o LiveOptions) liveProber(b *Bundle, now time.Time) (p connectors.Prober, ok bool, err error) {
	if !liveCapable(b) {
		return nil, false, nil
	}
	cfg := b.Config
	if cfg.BindDN == "" || b.cred == "" {
		return nil, true, errors.New("readiness: no bind DN or stored credential for the LDAP connection")
	}
	var roots *x509.CertPool
	if cfg.CABundle != "" {
		if roots, err = caPool(cfg.CABundle); err != nil {
			return nil, true, err
		}
	}
	env, allow := o.Env, o.Allow
	if env != config.Dev {
		env, allow = config.Prod, nil
	}
	d, err := safedial.New(safedial.Options{Env: env, Allow: allow, RootCAs: roots, Agent: o.Agent})
	if err != nil {
		return nil, true, err
	}
	lp, err := ldap.New(ldap.Config{Host: cfg.Host, Port: cfg.Port, BindDN: cfg.BindDN, Password: b.cred, BaseDNs: cfg.BaseDNs,
		UserFilter: cfg.UserFilter, RootCAs: roots, Dialer: d, Now: func() time.Time { return now }})
	return lp, true, err
}
