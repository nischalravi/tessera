package readiness

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/agent"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/ldap"
	"github.com/nischalravi/tessera/mvp/server/internal/obs"
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
	// Agents reaches the Directory Agents (DR-11). A connection whose
	// credential reference is agent:<id>/<name> is probed only through its
	// agent (typed operations; the agent holds the credential and enforces its
	// own target allowlist), never by a direct dial. Nil: such a connection
	// reports that no prober is available.
	Agents AgentLink
}

// AgentLink is what readiness needs of the Directory Agent service: send a
// typed job, and check that an agent of the tenant exists and is active.
// *agent.Service implements it.
type AgentLink interface {
	agent.Dispatcher
	Active(c *store.TenantTx, id string) (*agent.View, error)
}

// connectionSecretAAD binds a sealed credential to its tenant, connection and
// reference, so a blob copied to another row or tenant does not open.
func connectionSecretAAD(t tenancy.ID, connectionID, ref string) []byte {
	return store.CredentialAAD(t, connectionID, store.PurposeBind, ref)
}

// loadCredential opens the sealed credential of a real revision into the
// bundle, inside the transaction that loaded it. Demo connections and
// revisions without a stored secret (a vault or agent reference, or no
// Sealer) get none. A secret that cannot be opened is an error: it fails
// closed rather than binding with something else.
func (s *Service) loadCredential(c *store.TenantTx, b *Bundle) error {
	if !b.Simulated() && agentRef(b) {
		return s.bindAgent(c, b)
	}
	if b.Simulated() || b.Rev.SecretRef == nil || !strings.HasPrefix(*b.Rev.SecretRef, "sealed:") || s.Runner.Live.Sealer == nil {
		return nil
	}
	k, err := c.Credential(b.Conn.ID, store.PurposeBind, *b.Rev.SecretRef)
	if errors.Is(err, store.ErrNotFound) {
		return nil // acknowledged but never stored (no Sealer when it was set)
	}
	if err != nil {
		return err
	}
	pt, err := s.Runner.Live.Sealer.Open(k.Sealed, connectionSecretAAD(c.Tenant(), b.Conn.ID, *b.Rev.SecretRef))
	if err != nil {
		return fmt.Errorf("readiness: the stored credential cannot be opened: %w", err)
	}
	b.cred = ldap.Secret(pt)
	return nil
}

// agentRef reports whether the revision's credential is on a Directory Agent.
func agentRef(b *Bundle) bool {
	return b.Rev != nil && b.Rev.SecretRef != nil && strings.HasPrefix(*b.Rev.SecretRef, "agent:")
}

// bindAgent resolves an agent:<id>/<name> credential reference: the agent
// must exist in this tenant and be active (a revoked or foreign agent is an
// error, so the run fails closed rather than falling back to a direct dial).
// The secret is not here: the agent holds it.
func (s *Service) bindAgent(c *store.TenantTx, b *Bundle) error {
	id, name, ok := agent.ParseRef(*b.Rev.SecretRef)
	if !ok {
		return errors.New("readiness: the Directory Agent credential reference is malformed")
	}
	if s.Runner.Live.Agents == nil {
		return nil // liveProber reports that no prober is available
	}
	if _, err := s.Runner.Live.Agents.Active(c, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return errors.New("readiness: the Directory Agent of this connection does not exist or is revoked")
		}
		return err
	}
	b.agentID, b.agentCred = id, name
	return nil
}

// liveCapable reports whether a revision's checks run against the real
// system (a real LDAP connection) rather than a simulation.
func liveCapable(b *Bundle) bool {
	return !b.Simulated() && (b.Template.ID == "ldap" || b.Template.ID == "racf")
}

// liveProber returns the real prober for a non-demo revision, or ok=false
// for a type that has none yet (those keep their simulated prober, whose
// results can never gate a real type).
func (o LiveOptions) liveProber(b *Bundle, now time.Time) (p connectors.Prober, ok bool, err error) {
	if !liveCapable(b) {
		return nil, false, nil
	}
	cfg := b.Config
	var roots *x509.CertPool
	if cfg.CABundle != "" {
		if roots, err = caPool(cfg.CABundle); err != nil {
			return nil, true, err
		}
	}
	if agentRef(b) {
		// Private directory: typed operations through the Directory Agent. No
		// direct dial and no fallback to one when the agent is unavailable.
		if o.Agents == nil || b.agentID == "" || cfg.BindDN == "" {
			return nil, true, errors.New("readiness: no Directory Agent, or no bind DN, for the LDAP connection")
		}
		rp, err := agent.NewRemoteProber(o.Agents, b.Conn.TenantID, b.agentID, agent.Target{Host: cfg.Host, Port: cfg.Port, TLSMode: cfg.TLSMode},
			agent.ProbeConfig{BindDN: cfg.BindDN, CredName: b.agentCred, BaseDNs: cfg.BaseDNs, UserFilter: cfg.UserFilter,
				CABundle: cfg.CABundle})
		return rp, true, err
	}
	if b.Template.ID != "ldap" {
		// RACF is read only through a Directory Agent: never a direct dial from
		// the server, whatever credential the revision holds.
		return nil, true, errors.New("readiness: this connection is read only through a Directory Agent")
	}
	if cfg.BindDN == "" || b.cred == "" {
		return nil, true, errors.New("readiness: no bind DN or stored credential for the LDAP connection")
	}
	env, allow := o.Env, o.Allow
	if env != config.Dev {
		env, allow = config.Prod, nil
	}
	d, err := safedial.New(safedial.Options{Env: env, Allow: allow, RootCAs: roots})
	if err != nil {
		return nil, true, err
	}
	lp, err := ldap.New(ldap.Config{Host: cfg.Host, Port: cfg.Port, TLSMode: cfg.TLSMode, BindDN: cfg.BindDN, Password: b.cred, BaseDNs: cfg.BaseDNs,
		UserFilter: cfg.UserFilter, RootCAs: roots, Dialer: d, Now: func() time.Time { return now }})
	if err != nil {
		return nil, true, err
	}
	return meteredProber{lp}, true, nil
}

// meteredProber records each real directory operation in the connector call
// metrics (tessera_connector_*; connector "ldap", op = the operation name).
// An unsupported operation is an answer, not a failure.
type meteredProber struct{ connectors.Prober }

func observe[T any](op string, fn func() (T, error)) (T, error) {
	done := obs.StartCall(obs.ConnLDAP, op)
	v, err := fn()
	if errors.Is(err, connectors.ErrUnsupported) {
		done(nil)
	} else {
		done(err)
	}
	return v, err
}

func (m meteredProber) Connect(ctx context.Context) (connectors.ConnInfo, error) {
	return observe("connect", func() (connectors.ConnInfo, error) { return m.Prober.Connect(ctx) })
}

func (m meteredProber) Authenticate(ctx context.Context) (connectors.AuthInfo, error) {
	return observe("authenticate", func() (connectors.AuthInfo, error) { return m.Prober.Authenticate(ctx) })
}

func (m meteredProber) RootInfo(ctx context.Context) (connectors.RootInfo, error) {
	return observe("root_info", func() (connectors.RootInfo, error) { return m.Prober.RootInfo(ctx) })
}

func (m meteredProber) ObjectExists(ctx context.Context, ref string) (bool, error) {
	return observe("object_exists", func() (bool, error) { return m.Prober.ObjectExists(ctx, ref) })
}

func (m meteredProber) Sample(ctx context.Context, q connectors.SampleQuery) (connectors.SampleStats, error) {
	return observe("sample", func() (connectors.SampleStats, error) { return m.Prober.Sample(ctx, q) })
}

func (m meteredProber) EffectiveRights(ctx context.Context, ref string) (connectors.Rights, error) {
	return observe("effective_rights", func() (connectors.Rights, error) { return m.Prober.EffectiveRights(ctx, ref) })
}

func (m meteredProber) ChangeFeed(ctx context.Context) (connectors.FeedInfo, error) {
	return observe("change_feed", func() (connectors.FeedInfo, error) { return m.Prober.ChangeFeed(ctx) })
}
