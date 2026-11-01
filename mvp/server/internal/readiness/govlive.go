package readiness

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// GovOptions wire the real probers and connectors of the governed connector
// types (internal/connectors/governed): AWS Organizations, GitHub, SAP and
// Oracle, the privileged-access vaults, the contractor feeds and AgentCore.
// The zero value is safe: without a Client a real connection of these types has
// no prober, so every live check reports an error rather than running unguarded.
type GovOptions struct {
	// Client is the outbound client (safehttp.ForConfig): every request is
	// SSRF-guarded. The connection's configured port is added per revision
	// (safehttp.WithConfiguredPorts).
	Client *http.Client
	// Runtime is the validated process runtime (connsync.RuntimeFromConfig).
	Runtime connsync.Runtime
	// AWS builds the prober of an AWS Organizations connection over the given
	// guarded client (awsorg.GovernedProber; set by the server, because package
	// awsorg imports ingest and so cannot be imported here). Nil: no AWS prober.
	AWS func(p governed.Params, hc *http.Client, now func() time.Time) (connectors.Prober, error)
	// DataDir is TESSERA_LOADER_DATA_DIR, where an AgentCore snapshot is read from.
	DataDir string
	// Prod is true in a production deployment.
	Prod bool
	// Prober and Connector open the real prober and connector of a governed
	// connection (governed/wire.Prober and wire.Connector; set by the server,
	// because the connector packages cannot be imported here without a cycle
	// through ingest). Nil: such a connection has no prober or connector.
	Prober    func(p governed.Params, n governed.Net) (connectors.Prober, error)
	Connector func(p governed.Params, n governed.Net) (connectors.Connector, error)
}

// govLive reports whether a revision's checks run against the real system
// (a non-demo connection of a governed connector type).
func govLive(b *Bundle) bool {
	if b.Simulated() {
		return false
	}
	_, ok := governed.Lookup(b.Conn.ConnectorType)
	return ok
}

// storedLive reports whether a revision's connector is built from its stored
// config although its type is not governed (a Google Workspace connection: its
// org units, customer and domain scope the sync). Its checks keep their own prober.
func storedLive(b *Bundle) bool {
	return !b.Simulated() && b.Conn.ConnectorType == governed.GoogleWorkspace
}

// storedConnector builds the connector of a stored-config revision (storedLive).
func (o GovOptions) storedConnector(b *Bundle, now time.Time) (connectors.Connector, error) {
	if b.cred == "" {
		return nil, conflict("credential_unavailable", "the connection has no stored credential Tessera can open")
	}
	n, err := o.net(b, now)
	if err != nil {
		return nil, err
	}
	if o.Connector == nil {
		return nil, errors.New("readiness: no connector is wired for the connection")
	}
	return o.Connector(o.params(b), n)
}

// params is the connection as the governed package opens it.
func (o GovOptions) params(b *Bundle) governed.Params {
	return governed.Params{Type: b.Conn.ConnectorType, BaseURL: b.Config.BaseURL, Settings: b.Config.Settings,
		Secret: string(b.cred), Tenant: b.Conn.TenantID.String(), DataDir: o.DataDir, Prod: o.Prod,
		Customer: b.Config.Customer, Domain: b.Config.Domain, OrgUnits: b.Config.BaseDNs}
}

func (o GovOptions) net(b *Bundle, now time.Time) (governed.Net, error) {
	if o.Client == nil {
		return governed.Net{}, errors.New("readiness: no outbound HTTP client for the connection")
	}
	hc := safehttp.WithConfiguredPorts(o.Client, b.Config.BaseURL)
	n := governed.Net{RT: o.Runtime, HC: hc, Now: func() time.Time { return now }}
	if b.Conn.ConnectorType == governed.AWSOrg && o.AWS != nil {
		n.AWS = func(p governed.Params) (connectors.Prober, error) { return o.AWS(p, hc, n.Now) }
	}
	return n, nil
}

// needsSecret reports whether a type authenticates with a stored credential
// (AgentCore reads a recorded snapshot).
func needsSecret(typ string) bool { return typ != governed.AgentCore }

// prober returns the real prober of a non-demo governed revision, or ok=false
// for any other revision.
func (o GovOptions) prober(b *Bundle, now time.Time) (p connectors.Prober, ok bool, err error) {
	if !govLive(b) {
		return nil, false, nil
	}
	if needsSecret(b.Conn.ConnectorType) && b.cred == "" {
		return nil, true, errors.New("readiness: no stored credential for the connection (a vault reference cannot be opened by Tessera)")
	}
	n, err := o.net(b, now)
	if err != nil {
		return nil, true, err
	}
	if o.Prober == nil {
		return nil, true, errors.New("readiness: no prober is wired for the connection")
	}
	p, err = o.Prober(o.params(b), n)
	return p, true, err
}

// connector returns what a dry run or a first sync of a governed revision
// discovers through: the existing connector built from the connection's
// settings (PAM, ERP, GitHub scan, AgentCore). A type that hands over to its
// own feature (AWS connectors, contractor feeds) is read for its probe only,
// so the dry run still proves the source is reachable and readable; the
// feature reads it once activated.
func (o GovOptions) connector(b *Bundle, now time.Time) (connectors.Connector, error) {
	t, ok := governed.Lookup(b.Conn.ConnectorType)
	if !ok || b.Simulated() {
		return nil, conflict("connector_unavailable", "no %s connector is available", b.Conn.ConnectorType)
	}
	if needsSecret(t.ID) && b.cred == "" {
		return nil, conflict("credential_unavailable", "the connection has no stored credential Tessera can open")
	}
	n, err := o.net(b, now)
	if err != nil {
		return nil, err
	}
	if o.Prober == nil || o.Connector == nil {
		return nil, errors.New("readiness: no connector is wired for the connection")
	}
	if t.Feature {
		p, err := o.Prober(o.params(b), n)
		if err != nil {
			return nil, err
		}
		return &featureProbe{t: t, name: b.Conn.Name, p: p}, nil
	}
	return o.Connector(o.params(b), n)
}

// featureProbe is the dry-run connector of a type whose records are read by its
// own feature: it proves authentication and a read, and stages nothing.
type featureProbe struct {
	t    governed.Type
	name string
	p    connectors.Prober
}

func (f *featureProbe) System() string      { return f.t.System }
func (f *featureProbe) DisplayName() string { return f.name }
func (f *featureProbe) TypeName() string    { return "Governed" + f.t.ID + "Probe" }

// Discover reads through the probe and returns an empty result.
func (f *featureProbe) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	a, err := f.p.Authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if !a.OK {
		return nil, errors.New("the source refused the credential")
	}
	if _, err := f.p.Sample(ctx, connectors.SampleQuery{Op: "probe", Limit: connectors.MaxSample}); err != nil {
		return nil, err
	}
	return &connectors.DiscoveryResult{}, nil
}

func (*featureProbe) StreamEvents(context.Context, *time.Time, func(connectors.Event) error) error {
	return nil
}
