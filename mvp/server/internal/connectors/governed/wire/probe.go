package wire

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/agentcore"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/azurerbac"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/erp"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/gcpiam"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/githubscan"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/pam"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/successfactors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/vms"
)

// Probe limits: the probe reads a bounded number of objects and keeps counts
// only (design §5.2: no attribute values, no personal data).
const (
	maxProbeSafes = 25
	sentinelAfter = 100 // records read from a contractor feed before the probe stops
)

// Prober returns the read-only prober of a connection, built over the
// connector's own client. A type with no prober here (the feature types are
// probed through their own readers, below) is an error; every operation a
// check calls is one read.
func Prober(p governed.Params, n governed.Net) (connectors.Prober, error) {
	switch p.Type {
	case governed.CyberArk, governed.Delinea, governed.BeyondTrust:
		getenv, err := p.Env()
		if err != nil {
			return nil, err
		}
		cfg, err := pam.ConfigFromEnv(p.Type, getenv)
		if err != nil {
			return nil, err
		}
		v, err := pam.Open(cfg, n.RT, n.HC, n.Clock)
		if err != nil {
			return nil, err
		}
		return &pamProber{v: v, user: cfg.Username, base: p.BaseURL, hc: n.HC, vendor: p.Type}, nil
	case governed.SAP, governed.Oracle:
		getenv, err := p.Env()
		if err != nil {
			return nil, err
		}
		cfg, err := erp.ConfigFromEnv(p.Type, getenv)
		if err != nil {
			return nil, err
		}
		s, err := erp.Open(cfg, n.RT, n.HC, n.Clock)
		if err != nil {
			return nil, err
		}
		return &erpProber{s: s, id: cfg.ClientID, base: p.BaseURL, hc: n.HC}, nil
	case governed.GitHubScan:
		getenv, err := p.Env()
		if err != nil {
			return nil, err
		}
		cfg, err := githubscan.RESTConfigFromEnv(getenv)
		if err != nil {
			return nil, err
		}
		src, err := githubscan.NewREST(cfg, n.RT, n.HC, n.Clock)
		if err != nil {
			return nil, err
		}
		base := cfg.APIURL
		if base == "" {
			base = githubscan.DefaultAPIURL
		}
		return &githubProber{src: src, org: cfg.Org, base: base, hc: n.HC}, nil
	case governed.SuccessFactors:
		getenv, err := p.Env()
		if err != nil {
			return nil, err
		}
		cfg, err := successfactors.ConfigFromEnv(getenv)
		if err != nil {
			return nil, err
		}
		c, err := successfactors.New(cfg, n.RT, n.HC, n.Clock)
		if err != nil {
			return nil, err
		}
		mode := "basic_auth"
		if cfg.Auth == successfactors.AuthSAML {
			mode = successfactors.AuthSAML
		}
		return &sfProber{c: c, user: cfg.Username, mode: mode, base: p.BaseURL, hc: n.HC}, nil
	case governed.AgentCore:
		getenv, err := p.Env()
		if err != nil {
			return nil, err
		}
		if getenv("TESSERA_ENV") == config.Prod {
			return nil, errors.New("agentcore: only a recorded snapshot is available (no live governed.AgentCore client is built); refused in prod")
		}
		return &agentcoreProber{api: agentcore.FileAPI{Path: getenv("TESSERA_AGENTCORE_SNAPSHOT")}}, nil
	case governed.Fieldglass, governed.Beeline, governed.CSVFeed:
		r, err := VmsReader(p, n)
		if err != nil {
			return nil, err
		}
		return &vmsProber{r: r, base: p.BaseURL, hc: n.HC, typ: p.Type}, nil
	case governed.AzureRBAC, governed.GCPIAM:
		getenv, err := p.Env()
		if err == nil {
			getenv, err = n.Overrides(getenv)
		}
		if err != nil {
			return nil, err
		}
		if p.Type == governed.AzureRBAC {
			cfg, err := azurerbac.ConfigFromEnv(getenv)
			if err != nil {
				return nil, err
			}
			c, err := azurerbac.New(cfg, n.RT, n.HC, n.Clock)
			if err != nil {
				return nil, err
			}
			return &cloudProber{id: cfg.ClientID, probe: func(ctx context.Context) (cloudProbe, error) {
				r, err := c.Probe(ctx)
				return cloudProbe{mode: c.Mode(), counts: map[string]int{"scope": r.Scopes, "assignment": r.Assignments, "role": r.Roles}}, err
			}, refused: azurerbac.ErrCredential}, nil
		}
		cfg, err := gcpiam.ConfigFromEnv(getenv)
		if err != nil {
			return nil, err
		}
		c, err := gcpiam.New(cfg, n.RT, n.HC, n.Clock)
		if err != nil {
			return nil, err
		}
		return &cloudProber{id: c.Identity(), probe: func(ctx context.Context) (cloudProbe, error) {
			r, err := c.Probe(ctx)
			return cloudProbe{mode: "json_key", counts: map[string]int{"resource": r.Resources, "binding": r.Bindings}}, err
		}, refused: gcpiam.ErrCredential}, nil
	case governed.AWSOrg:
		if n.AWS == nil {
			return nil, errors.New("awsorg: no AWS client")
		}
		return n.AWS(p)
	}
	return nil, errors.New("governed: no prober for type " + p.Type)
}

// VmsReader builds the contractor-feed reader of a connection exactly as the
// contractor sources do (vms.New for governed.Fieldglass and governed.Beeline, a fetched CSV for
// a feed). Secret is client_id:client_secret for the REST vendors and an
// optional bearer token for a CSV feed.
func VmsReader(p governed.Params, n governed.Net) (connectors.VmsConnector, error) {
	set := VmsSettings(p)
	if p.Type == governed.CSVFeed {
		base, err := connsync.ParseBaseURL(p.BaseURL, n.RT)
		if err != nil {
			return nil, errors.New("base URL: " + err.Error())
		}
		if err := set.Validate("csv"); err != nil {
			return nil, err
		}
		u := *base
		u.Path = set.CSVPath
		return csvReader{&vms.CSVFetcher{URL: u.String(), Token: connsync.NewSecret(p.Secret), HC: n.HC, Settings: set, Now: n.Clock}}, nil
	}
	return vms.New(vms.Config{Vendor: p.Type, BaseURL: p.BaseURL, Settings: set, Credential: p.Secret}, n.RT, n.HC, n.Clock)
}

// VmsSettings are the contractor feed settings of a connection, as the feed's
// own JSON (vms_sources.settings).
func VmsSettings(p governed.Params) vms.Settings {
	s := vms.Settings{WorkersPath: strings.TrimSpace(p.Settings["workers_path"]), TokenPath: strings.TrimSpace(p.Settings["token_path"]),
		CSVPath: strings.TrimSpace(p.Settings["csv_path"])}
	if v := strings.TrimSpace(p.Settings["page_size"]); v != "" {
		s.PageSize, _ = strconv.Atoi(v)
	}
	return s
}

type csvReader struct{ f *vms.CSVFetcher }

func (c csvReader) VmsRecords(ctx context.Context, _ *time.Time, yield func(*connectors.VmsRecord) error) error {
	res, err := c.f.Fetch(ctx)
	if err != nil {
		return err
	}
	for _, r := range res.Records {
		if err := yield(r); err != nil {
			return err
		}
	}
	return nil
}

// noop answers every operation as unsupported; a prober overrides what its
// system can answer.
type noop struct{}

func (noop) Connect(context.Context) (connectors.ConnInfo, error) {
	return connectors.ConnInfo{}, connectors.ErrUnsupported
}
func (noop) Authenticate(context.Context) (connectors.AuthInfo, error) {
	return connectors.AuthInfo{}, connectors.ErrUnsupported
}
func (noop) RootInfo(context.Context) (connectors.RootInfo, error) {
	return connectors.RootInfo{}, connectors.ErrUnsupported
}
func (noop) ObjectExists(context.Context, string) (bool, error) {
	return false, connectors.ErrUnsupported
}
func (noop) Sample(context.Context, connectors.SampleQuery) (connectors.SampleStats, error) {
	return connectors.SampleStats{}, connectors.ErrUnsupported
}
func (noop) EffectiveRights(context.Context, string) (connectors.Rights, error) {
	return connectors.Rights{}, connectors.ErrUnsupported
}
func (noop) ChangeFeed(context.Context) (connectors.FeedInfo, error) {
	return connectors.FeedInfo{}, connectors.ErrUnsupported
}
func (noop) RateLimits(context.Context) (connectors.RateInfo, error) {
	return connectors.RateInfo{}, connectors.ErrUnsupported
}
func (noop) Time(context.Context) (time.Time, error) { return time.Time{}, connectors.ErrUnsupported }

// httpConnect reports whether the service answers over verified TLS. Any HTTP
// answer counts as reachable; the TLS fields describe the verified handshake
// (the safehttp client verifies the chain and the name). A target the network
// policy refuses reports not reachable.
func httpConnect(ctx context.Context, hc *http.Client, base string) (connectors.ConnInfo, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return connectors.ConnInfo{}, nil
	}
	root := url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/"}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, root.String(), nil)
	if err != nil {
		return connectors.ConnInfo{}, nil
	}
	req.Header.Set("User-Agent", "tessera-readiness/1")
	resp, err := hc.Do(req) // #nosec G107 G704 -- hc is the SSRF-guarded safehttp client; base is the connection's stored URL
	if err != nil {
		var (
			ua x509.UnknownAuthorityError
			ci x509.CertificateInvalidError
			he x509.HostnameError
		)
		switch {
		case errors.As(err, &ua), errors.As(err, &ci), errors.As(err, &he):
			return connectors.ConnInfo{Reachable: true}, nil // answered, but the chain or the name is wrong
		case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
			return connectors.ConnInfo{}, err
		}
		return connectors.ConnInfo{}, nil // refused by safehttp, DNS failure, connection refused
	}
	defer resp.Body.Close()
	info := connectors.ConnInfo{Reachable: true}
	if resp.TLS != nil {
		info.TLSVersion = tlsName(resp.TLS.Version)
		info.ChainValid, info.HostnameMatch = true, true
		if len(resp.TLS.PeerCertificates) > 0 {
			leaf := resp.TLS.PeerCertificates[0]
			info.NotAfter, info.Issuer = leaf.NotAfter, leaf.Issuer.CommonName
		}
	}
	return info, nil
}

func tlsName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "1.3"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS10:
		return "1.0"
	}
	return ""
}

// denied reports whether an error is the source refusing the credential (401
// or 403): an answer to the authentication check, not a failure of the probe.
func denied(err error) bool {
	s := connsync.Status(err)
	return s == http.StatusUnauthorized || s == http.StatusForbidden
}

// ---------------------------------------------------------------- PAM

type pamProber struct {
	noop
	v      pam.Vault
	user   string
	base   string
	hc     *http.Client
	vendor string
	safes  []pam.Safe
}

func (p *pamProber) Connect(ctx context.Context) (connectors.ConnInfo, error) {
	return httpConnect(ctx, p.hc, p.base)
}

func (p *pamProber) list(ctx context.Context) error {
	if p.safes != nil {
		return nil
	}
	s, err := p.v.Safes(ctx)
	if err != nil {
		return err
	}
	if s == nil {
		s = []pam.Safe{}
	}
	p.safes = s
	return nil
}

func (p *pamProber) Authenticate(ctx context.Context) (connectors.AuthInfo, error) {
	mode := "password"
	if p.vendor == governed.BeyondTrust {
		mode = "api_token"
	}
	if err := p.list(ctx); err != nil {
		if denied(err) {
			return connectors.AuthInfo{OK: false, Mode: mode}, nil
		}
		return connectors.AuthInfo{}, err
	}
	return connectors.AuthInfo{OK: true, Identity: p.user, Mode: mode}, nil
}

// Sample reads the safes, then the members and accounts of the first few:
// counts only.
func (p *pamProber) Sample(ctx context.Context, _ connectors.SampleQuery) (connectors.SampleStats, error) {
	if err := p.list(ctx); err != nil {
		return connectors.SampleStats{}, err
	}
	st := connectors.SampleStats{PerClass: map[string]int{"safe": len(p.safes)}, Available: true}
	for i, s := range p.safes {
		if i >= maxProbeSafes {
			break
		}
		ms, err := p.v.Members(ctx, s)
		if err != nil {
			return st, err
		}
		as, err := p.v.Accounts(ctx, s)
		if err != nil {
			return st, err
		}
		st.PerClass["member"] += len(ms)
		st.PerClass["vaulted_account"] += len(as)
	}
	st.Objects = min(len(p.safes)+st.PerClass["member"]+st.PerClass["vaulted_account"], connectors.MaxSample)
	return st, nil
}

// EffectiveRights reads which of the first safes the service user may
// manage the members of, the right a write-back (SetMember, RemoveMember)
// needs: those safes are what the user could write to.
func (p *pamProber) EffectiveRights(ctx context.Context, _ string) (connectors.Rights, error) {
	if err := p.list(ctx); err != nil {
		return connectors.Rights{}, err
	}
	var r connectors.Rights
	for i, s := range p.safes {
		if i >= maxProbeSafes {
			break
		}
		ms, err := p.v.Members(ctx, s)
		if err != nil {
			return r, err
		}
		for _, m := range ms {
			if strings.EqualFold(m.Name, p.user) && slices.Contains(m.Perms, pam.PermManageMembers) {
				r.Writable = append(r.Writable, s.ID)
			}
		}
	}
	return r, nil
}

// ---------------------------------------------------------------- ERP

type erpProber struct {
	noop
	s     erp.System
	id    string
	base  string
	hc    *http.Client
	roles []erp.Role
	read  bool
}

func (p *erpProber) Connect(ctx context.Context) (connectors.ConnInfo, error) {
	return httpConnect(ctx, p.hc, p.base)
}

func (p *erpProber) loadRoles(ctx context.Context) error {
	if p.read {
		return nil
	}
	r, err := p.s.Roles(ctx)
	if err != nil {
		return err
	}
	p.roles, p.read = r, true
	return nil
}

func (p *erpProber) Authenticate(ctx context.Context) (connectors.AuthInfo, error) {
	if err := p.loadRoles(ctx); err != nil {
		if denied(err) {
			return connectors.AuthInfo{OK: false, Mode: "client_secret"}, nil
		}
		return connectors.AuthInfo{}, err
	}
	return connectors.AuthInfo{OK: true, Identity: p.id, Mode: "client_secret"}, nil
}

func (p *erpProber) Sample(ctx context.Context, _ connectors.SampleQuery) (connectors.SampleStats, error) {
	if err := p.loadRoles(ctx); err != nil {
		return connectors.SampleStats{}, err
	}
	users, err := p.s.Users(ctx)
	if err != nil {
		return connectors.SampleStats{}, err
	}
	return connectors.SampleStats{Objects: min(len(p.roles)+len(users), connectors.MaxSample), Available: true,
		PerClass: map[string]int{"role": len(p.roles), "user": len(users)}}, nil
}

// ---------------------------------------------------------------- Azure RBAC and Google Cloud IAM

// cloudProbe is what one probe read: how the connection authenticated and counts per class.
type cloudProbe struct {
	mode   string
	counts map[string]int
}

// cloudProber probes a cloud entitlement connector with one bounded read (the first few scopes or
// resources). The endpoints are fixed (the public cloud), so there is no transport check of the
// connection's own: Connect reports nothing and the template has no endpoint item.
type cloudProber struct {
	noop
	id      string
	probe   func(context.Context) (cloudProbe, error)
	refused error
	res     cloudProbe
	err     error
	read    bool
}

func (p *cloudProber) load(ctx context.Context) error {
	if !p.read {
		p.res, p.err = p.probe(ctx)
		p.read = true
	}
	return p.err
}

func (p *cloudProber) Authenticate(ctx context.Context) (connectors.AuthInfo, error) {
	if err := p.load(ctx); err != nil {
		if errors.Is(err, p.refused) || denied(err) {
			return connectors.AuthInfo{OK: false, Mode: p.res.mode}, nil
		}
		return connectors.AuthInfo{}, err
	}
	return connectors.AuthInfo{OK: true, Identity: p.id, Mode: p.res.mode}, nil
}

func (p *cloudProber) Sample(ctx context.Context, _ connectors.SampleQuery) (connectors.SampleStats, error) {
	if err := p.load(ctx); err != nil {
		return connectors.SampleStats{}, err
	}
	n := 0
	for _, c := range p.res.counts {
		n += c
	}
	return connectors.SampleStats{Objects: min(n, connectors.MaxSample), Available: true, PerClass: p.res.counts}, nil
}

// ---------------------------------------------------------------- GitHub

type githubProber struct {
	noop
	src   githubscan.Source
	org   string
	base  string
	hc    *http.Client
	repos []githubscan.Repo
	read  bool
}

func (p *githubProber) Connect(ctx context.Context) (connectors.ConnInfo, error) {
	return httpConnect(ctx, p.hc, p.base)
}

func (p *githubProber) loadRepos(ctx context.Context) error {
	if p.read {
		return nil
	}
	r, err := p.src.Repos(ctx)
	if err != nil {
		return err
	}
	p.repos, p.read = r, true
	return nil
}

func (p *githubProber) Authenticate(ctx context.Context) (connectors.AuthInfo, error) {
	if err := p.loadRepos(ctx); err != nil {
		if denied(err) {
			return connectors.AuthInfo{OK: false, Mode: "api_token"}, nil
		}
		return connectors.AuthInfo{}, err
	}
	return connectors.AuthInfo{OK: true, Identity: p.org, Mode: "api_token"}, nil
}

func (p *githubProber) Sample(ctx context.Context, _ connectors.SampleQuery) (connectors.SampleStats, error) {
	if err := p.loadRepos(ctx); err != nil {
		return connectors.SampleStats{}, err
	}
	return connectors.SampleStats{Objects: min(len(p.repos), connectors.MaxSample), Available: true,
		PerClass: map[string]int{"repository": len(p.repos)}}, nil
}

// ---------------------------------------------------------------- SuccessFactors

type sfProber struct {
	noop
	c    *successfactors.Connector
	user string
	mode string
	base string
	hc   *http.Client
}

func (p *sfProber) Connect(ctx context.Context) (connectors.ConnInfo, error) {
	return httpConnect(ctx, p.hc, p.base)
}

// Authenticate is one bounded read of User: the credential is accepted when it
// is answered (an empty tenant still proves the credential; the read check
// reports it). A 400 from the token endpoint is a refused assertion.
func (p *sfProber) Authenticate(ctx context.Context) (connectors.AuthInfo, error) {
	if _, err := p.c.Probe(ctx, 1); err != nil && !successfactors.ErrNoRows(err) {
		if denied(err) || connsync.Status(err) == http.StatusBadRequest {
			return connectors.AuthInfo{OK: false, Mode: p.mode}, nil
		}
		return connectors.AuthInfo{}, err
	}
	return connectors.AuthInfo{OK: true, Identity: p.user, Mode: p.mode}, nil
}

// Sample reads one page of User with the connector's own field selection and
// reports counts and field names only, never values.
func (p *sfProber) Sample(ctx context.Context, q connectors.SampleQuery) (connectors.SampleStats, error) {
	pr, err := p.c.Probe(ctx, min(q.Limit, connectors.MaxSample))
	if err != nil && !successfactors.ErrNoRows(err) {
		return connectors.SampleStats{}, err
	}
	return connectors.SampleStats{Objects: pr.Users, Available: true, Fields: pr.Fields,
		PerClass: map[string]int{"user": pr.Users}}, nil
}

// ---------------------------------------------------------------- governed.AgentCore

type agentcoreProber struct {
	noop
	api agentcore.API
}

func (p *agentcoreProber) Sample(ctx context.Context, _ connectors.SampleQuery) (connectors.SampleStats, error) {
	rs, err := p.api.Runtimes(ctx)
	if err != nil {
		return connectors.SampleStats{}, err
	}
	st := connectors.SampleStats{Available: true, PerClass: map[string]int{"agent_runtime": len(rs)}}
	for _, r := range rs {
		st.PerClass["credential"] += len(r.Credentials)
		st.PerClass["access"] += len(r.Access)
	}
	st.Objects = min(len(rs)+st.PerClass["credential"]+st.PerClass["access"], connectors.MaxSample)
	return st, nil
}

// ---------------------------------------------------------------- contractor feeds

type vmsProber struct {
	noop
	r     connectors.VmsConnector
	base  string
	hc    *http.Client
	typ   string
	read  bool
	count int
	err   error
}

var errEnough = errors.New("governed: enough records read for the probe")

func (p *vmsProber) Connect(ctx context.Context) (connectors.ConnInfo, error) {
	return httpConnect(ctx, p.hc, p.base)
}

// load reads up to sentinelAfter records once: that call acquires the token
// (REST vendors) and reads the first page, so it is the authentication and the
// read probe at once.
func (p *vmsProber) load(ctx context.Context) error {
	if !p.read {
		err := p.r.VmsRecords(ctx, nil, func(*connectors.VmsRecord) error {
			p.count++
			if p.count >= sentinelAfter {
				return errEnough
			}
			return nil
		})
		if errors.Is(err, errEnough) {
			err = nil
		}
		p.read, p.err = true, err
	}
	return p.err
}

func (p *vmsProber) Authenticate(ctx context.Context) (connectors.AuthInfo, error) {
	mode := "oauth_client_credentials"
	if p.typ == governed.CSVFeed {
		mode = "bearer_token"
	}
	if err := p.load(ctx); err != nil {
		if denied(err) {
			return connectors.AuthInfo{OK: false, Mode: mode}, nil
		}
		return connectors.AuthInfo{}, err
	}
	return connectors.AuthInfo{OK: true, Mode: mode}, nil
}

func (p *vmsProber) Sample(ctx context.Context, _ connectors.SampleQuery) (connectors.SampleStats, error) {
	if err := p.load(ctx); err != nil {
		return connectors.SampleStats{}, err
	}
	return connectors.SampleStats{Objects: p.count, Available: true, PerClass: map[string]int{"assignment": p.count}}, nil
}
