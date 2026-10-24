package restgen

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// Prober is the read-only readiness prober of a REST connection: it checks
// that the endpoint is reachable, that the credential works, and that the
// users mapping yields records. It sends GET requests only (and the OAuth
// token request), and keeps counts and field names, never attribute values.
type Prober struct {
	spec *Spec
	c    *Client
}

var _ connectors.Prober = (*Prober)(nil)

// NewProber returns the prober for a Spec. hc must come from internal/safehttp.
func NewProber(spec *Spec, sec Secrets, rt connsync.Runtime, hc *http.Client) (*Prober, error) {
	if errs := spec.Validate(rt); len(errs) > 0 {
		return nil, errs
	}
	c, err := NewClient(spec, sec, rt, hc)
	if err != nil {
		return nil, err
	}
	return &Prober{spec: spec, c: c}, nil
}

func tlsName(v uint16) string {
	switch v {
	case 0x0304:
		return "1.3"
	case 0x0303:
		return "1.2"
	case 0x0302:
		return "1.1"
	case 0x0301:
		return "1.0"
	}
	return ""
}

// Connect makes an unauthenticated GET of the base URL. Any answer, 401
// included, shows the endpoint is reachable; the handshake is what is judged.
func (p *Prober) Connect(ctx context.Context) (connectors.ConnInfo, error) {
	u, err := buildURL(p.c.base, "", nil)
	if err != nil {
		return connectors.ConnInfo{}, err
	}
	resp, err := p.c.do(ctx, request{method: http.MethodGet, u: u, anon: true})
	if err != nil {
		return connectors.ConnInfo{}, err
	}
	ci := connectors.ConnInfo{Reachable: true}
	if st := resp.TLS; st != nil {
		// the guarded client verifies the chain and the host name before it answers
		ci.TLSVersion, ci.ChainValid, ci.HostnameMatch = tlsName(st.Version), st.HandshakeComplete, st.HandshakeComplete
		if len(st.PeerCertificates) > 0 {
			ci.NotAfter, ci.Issuer = st.PeerCertificates[0].NotAfter, st.PeerCertificates[0].Issuer.CommonName
		}
	}
	return ci, nil
}

// Authenticate gets a token (OAuth) or makes one authenticated read, and
// reports whether the system accepted the credential.
func (p *Prober) Authenticate(ctx context.Context) (connectors.AuthInfo, error) {
	a := p.spec.Auth
	info := connectors.AuthInfo{Mode: map[string]string{AuthOAuth2: "client_secret", AuthAPIKey: "api_token", AuthBasic: "basic", AuthBearer: "bearer_token"}[a.Type]}
	info.Identity = a.ClientID
	if a.Type == AuthBasic {
		info.Identity = a.Username
	}
	if a.Type == AuthOAuth2 {
		info.Scopes = a.Scopes
		if _, err := p.c.accessToken(ctx); err != nil {
			var se *StatusError
			if errors.As(err, &se) && (se.Status == 400 || se.Status == 401 || se.Status == 403) {
				return info, nil // refused: OK stays false
			}
			return info, err
		}
	}
	// the credential is only proved by the API accepting it
	r := p.probeResource()
	if r == nil {
		info.OK = a.Type == AuthOAuth2
		return info, nil
	}
	u, err := p.firstPage(r.list())
	if err != nil {
		return info, err
	}
	resp, err := p.c.do(ctx, request{method: http.MethodGet, u: u})
	if err != nil {
		return info, err
	}
	switch {
	case resp.Status >= 200 && resp.Status < 300:
		info.OK = true
	case resp.Status == http.StatusUnauthorized || resp.Status == http.StatusForbidden:
	default:
		return info, &StatusError{Status: resp.Status, Op: "authenticate", Detail: errorDetail(resp.Body), RetryAfter: resp.RetryAfter}
	}
	return info, nil
}

func (p *Prober) probeResource() *Resource {
	for _, r := range []*Resource{p.spec.Users, p.spec.Groups, p.spec.Entitlements} {
		if r != nil {
			return r
		}
	}
	return nil
}

func (p *Prober) firstPage(ls listSpec) (u *url.URL, err error) {
	path, err := expandPath(ls.path, nil)
	if err != nil {
		return nil, err
	}
	q := expandQuery(ls.query, nil)
	if ls.pg.SizeParam != "" && ls.pg.PageSize > 0 {
		q.Set(ls.pg.SizeParam, fmt.Sprint(ls.pg.PageSize))
	}
	return buildURL(p.c.base, path, q)
}

// RootInfo is not offered by a generic REST system.
func (p *Prober) RootInfo(context.Context) (connectors.RootInfo, error) {
	return connectors.RootInfo{}, connectors.ErrUnsupported
}

// ObjectExists is not offered.
func (p *Prober) ObjectExists(context.Context, string) (bool, error) {
	return false, connectors.ErrUnsupported
}

// EffectiveRights is not offered: a generic REST system does not say what a credential may write.
func (p *Prober) EffectiveRights(context.Context, string) (connectors.Rights, error) {
	return connectors.Rights{Unsupported: true}, nil
}

// ChangeFeed is not offered.
func (p *Prober) ChangeFeed(context.Context) (connectors.FeedInfo, error) {
	return connectors.FeedInfo{}, connectors.ErrUnsupported
}

// Time is not offered.
func (p *Prober) Time(context.Context) (time.Time, error) {
	return time.Time{}, connectors.ErrUnsupported
}

// RateLimits reports the throttling and rate-limit headers seen so far.
func (p *Prober) RateLimits(context.Context) (connectors.RateInfo, error) {
	s := p.c.Stats()
	ri := connectors.RateInfo{Throttled: s.Throttled, Retries: s.Retries, RetryAfterSeconds: s.RetryAfterSeconds}
	if s.Limit > 0 && s.Remaining >= 0 {
		ri.Limit, ri.Remaining = s.Limit, s.Remaining
	}
	return ri, nil
}

// errStop ends a sample walk early.
var errStop = errors.New("stop")

// Sample reads up to q.Limit users (at most connectors.MaxSample) and applies
// the mapping. Objects is how many mapped, PerClass counts "user" and
// "skipped" (records without an id or sign-in name), AttrFill counts the
// records that carry each mapped field, and Missing lists the declared fields
// that no record filled. Findings reports a pagination that does not advance
// (a repeated id), which would make a sync loop or truncate.
func (p *Prober) Sample(ctx context.Context, q connectors.SampleQuery) (connectors.SampleStats, error) {
	var st connectors.SampleStats
	r := p.spec.Users
	if r == nil || (q.Op != "" && q.Op != "mapping" && q.Op != "search" && q.Op != "page") {
		return st, connectors.ErrUnsupported
	}
	limit := q.Limit
	if limit <= 0 || limit > connectors.MaxSample {
		limit = connectors.MaxSample
	}
	m, err := newMapper(r)
	if err != nil {
		return st, err
	}
	st.PerClass = map[string]int{}
	st.AttrFill = map[string]int{}
	ids := map[string]bool{}
	dups := 0
	read := 0
	pages, err := p.c.walk(ctx, r.list(), nil, func(rec any) error {
		read++
		u, ok := m.mapUser(rec)
		if !ok {
			st.PerClass["skipped"]++
			return nil
		}
		if ids[u.id] {
			dups++
		}
		ids[u.id] = true
		st.Objects++
		st.PerClass["user"]++
		for field := range m.fields {
			if m.get(field, rec) != "" {
				st.AttrFill[field]++
			}
		}
		if read >= limit {
			return errStop
		}
		return nil
	})
	st.Pages = pages
	switch {
	case errors.Is(err, errStop), errors.Is(err, ErrTruncated):
	case err != nil:
		return st, err
	}
	for field := range m.fields {
		if st.AttrFill[field] == 0 && st.Objects > 0 {
			st.Missing = append(st.Missing, field)
		}
	}
	sort.Strings(st.Missing)
	if dups > 0 {
		st.Findings = append(st.Findings, fmt.Sprintf("duplicate_ids: %d records repeated an id, so pagination may not advance", dups))
	}
	if st.PerClass["skipped"] > 0 {
		st.Findings = append(st.Findings, fmt.Sprintf("unmapped_records: %d of %d records have no id or sign-in name under the mapping", st.PerClass["skipped"], read))
	}
	st.Available = st.Objects > 0
	return st, nil
}
