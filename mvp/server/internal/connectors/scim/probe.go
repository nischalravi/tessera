// Package scim is the read-only live prober for a generic SCIM 2.0 application
// (RFC 7643, 7644; readiness design §3.13, §5.4, DR-18). Tessera acts as a
// SCIM client: it reads discovery, pages through Users and Groups, compares a
// group's members from the list call, the single-resource GET and a reverse
// lookup through each user's groups, and records the rate limits it meets.
//
// Safety properties:
//   - GET only. The one request function builds a GET and nothing else; the
//     connectors.Prober interface has no write method.
//   - Every request goes through an *http.Client built by NewClient from
//     internal/safehttp (https only, addresses checked after DNS, no private
//     targets in prod, bounded redirects, time and size). A caller may not
//     pass any other client in production code.
//   - Bounded: at most MaxPages pages and MaxItems objects per listing,
//     MaxRequests requests per prober, MaxRetries retries per request, and a
//     Retry-After longer than MaxRetryWait is not waited for.
//   - The bearer token is a Secret: it prints as [redacted], is sent only in
//     the Authorization header and never appears in an error or an observed
//     value. Observed data are counts and ids; no attribute value is kept.
package scim

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// Bounds (design §5.2).
const (
	MaxPages     = 10 // pages per listing
	MaxItems     = connectors.MaxSample
	MaxRequests  = 120             // requests per prober (one validation run)
	MaxRetries   = 2               // retries of one request after HTTP 429
	MaxRetryWait = 3 * time.Second // longest Retry-After (or backoff) waited for
	MaxBodyBytes = 1 << 20         // response body limit
	PageSize     = 50              // default page size requested
	MaxGroups    = 5               // groups whose members are compared per run
	baseBackoff  = 250 * time.Millisecond
	mediaType    = "application/scim+json, application/json;q=0.9"
)

// ErrUnsupported is returned for Prober operations SCIM has no equivalent of.
var ErrUnsupported = errors.New("scim: operation not supported")

// Secret is a credential. It never prints.
type Secret string

func (Secret) String() string               { return "[redacted]" }
func (Secret) GoString() string             { return "[redacted]" }
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"[redacted]"`), nil }

// Config configures a Prober.
type Config struct {
	// BaseURL is the SCIM service root, for example https://app.example.com/scim/v2.
	BaseURL string
	// Token is the bearer token (a sealed connection credential, opened by the caller).
	Token Secret
	// Client must come from NewClient (internal/safehttp).
	Client *http.Client
	// Sleep waits between retries; nil uses a context-aware timer. Tests inject one.
	Sleep func(ctx context.Context, d time.Duration) error
}

// ClientOptions configure NewClient.
type ClientOptions struct {
	Env           string // config.Dev or config.Prod
	AllowLoopback bool   // dev only
	RootCAs       *x509.CertPool
	Timeout       time.Duration // per request (default safehttp's 5 s)
}

// NewClient returns the SSRF-guarded client the Prober requires.
func NewClient(o ClientOptions) (*http.Client, error) {
	return safehttp.New(safehttp.Options{Env: o.Env, AllowLoopback: o.AllowLoopback, RootCAs: o.RootCAs,
		Timeout: o.Timeout, MaxBodyBytes: MaxBodyBytes})
}

// Prober implements connectors.Prober for a SCIM 2.0 service.
type Prober struct {
	base  *url.URL
	token Secret
	hc    *http.Client
	sleep func(ctx context.Context, d time.Duration) error

	mu         sync.Mutex
	requests   int
	throttled  int
	retries    int
	retryAfter int // longest Retry-After seen, seconds
	limit      int
	remaining  int
	haveLimit  bool
	maxResults int // filter.maxResults from ServiceProviderConfig, when known
	spcRead    bool
}

var _ connectors.Prober = (*Prober)(nil)

// New validates the configuration and returns a Prober. It makes no request.
func New(c Config) (*Prober, error) {
	if c.Client == nil {
		return nil, errors.New("scim: a safehttp client is required")
	}
	u, err := url.Parse(strings.TrimSpace(c.BaseURL))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("scim: base URL must be an absolute http(s) URL without credentials, query or fragment")
	}
	p := &Prober{base: u, token: c.Token, hc: c.Client, sleep: c.Sleep}
	if p.sleep == nil {
		p.sleep = sleepCtx
	}
	return p, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// ---------------------------------------------------------------- transport

type reply struct {
	status int
	header http.Header
	body   []byte
	tls    *tls.ConnectionState
}

var errBudget = errors.New("scim: request budget for this run exhausted")

// get is the only function that sends a request, and it sends GET. A 429 is
// retried at most MaxRetries times, waiting the server's Retry-After (or a
// doubling backoff), never longer than MaxRetryWait; beyond that it returns
// connectors.ErrRateLimited so the run aborts.
func (p *Prober) get(ctx context.Context, path string, q url.Values) (*reply, error) {
	u := p.base.JoinPath(path)
	u.RawQuery = q.Encode()
	for attempt := 0; ; attempt++ {
		p.mu.Lock()
		if p.requests >= MaxRequests {
			p.mu.Unlock()
			return nil, errBudget
		}
		p.requests++
		p.mu.Unlock()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", mediaType)
		if p.token != "" {
			req.Header.Set("Authorization", "Bearer "+string(p.token))
		}
		resp, err := p.hc.Do(req)
		if err != nil {
			return nil, normalise(ctx, err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes+1))
		_ = resp.Body.Close()
		if err != nil {
			return nil, normalise(ctx, err)
		}
		if len(body) > MaxBodyBytes {
			return nil, safehttp.ErrTooLarge
		}
		r := &reply{status: resp.StatusCode, header: resp.Header, body: body, tls: resp.TLS}
		p.noteHeaders(r.header)
		if r.status != http.StatusTooManyRequests {
			return r, nil
		}
		wait, ok := retryDelay(r.header.Get("Retry-After"), attempt)
		p.mu.Lock()
		p.throttled++
		if s := retryAfterSeconds(r.header.Get("Retry-After")); s > p.retryAfter {
			p.retryAfter = s
		}
		giveUp := !ok || attempt >= MaxRetries
		if !giveUp {
			p.retries++
		}
		p.mu.Unlock()
		if giveUp {
			return nil, connectors.ErrRateLimited
		}
		if err := p.sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
}

// normalise maps a client timeout to context.DeadlineExceeded.
func normalise(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return fmt.Errorf("scim: %w", context.DeadlineExceeded)
	}
	return err
}

func retryAfterSeconds(h string) int {
	h = strings.TrimSpace(h)
	if n, err := strconv.Atoi(h); err == nil && n >= 0 {
		return n
	}
	if t, err := http.ParseTime(h); err == nil {
		if d := time.Until(t); d > 0 {
			return int(d / time.Second)
		}
	}
	return 0
}

// retryDelay is how long to wait before the next try. ok is false when the
// server asks for longer than MaxRetryWait: the prober then gives up.
func retryDelay(h string, attempt int) (time.Duration, bool) {
	if strings.TrimSpace(h) != "" {
		d := time.Duration(retryAfterSeconds(h)) * time.Second
		return d, d <= MaxRetryWait
	}
	d := baseBackoff << attempt
	return min(d, MaxRetryWait), true
}

// noteHeaders records the rate-limit headers seen (X-RateLimit-* and the
// RateLimit-* of the IETF draft).
func (p *Prober) noteHeaders(h http.Header) {
	num := func(names ...string) (int, bool) {
		for _, n := range names {
			if n, err := strconv.Atoi(strings.TrimSpace(h.Get(n))); err == nil && n >= 0 {
				return n, true
			}
		}
		return 0, false
	}
	l, lok := num("X-RateLimit-Limit", "RateLimit-Limit")
	r, rok := num("X-RateLimit-Remaining", "RateLimit-Remaining")
	if lok && rok {
		p.mu.Lock()
		p.limit, p.remaining, p.haveLimit = l, r, true
		p.mu.Unlock()
	}
}

// ---------------------------------------------------------------- JSON shapes

type listResponse struct {
	TotalResults *int              `json:"totalResults"`
	StartIndex   *int              `json:"startIndex"`
	ItemsPerPage *int              `json:"itemsPerPage"`
	Resources    []json.RawMessage `json:"Resources"`
}

type ref struct {
	Value string `json:"value"`
	Type  string `json:"type"`
}

type resource struct {
	ID      string          `json:"id"`
	Name    string          `json:"name"` // ResourceType name
	Members []ref           `json:"members"`
	Groups  json.RawMessage `json:"groups"`
}

func (r resource) groupIDs() []string {
	var gs []ref
	if json.Unmarshal(r.Groups, &gs) != nil {
		return nil
	}
	out := make([]string, 0, len(gs))
	for _, g := range gs {
		out = append(out, g.Value)
	}
	return out
}

func decodeList(b []byte) (*listResponse, []resource, error) {
	var lr listResponse
	if err := json.Unmarshal(b, &lr); err != nil {
		return nil, nil, err
	}
	rs := make([]resource, 0, len(lr.Resources))
	for _, raw := range lr.Resources {
		var r resource
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, nil, err
		}
		rs = append(rs, r)
	}
	return &lr, rs, nil
}

// ---------------------------------------------------------------- Prober

// Connect implements connectors.Prober. Any HTTP answer from the service
// counts as reachable; the TLS fields describe the verified handshake. A
// target the network policy refuses reports not reachable.
func (p *Prober) Connect(ctx context.Context) (connectors.ConnInfo, error) {
	r, err := p.get(ctx, "ServiceProviderConfig", nil)
	if err != nil {
		var (
			ua x509.UnknownAuthorityError
			ci x509.CertificateInvalidError
			he x509.HostnameError
		)
		switch {
		case errors.As(err, &ua), errors.As(err, &ci), errors.As(err, &he):
			return connectors.ConnInfo{Reachable: true}, nil // answered, but the chain or name is wrong
		case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled), errors.Is(err, connectors.ErrRateLimited):
			return connectors.ConnInfo{}, err
		}
		return connectors.ConnInfo{}, nil // refused by safehttp, DNS failure, connection refused
	}
	ci := connectors.ConnInfo{Reachable: true}
	if r.tls != nil {
		ci.TLSVersion = tlsName(r.tls.Version)
		ci.ChainValid, ci.HostnameMatch = true, true // the safehttp client verifies both
		if len(r.tls.PeerCertificates) > 0 {
			leaf := r.tls.PeerCertificates[0]
			ci.NotAfter, ci.Issuer = leaf.NotAfter, leaf.Issuer.CommonName
		}
	}
	return ci, nil
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

// Authenticate implements connectors.Prober: one read of /Users with the
// bearer token. 401 and 403 mean the token is refused.
func (p *Prober) Authenticate(ctx context.Context) (connectors.AuthInfo, error) {
	if p.token == "" {
		return connectors.AuthInfo{Mode: "none"}, nil
	}
	r, err := p.get(ctx, "Users", url.Values{"startIndex": {"1"}, "count": {"1"}, "attributes": {"id"}})
	if err != nil {
		return connectors.AuthInfo{}, err
	}
	a := connectors.AuthInfo{Mode: "bearer_token"}
	switch {
	case r.status >= 200 && r.status < 300:
		a.OK = true
	case r.status == http.StatusUnauthorized || r.status == http.StatusForbidden || r.status == http.StatusNotFound:
	default:
		return a, fmt.Errorf("scim: unexpected status %d", r.status)
	}
	return a, nil
}

// RootInfo implements connectors.Prober: ServiceProviderConfig, ResourceTypes
// and Schemas. Capabilities lists what the service declares; Missing lists
// the discovery documents that could not be read.
func (p *Prober) RootInfo(ctx context.Context) (connectors.RootInfo, error) {
	var ri connectors.RootInfo
	spc, err := p.serviceProviderConfig(ctx)
	if err != nil {
		return ri, err
	}
	if spc == nil {
		ri.Missing = append(ri.Missing, "ServiceProviderConfig")
	} else {
		ri.Capabilities = spc.capabilities()
	}
	types, ok, err := p.discoveryList(ctx, "ResourceTypes")
	if err != nil {
		return ri, err
	}
	if !ok {
		ri.Missing = append(ri.Missing, "ResourceTypes")
	} else {
		have := map[string]bool{}
		for _, t := range types {
			have[t.Name] = true
			ri.Capabilities = append(ri.Capabilities, "resource:"+t.Name)
		}
		for _, want := range []string{"User", "Group"} {
			if !have[want] {
				ri.Missing = append(ri.Missing, "ResourceType "+want)
			}
		}
	}
	schemas, ok, err := p.discoveryList(ctx, "Schemas")
	if err != nil {
		return ri, err
	}
	if !ok || len(schemas) == 0 {
		ri.Missing = append(ri.Missing, "Schemas")
	}
	sort.Strings(ri.Capabilities)
	return ri, nil
}

type feature struct {
	Supported  bool `json:"supported"`
	MaxResults int  `json:"maxResults"`
}

type spcDoc struct {
	Patch          feature `json:"patch"`
	Bulk           feature `json:"bulk"`
	Filter         feature `json:"filter"`
	ChangePassword feature `json:"changePassword"`
	Sort           feature `json:"sort"`
	ETag           feature `json:"etag"`
}

func (d *spcDoc) capabilities() []string {
	var out []string
	for name, on := range map[string]bool{"patch": d.Patch.Supported, "bulk": d.Bulk.Supported, "filter": d.Filter.Supported,
		"change_password": d.ChangePassword.Supported, "sort": d.Sort.Supported, "etag": d.ETag.Supported} {
		if on {
			out = append(out, name)
		}
	}
	return out
}

// serviceProviderConfig reads and caches the discovery document; nil means it
// is not readable (missing, refused or not JSON).
func (p *Prober) serviceProviderConfig(ctx context.Context) (*spcDoc, error) {
	r, err := p.get(ctx, "ServiceProviderConfig", nil)
	if err != nil {
		return nil, err
	}
	var d spcDoc
	if r.status != http.StatusOK || json.Unmarshal(r.body, &d) != nil {
		return nil, nil
	}
	p.mu.Lock()
	p.maxResults, p.spcRead = d.Filter.MaxResults, true
	p.mu.Unlock()
	return &d, nil
}

// discoveryList reads /ResourceTypes or /Schemas; ok is false when the
// document is not readable or not a list.
func (p *Prober) discoveryList(ctx context.Context, name string) ([]resource, bool, error) {
	r, err := p.get(ctx, name, nil)
	if err != nil {
		return nil, false, err
	}
	if r.status != http.StatusOK {
		return nil, false, nil
	}
	_, rs, err := decodeList(r.body)
	if err != nil {
		return nil, false, nil
	}
	return rs, true, nil
}

// ObjectExists implements connectors.Prober for the fixed SCIM endpoints.
func (p *Prober) ObjectExists(ctx context.Context, ref string) (bool, error) {
	switch ref = strings.Trim(ref, "/"); ref {
	case "ServiceProviderConfig", "ResourceTypes", "Schemas", "Users", "Groups":
	default:
		return false, ErrUnsupported
	}
	r, err := p.get(ctx, ref, url.Values{"count": {"1"}})
	if err != nil {
		return false, err
	}
	return r.status == http.StatusOK, nil
}

// Sample implements connectors.Prober for the "page" and "members" reads.
func (p *Prober) Sample(ctx context.Context, q connectors.SampleQuery) (connectors.SampleStats, error) {
	switch q.Op {
	case "page":
		return p.samplePaging(ctx, q)
	case "members":
		return p.sampleMembers(ctx)
	}
	return connectors.SampleStats{}, ErrUnsupported
}

// EffectiveRights implements connectors.Prober. SCIM has no way to read the
// token's rights, and the prober never tries a write to find out.
func (p *Prober) EffectiveRights(context.Context, string) (connectors.Rights, error) {
	return connectors.Rights{}, ErrUnsupported
}

// ChangeFeed implements connectors.Prober: SCIM 2.0 has no change feed.
func (p *Prober) ChangeFeed(context.Context) (connectors.FeedInfo, error) {
	return connectors.FeedInfo{}, nil
}

// RateLimits implements connectors.Prober: what the run has seen so far. When
// no request was made yet, one read of ServiceProviderConfig gathers headers.
func (p *Prober) RateLimits(ctx context.Context) (connectors.RateInfo, error) {
	p.mu.Lock()
	n := p.requests
	p.mu.Unlock()
	if n == 0 {
		if _, err := p.get(ctx, "ServiceProviderConfig", nil); err != nil && !errors.Is(err, connectors.ErrRateLimited) {
			return connectors.RateInfo{}, err
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	ri := connectors.RateInfo{Throttled: p.throttled, Retries: p.retries, RetryAfterSeconds: p.retryAfter}
	if p.haveLimit {
		ri.Limit, ri.Remaining = p.limit, p.remaining
	}
	return ri, nil
}

// Time implements connectors.Prober from the HTTP Date header.
func (p *Prober) Time(ctx context.Context) (time.Time, error) {
	r, err := p.get(ctx, "ServiceProviderConfig", nil)
	if err != nil {
		return time.Time{}, err
	}
	t, err := http.ParseTime(r.header.Get("Date"))
	if err != nil {
		return time.Time{}, ErrUnsupported
	}
	return t, nil
}

// ---------------------------------------------------------------- paging

// statusError is a non-200 answer to the first page of a listing.
type statusError struct {
	path string
	code int
}

func (e *statusError) Error() string {
	return fmt.Sprintf("scim: GET %s returned status %d", e.path, e.code)
}

type listing struct {
	items    []resource
	pages    int
	total    int
	exhaust  bool // an empty page ended the walk (the whole collection was read)
	findings []string
}

func (p *Prober) pageSize() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.maxResults > 0 && p.maxResults < PageSize {
		return p.maxResults
	}
	return PageSize
}

// list walks a collection with startIndex and count, checking each page
// against RFC 7644 §3.4.2: totalResults present and stable, startIndex
// echoed, no more than count resources, no id twice. It reads until an empty
// page, MaxPages pages or MaxItems objects. A non-200 on the first page is an
// error; later it ends the walk with a finding.
func (p *Prober) list(ctx context.Context, path string, count int, attrs string) (*listing, error) {
	l := &listing{}
	seen := map[string]bool{}
	flag := func(code, detail string) {
		for _, f := range l.findings {
			if strings.HasPrefix(f, code+":") {
				return
			}
		}
		l.findings = append(l.findings, code+": "+detail)
	}
	start := 1
	for l.pages < MaxPages && len(l.items) < MaxItems {
		q := url.Values{"startIndex": {strconv.Itoa(start)}, "count": {strconv.Itoa(count)}}
		if attrs != "" {
			q.Set("attributes", attrs)
		}
		r, err := p.get(ctx, path, q)
		if err != nil {
			return nil, err
		}
		if r.status != http.StatusOK {
			if l.pages == 0 {
				return nil, &statusError{path: path, code: r.status}
			}
			flag("page_failed", fmt.Sprintf("page %d answered status %d", l.pages+1, r.status))
			return l, nil
		}
		lr, rs, err := decodeList(r.body)
		if err != nil {
			flag("malformed_list", fmt.Sprintf("page %d is not a SCIM ListResponse", l.pages+1))
			return l, nil
		}
		l.pages++
		switch {
		case lr.TotalResults == nil:
			flag("total_results_missing", "the list response has no totalResults")
		case l.pages == 1:
			l.total = *lr.TotalResults
		case *lr.TotalResults != l.total:
			flag("total_results_unstable", fmt.Sprintf("totalResults changed from %d to %d between pages", l.total, *lr.TotalResults))
		}
		if lr.StartIndex != nil && *lr.StartIndex != start {
			flag("start_index_not_echoed", fmt.Sprintf("asked for startIndex %d, the server answered %d", start, *lr.StartIndex))
		}
		if len(rs) > count {
			flag("page_size_exceeded", fmt.Sprintf("asked for count %d, the server returned %d", count, len(rs)))
		}
		if len(rs) == 0 {
			l.exhaust = true
			break
		}
		for _, x := range rs {
			if x.ID != "" && seen[x.ID] {
				flag("duplicate_across_pages", "a resource appeared on more than one page (startIndex ignored?)")
			}
			seen[x.ID] = true
		}
		l.items = append(l.items, rs...)
		start += len(rs)
	}
	switch {
	case lenTotalKnown(l) && l.exhaust && len(l.items) != l.total:
		flag("total_results_mismatch", fmt.Sprintf("totalResults is %d but %d resources were returned", l.total, len(l.items)))
	case lenTotalKnown(l) && !l.exhaust && len(l.items) > l.total:
		flag("total_results_below_items", fmt.Sprintf("totalResults is %d but at least %d resources were returned", l.total, len(l.items)))
	}
	return l, nil
}

func lenTotalKnown(l *listing) bool {
	for _, f := range l.findings {
		if strings.HasPrefix(f, "total_results_missing:") || strings.HasPrefix(f, "total_results_unstable:") {
			return false
		}
	}
	return true
}

func (p *Prober) samplePaging(ctx context.Context, _ connectors.SampleQuery) (connectors.SampleStats, error) {
	if _, err := p.serviceProviderConfig(ctx); err != nil { // learns filter.maxResults; a missing document is not an error here
		return connectors.SampleStats{}, err
	}
	count := p.pageSize()
	l, err := p.list(ctx, "Users", count, "id")
	if err != nil {
		return connectors.SampleStats{}, err
	}
	// Index check: a one-resource page at startIndex 2 must be the second resource.
	if len(l.items) >= 2 {
		r, err := p.get(ctx, "Users", url.Values{"startIndex": {"2"}, "count": {"1"}, "attributes": {"id"}})
		if err != nil {
			return connectors.SampleStats{}, err
		}
		if _, rs, derr := decodeList(r.body); r.status != http.StatusOK || derr != nil || len(rs) != 1 || rs[0].ID != l.items[1].ID {
			l.findings = append(l.findings, "start_index_ignored: startIndex=2 count=1 did not return the second resource")
		}
	}
	return connectors.SampleStats{Objects: len(l.items), Pages: l.pages, TotalResults: l.total, Findings: l.findings,
		PagedBeyond: len(l.findings) == 0}, nil
}

// ---------------------------------------------------------------- members

func (p *Prober) sampleMembers(ctx context.Context) (connectors.SampleStats, error) {
	count := p.pageSize()
	gl, err := p.list(ctx, "Groups", count, "")
	if err != nil {
		return connectors.SampleStats{}, err
	}
	s := connectors.SampleStats{Objects: len(gl.items)}
	if len(gl.items) == 0 {
		s.Findings = []string{"no_groups: the application has no group to compare"}
		return s, nil
	}
	// The groups with the most members on the list call first: a cap shows there.
	groups := append([]resource(nil), gl.items...)
	sort.SliceStable(groups, func(i, j int) bool { return len(groups[i].Members) > len(groups[j].Members) })
	if len(groups) > MaxGroups {
		groups = groups[:MaxGroups]
	}
	worst, worstDiff, largest, largestGet, largestUsers := -1, -1, -1, -1, 0
	var gets []int
	for i, g := range groups {
		if g.ID == "" {
			s.Findings = append(s.Findings, "group_without_id: a group has no id")
			gets = append(gets, 0)
			continue
		}
		r, err := p.get(ctx, "Groups/"+url.PathEscape(g.ID), url.Values{"attributes": {"members"}})
		if err != nil {
			return connectors.SampleStats{}, err
		}
		var one resource
		if r.status != http.StatusOK || json.Unmarshal(r.body, &one) != nil {
			s.Findings = append(s.Findings, fmt.Sprintf("group_get_failed: GET of a group answered status %d", r.status))
			gets = append(gets, len(g.Members))
			continue
		}
		gets = append(gets, len(one.Members))
		diff := len(one.Members) - len(g.Members)
		if diff < 0 {
			diff = -diff
		}
		if diff > worstDiff || (diff == worstDiff && len(one.Members) > gets[worst]) {
			worst, worstDiff = i, diff
		}
		if len(one.Members) > largestGet {
			largest, largestGet = i, len(one.Members)
			largestUsers = 0
			for _, m := range one.Members {
				if !strings.EqualFold(m.Type, "Group") { // nested groups are not users
					largestUsers++
				}
			}
		}
		if len(one.Members) != len(g.Members) {
			s.Findings = append(s.Findings, fmt.Sprintf("members_truncated: a group lists %d members on the list call and %d on GET", len(g.Members), len(one.Members)))
		}
	}
	if worst >= 0 {
		s.RangedCount, s.FullCount = len(groups[worst].Members), gets[worst]
	}
	// Reverse lookup for the largest group: which users say they are in it.
	if largest >= 0 && largestUsers > 0 {
		if err := p.reverse(ctx, &s, groups[largest].ID, largestUsers, count); err != nil {
			return connectors.SampleStats{}, err
		}
	}
	return s, nil
}

// reverse counts the users whose own groups attribute names the group and
// compares it with the members the group's GET listed (user members only).
// Equality is judged only when every user was read; a larger reverse count
// proves truncation even on a partial read. A server whose users carry no
// groups attribute gives no evidence, which is not a failure.
func (p *Prober) reverse(ctx context.Context, s *connectors.SampleStats, groupID string, want, count int) error {
	ul, err := p.list(ctx, "Users", count, "id,groups")
	if err != nil {
		var se *statusError
		if errors.As(err, &se) {
			return nil // users not listable: no reverse evidence
		}
		return err
	}
	carries, got := false, 0
	for _, u := range ul.items {
		if len(u.Groups) > 0 {
			carries = true
		}
		if slices.Contains(u.groupIDs(), groupID) {
			got++
		}
	}
	if !carries {
		return nil
	}
	complete := ul.exhaust && len(ul.findings) == 0
	if (complete && got != want) || got > want {
		s.ReverseChecked, s.ReverseCount = true, got
		s.Findings = append(s.Findings, fmt.Sprintf("reverse_lookup_mismatch: the group GET lists %d user members, a reverse lookup through users' groups finds %d", want, got))
		return nil
	}
	if complete {
		s.ReverseChecked, s.ReverseCount = true, got
	}
	return nil
}
