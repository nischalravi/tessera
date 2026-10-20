package scim_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/scim"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/checks"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

var t0 = time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)

type rig struct {
	f      *fakeSCIM
	p      *scim.Prober
	sleeps *[]time.Duration
	base   string
}

// newRig starts the fake and a prober against it. The prober's sleeps are
// recorded, not waited.
func newRig(t *testing.T, f *fakeSCIM, mutate ...func(*scim.Config)) *rig {
	t.Helper()
	_, base, pool := serve(t, f)
	var sleeps []time.Duration
	cfg := scim.Config{BaseURL: base, Token: testToken, Client: devClient(t, pool, 2*time.Second),
		Sleep: func(ctx context.Context, d time.Duration) error { sleeps = append(sleeps, d); return ctx.Err() }}
	for _, m := range mutate {
		m(&cfg)
	}
	p, err := scim.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &rig{f: f, p: p, sleeps: &sleeps, base: base}
}

// check runs one registered readiness check against the prober.
func (r *rig) check(t *testing.T, id string) checks.Result {
	t.Helper()
	c, ok := checks.Get(id)
	if !ok {
		t.Fatalf("no check %s", id)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return checks.Run(ctx, c, checks.Env{Probe: r.p, Now: t0, TemplateID: "scim_app"}, nil)
}

func (r *rig) all(t *testing.T) map[string]checks.Result {
	t.Helper()
	out := map[string]checks.Result{}
	for _, id := range liveChecks {
		out[id] = r.check(t, id)
	}
	return out
}

var liveChecks = []string{"endpoint_reachable", "auth_ok", "scim_discovery", "paging", "members_complete", "rate_headroom"}

func TestHealthy_AllChecksPass(t *testing.T) {
	r := newRig(t, &fakeSCIM{RateLimit: 100, RateRemain: 90})
	for id, res := range r.all(t) {
		if res.Status != checks.Pass {
			t.Errorf("%s: %s %q %v", id, res.Status, res.Message, res.Observed)
		}
	}
	res := r.check(t, "scim_discovery")
	caps, _ := res.Observed["capabilities"].([]string)
	for _, want := range []string{"patch", "filter", "etag", "resource:User", "resource:Group"} {
		if !slices.Contains(caps, want) {
			t.Errorf("capabilities %v lack %s", caps, want)
		}
	}
	if res := r.check(t, "paging"); res.Observed["total_results"] != 120 || res.Observed["read"] != 120 {
		t.Errorf("paging evidence %v", res.Observed)
	}
	if res := r.check(t, "members_complete"); res.Observed["list_count"] != 30 || res.Observed["get_count"] != 30 || res.Observed["reverse_count"] != 30 {
		t.Errorf("members evidence %v", res.Observed)
	}
	if res := r.check(t, "rate_headroom"); res.Observed["limit"] != 100 || res.Observed["remaining"] != 90 {
		t.Errorf("rate evidence %v", res.Observed)
	}
}

// Every misbehaviour makes exactly the check that owns it fail, with the
// right finding, and leaves unrelated checks alone.
func TestMisbehaviour_FailsTheRightCheck(t *testing.T) {
	cases := []struct {
		name   string
		f      *fakeSCIM
		check  string
		status string
		want   string // substring of the message
	}{
		{"schemas missing", &fakeSCIM{Missing: map[string]bool{"Schemas": true}}, "scim_discovery", checks.Fail, "Schemas"},
		{"resource types missing", &fakeSCIM{Missing: map[string]bool{"ResourceTypes": true}}, "scim_discovery", checks.Fail, "ResourceTypes"},
		{"service provider config missing", &fakeSCIM{Missing: map[string]bool{"ServiceProviderConfig": true}}, "scim_discovery", checks.Fail, "ServiceProviderConfig"},
		{"no group resource type", &fakeSCIM{NoGroupResourceType: true}, "scim_discovery", checks.Fail, "ResourceType Group"},
		{"totalResults too high", &fakeSCIM{TotalDelta: 7}, "paging", checks.Fail, "total_results_mismatch"},
		{"totalResults too low", &fakeSCIM{TotalDelta: -7}, "paging", checks.Fail, "total_results_mismatch"},
		{"startIndex ignored", &fakeSCIM{IgnoreStartIndex: true}, "paging", checks.Fail, "start_index_ignored"},
		{"startIndex ignored, duplicates", &fakeSCIM{IgnoreStartIndex: true}, "paging", checks.Fail, "duplicate_across_pages"},
		{"count ignored", &fakeSCIM{IgnoreCount: true}, "paging", checks.Fail, "page_size_exceeded"},
		{"startIndex not echoed", &fakeSCIM{NoStartIndexEcho: true}, "paging", checks.Fail, "start_index_not_echoed"},
		{"members capped on list", &fakeSCIM{TruncateListMembers: 10}, "members_complete", checks.Fail, "members_truncated"},
		{"members omitted on list", &fakeSCIM{OmitListMembers: true}, "members_complete", checks.Fail, "members_truncated"},
		{"members capped everywhere", &fakeSCIM{TruncateListMembers: 10, TruncateGetMembers: 10}, "members_complete", checks.Fail, "reverse_lookup_mismatch"},
		{"no groups", &fakeSCIM{NoGroups: true}, "members_complete", checks.Fail, "no_groups"},
		{"429 then ok", &fakeSCIM{Throttle: 1, RetryAfter: "1"}, "rate_headroom", checks.Fail, "1 throttled"},
		{"token refused", &fakeSCIM{Token: "another-token"}, "auth_ok", checks.Fail, "Authentication failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, tc.f)
			res := r.check(t, tc.check)
			if res.Status != tc.status || !strings.Contains(res.Message, tc.want) {
				t.Fatalf("%s: got %s %q, want %s containing %q", tc.check, res.Status, res.Message, tc.status, tc.want)
			}
		})
	}
}

// A capped member list is not reported by checks that do not own it, and a
// healthy paging read still passes while one request was throttled.
func TestMisbehaviour_OtherChecksUnaffected(t *testing.T) {
	r := newRig(t, &fakeSCIM{TruncateListMembers: 10})
	if res := r.check(t, "paging"); res.Status != checks.Pass {
		t.Errorf("paging: %s %q", res.Status, res.Message)
	}
	r = newRig(t, &fakeSCIM{Throttle: 1, RetryAfter: "1"})
	if res := r.check(t, "paging"); res.Status != checks.Pass {
		t.Errorf("paging with one throttled request: %s %q", res.Status, res.Message)
	}
	r = newRig(t, &fakeSCIM{UsersWithoutGroups: true})
	res := r.check(t, "members_complete")
	if res.Status != checks.Pass {
		t.Errorf("users without a groups attribute: %s %q", res.Status, res.Message)
	}
	if _, has := res.Observed["reverse_count"]; has {
		t.Errorf("no reverse evidence expected: %v", res.Observed)
	}
}

func TestRateLimit_RetryAfterHonouredAndReported(t *testing.T) {
	r := newRig(t, &fakeSCIM{Throttle: 2, RetryAfter: "2", RateLimit: 100, RateRemain: 90})
	res := r.check(t, "rate_headroom")
	if res.Status != checks.Fail {
		t.Fatalf("got %s %q", res.Status, res.Message)
	}
	if res.Observed["throttled"] != 2 || res.Observed["retries"] != 2 || res.Observed["retry_after_seconds"] != 2 {
		t.Errorf("evidence %v", res.Observed)
	}
	if want := []time.Duration{2 * time.Second, 2 * time.Second}; !slices.Equal(*r.sleeps, want) {
		t.Errorf("slept %v, want %v", *r.sleeps, want)
	}
}

func TestRateLimit_BackoffIsBoundedAndDoubles(t *testing.T) {
	r := newRig(t, &fakeSCIM{AlwaysThrottle: true}) // no Retry-After
	res := r.check(t, "auth_ok")
	if res.Status != checks.Error || res.Observed["rate_limited"] != true {
		t.Fatalf("got %s %q %v", res.Status, res.Message, res.Observed)
	}
	if want := []time.Duration{250 * time.Millisecond, 500 * time.Millisecond}; !slices.Equal(*r.sleeps, want) {
		t.Errorf("backoff %v, want %v", *r.sleeps, want)
	}
	if n, _, _, _ := r.f.seen(); n != scim.MaxRetries+1 {
		t.Errorf("server saw %d requests, want %d", n, scim.MaxRetries+1)
	}
}

func TestRateLimit_LongRetryAfterIsNotWaitedFor(t *testing.T) {
	r := newRig(t, &fakeSCIM{AlwaysThrottle: true, RetryAfter: "3600"})
	res := r.check(t, "paging")
	if res.Status != checks.Error || res.Observed["rate_limited"] != true {
		t.Fatalf("got %s %q", res.Status, res.Message)
	}
	if len(*r.sleeps) != 0 {
		t.Errorf("slept %v for a one hour Retry-After", *r.sleeps)
	}
	if n, _, _, _ := r.f.seen(); n != 1 { // nothing is sent after the first 429
		t.Errorf("server saw %d requests, want 1", n)
	}
	ri, _ := r.p.RateLimits(context.Background())
	if ri.Throttled != 1 || ri.RetryAfterSeconds != 3600 || ri.Retries != 0 {
		t.Errorf("rate info %+v", ri)
	}
}

func TestSlowServer_TimesOut(t *testing.T) {
	f := &fakeSCIM{Delay: 400 * time.Millisecond}
	_, base, pool := serve(t, f)
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Dev, AllowLoopback: true, RootCAs: pool, Timeout: 50 * time.Millisecond, MaxBodyBytes: scim.MaxBodyBytes})
	if err != nil {
		t.Fatal(err)
	}
	p, _ := scim.New(scim.Config{BaseURL: base, Token: testToken, Client: hc})
	r := &rig{f: f, p: p}
	for _, id := range []string{"scim_discovery", "paging", "auth_ok", "endpoint_reachable"} {
		if res := r.check(t, id); res.Status != checks.Error || !strings.Contains(res.Message, "timed out") {
			t.Errorf("%s: %s %q", id, res.Status, res.Message)
		}
	}
}

func TestTransport_Evidence(t *testing.T) {
	// Plain http (dev loopback exception): reachable, but no TLS.
	f := &fakeSCIM{}
	plain := httptest.NewServer(f)
	defer plain.Close()
	hc := devClient(t, nil, time.Second)
	p, _ := scim.New(scim.Config{BaseURL: plain.URL + basePath, Token: testToken, Client: hc})
	ci, err := p.Connect(context.Background())
	if err != nil || !ci.Reachable || ci.TLSVersion != "" || ci.ChainValid {
		t.Errorf("plain http: %+v %v", ci, err)
	}
	r := &rig{p: p}
	if res := r.check(t, "endpoint_reachable"); res.Status != checks.Fail {
		t.Errorf("plain http endpoint: %s", res.Status)
	}

	// TLS the client does not trust: reachable, chain invalid.
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	p, _ = scim.New(scim.Config{BaseURL: srv.URL + basePath, Token: testToken, Client: devClient(t, nil, time.Second)})
	if ci, err = p.Connect(context.Background()); err != nil || !ci.Reachable || ci.ChainValid {
		t.Errorf("untrusted certificate: %+v %v", ci, err)
	}
	r = &rig{p: p}
	if res := r.check(t, "endpoint_reachable"); res.Status != checks.Fail {
		t.Errorf("untrusted certificate endpoint: %s", res.Status)
	}

	// TLS with a trusted chain.
	rr := newRig(t, &fakeSCIM{})
	if ci, err = rr.p.Connect(context.Background()); err != nil || !ci.Reachable || !ci.ChainValid || ci.TLSVersion == "" || ci.NotAfter.IsZero() {
		t.Errorf("trusted TLS: %+v %v", ci, err)
	}
}

// safehttp refuses a loopback target in production mode: nothing reaches the
// server, the endpoint check fails and other reads return the guard's error.
func TestProd_LoopbackBlocked(t *testing.T) {
	f := &fakeSCIM{}
	_, base, pool := serve(t, f)
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Prod, RootCAs: pool, Timeout: time.Second, MaxBodyBytes: scim.MaxBodyBytes})
	if err != nil {
		t.Fatal(err)
	}
	p, _ := scim.New(scim.Config{BaseURL: base, Token: testToken, Client: hc})
	ci, err := p.Connect(context.Background())
	if err != nil || ci.Reachable {
		t.Errorf("connect: %+v %v", ci, err)
	}
	if _, err := p.Authenticate(context.Background()); !isGuardRefusal(err) {
		t.Errorf("authenticate: %v", err)
	}
	if _, err := p.RootInfo(context.Background()); !isGuardRefusal(err) {
		t.Errorf("root info: %v", err)
	}
	if n, _, _, _ := f.seen(); n != 0 {
		t.Errorf("%d requests reached a loopback server in prod mode", n)
	}
	if _, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Prod, AllowLoopback: true, MaxBodyBytes: scim.MaxBodyBytes}); err == nil {
		t.Error("prod client with the loopback exception was allowed")
	}
}

// The prober never sends anything but GET, always with the bearer token, and
// every request goes to the configured SCIM base path.
func TestReadOnly_GetOnly(t *testing.T) {
	r := newRig(t, &fakeSCIM{})
	r.all(t)
	_, _ = r.p.ObjectExists(context.Background(), "Users")
	_, _ = r.p.Time(context.Background())
	n, methods, auth, paths := r.f.seen()
	if n < 15 {
		t.Fatalf("only %d requests", n)
	}
	for i := range methods {
		if methods[i] != http.MethodGet {
			t.Errorf("request %d was %s", i, methods[i])
		}
		if auth[i] != "Bearer "+testToken {
			t.Errorf("request %d carried the wrong credential", i)
		}
		if !strings.HasPrefix(paths[i], basePath+"/") {
			t.Errorf("request %d went to %s", i, paths[i])
		}
	}
	// What SCIM cannot answer is refused, never tried with a write.
	if _, err := r.p.EffectiveRights(context.Background(), "x"); !errors.Is(err, scim.ErrUnsupported) {
		t.Errorf("effective rights: %v", err)
	}
	if _, err := r.p.ObjectExists(context.Background(), "Users/../../admin"); !errors.Is(err, scim.ErrUnsupported) {
		t.Errorf("an arbitrary path was fetched: %v", err)
	}
	if _, err := r.p.Sample(context.Background(), connectors.SampleQuery{Op: "search"}); !errors.Is(err, scim.ErrUnsupported) {
		t.Errorf("sample op: %v", err)
	}
}

func TestBounds_EndlessCollection(t *testing.T) {
	r := newRig(t, &fakeSCIM{Endless: true})
	res := r.check(t, "paging")
	// totalResults is a million; the walk stops at the page bound and judges nothing it did not read.
	if res.Status != checks.Pass {
		t.Fatalf("got %s %q", res.Status, res.Message)
	}
	pages, _ := res.Observed["pages"].(int)
	if pages != scim.MaxPages {
		t.Errorf("read %d pages, want the bound %d", pages, scim.MaxPages)
	}
	if read, _ := res.Observed["read"].(int); read > scim.MaxItems {
		t.Errorf("read %d objects, bound %d", read, scim.MaxItems)
	}
	if n, _, _, _ := r.f.seen(); n > scim.MaxRequests {
		t.Errorf("%d requests, bound %d", n, scim.MaxRequests)
	}
	// A prober whose budget is spent stops sending.
	for i := 0; i < scim.MaxRequests; i++ {
		_, _ = r.p.ObjectExists(context.Background(), "Users")
	}
	n, _, _, _ := r.f.seen()
	_, _ = r.p.ObjectExists(context.Background(), "Users")
	if n2, _, _, _ := r.f.seen(); n2 != n || n > scim.MaxRequests {
		t.Errorf("requests grew past the budget: %d to %d", n, n2)
	}
}

func TestBounds_OversizedBody(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"x":"` + strings.Repeat("a", 2<<20) + `"}`))
	}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	p, _ := scim.New(scim.Config{BaseURL: srv.URL + basePath, Token: testToken, Client: devClient(t, pool, 2*time.Second)})
	if _, err := p.RootInfo(context.Background()); !errors.Is(err, safehttp.ErrTooLarge) {
		t.Errorf("a 2 MiB body was read: %v", err)
	}
}

// The token never shows in printed config, errors or results.
func TestSecret_NeverPrinted(t *testing.T) {
	cfg := scim.Config{BaseURL: "https://x.example.org/scim", Token: testToken}
	for _, s := range []string{fmt.Sprint(cfg), fmt.Sprintf("%+v", cfg), fmt.Sprintf("%#v", cfg), fmt.Sprint(cfg.Token)} {
		if strings.Contains(s, "SENTINEL") {
			t.Errorf("token printed: %s", s)
		}
	}
	if b, _ := json.Marshal(cfg); strings.Contains(string(b), "SENTINEL") {
		t.Errorf("token marshalled: %s", b)
	}
	r := newRig(t, &fakeSCIM{TruncateListMembers: 10, Throttle: 1, RetryAfter: "1"})
	res := r.all(t)
	b, _ := json.Marshal(res)
	if strings.Contains(string(b), "SENTINEL") {
		t.Errorf("token in results: %s", b)
	}
	r = newRig(t, &fakeSCIM{Token: "other"})
	_, err := r.p.RootInfo(context.Background())
	if err != nil && strings.Contains(err.Error(), "SENTINEL") {
		t.Errorf("token in error: %v", err)
	}
}

func TestNew_Validation(t *testing.T) {
	hc := devClient(t, nil, time.Second)
	for _, base := range []string{"", "ftp://x/scim", "https://", "https://u:p@x/scim", "https://x/scim?a=b", "/scim"} {
		if _, err := scim.New(scim.Config{BaseURL: base, Client: hc}); err == nil {
			t.Errorf("accepted base URL %q", base)
		}
	}
	if _, err := scim.New(scim.Config{BaseURL: "https://x.example.org/scim"}); err == nil {
		t.Error("accepted a prober without a safehttp client")
	}
}

func TestAuth_NoTokenIsNotAuthenticated(t *testing.T) {
	r := newRig(t, &fakeSCIM{}, func(c *scim.Config) { c.Token = "" })
	a, err := r.p.Authenticate(context.Background())
	if err != nil || a.OK || a.Mode != "none" {
		t.Errorf("%+v %v", a, err)
	}
	if n, _, _, _ := r.f.seen(); n != 0 {
		t.Errorf("%d requests without a credential", n)
	}
}

// isGuardRefusal: the SSRF guard refused the destination, by address or (for a
// non-default port) by port, whichever it checks first.
func isGuardRefusal(err error) bool {
	return errors.Is(err, safehttp.ErrBlockedAddress) || errors.Is(err, safehttp.ErrPort)
}
