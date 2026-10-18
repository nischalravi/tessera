package containment

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// The provider tests replay recorded provider answers (testdata/<provider>.json)
// from an httptest server through a real internal/safehttp client. A request
// the fixture does not hold fails the test, so the exact calls are pinned.

var t0 = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

type fixtureResp struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    json.RawMessage   `json:"body"`
}

type fixtureRoute struct {
	Method    string        `json:"method"`
	Path      string        `json:"path"`
	Query     string        `json:"query"`
	Responses []fixtureResp `json:"responses"`
}

type replay struct {
	t      *testing.T
	srv    *httptest.Server
	scheme string
	routes []fixtureRoute
	mu     sync.Mutex
	next   map[int]int
	calls  []string
}

func newReplay(t *testing.T, file, scenario, scheme string) *replay {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", file))
	if err != nil {
		t.Fatal(err)
	}
	var all map[string][]fixtureRoute
	if err := json.Unmarshal(raw, &all); err != nil {
		t.Fatal(err)
	}
	routes, ok := all[scenario]
	if !ok {
		t.Fatalf("%s has no scenario %q", file, scenario)
	}
	r := &replay{t: t, scheme: scheme, routes: routes, next: map[int]int{}}
	r.srv = httptest.NewServer(http.HandlerFunc(r.serve))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *replay) serve(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if got := req.Header.Get("Authorization"); !strings.HasPrefix(got, r.scheme+" ") || strings.TrimPrefix(got, r.scheme+" ") != "tok-secret" {
		r.t.Errorf("%s %s: Authorization scheme is wrong", req.Method, req.URL.Path)
	}
	for i, rt := range r.routes {
		if rt.Method != req.Method || rt.Path != req.URL.Path {
			continue
		}
		if rt.Query != "" {
			want, _ := url.ParseQuery(rt.Query)
			if !reflect.DeepEqual(want, req.URL.Query()) {
				continue
			}
		}
		n := r.next[i]
		if n >= len(rt.Responses) {
			n = len(rt.Responses) - 1 // the last answer repeats
		} else {
			r.next[i]++
		}
		r.calls = append(r.calls, req.Method+" "+req.URL.Path)
		resp := rt.Responses[n]
		for k, v := range resp.Headers {
			w.Header().Set(k, v)
		}
		if len(resp.Body) > 0 {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(resp.Status)
		_, _ = w.Write(resp.Body)
		return
	}
	r.t.Errorf("fixture holds no answer for %s %s?%s", req.Method, req.URL.Path, req.URL.RawQuery)
	http.Error(w, "no fixture", 599)
}

func (r *replay) Calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

// advancing is a clock that moves 7ms on every read (timings are non-zero).
func advancing() func() time.Time {
	var mu sync.Mutex
	cur := t0
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		cur = cur.Add(7 * time.Millisecond)
		return cur
	}
}

func testService(t *testing.T) (*Service, *[]time.Duration) {
	t.Helper()
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	var sleeps []time.Duration
	svc := &Service{HTTP: hc, Clock: func() time.Time { return t0 }, Sleep: func(_ context.Context, d time.Duration) error {
		sleeps = append(sleeps, d)
		return nil
	}}
	return svc, &sleeps
}

var targets = map[string]Target{
	Okta:   {System: Okta, UserID: "00u1abcd", Username: "alice@example.com"},
	Entra:  {System: Entra, UserID: "11111111-2222-3333-4444-555555555555", Username: "alice@example.com"},
	Google: {System: Google, UserID: "alice@example.com", Username: "alice@example.com"},
	GitHub: {System: GitHub, UserID: "octocat", Username: "octocat"},
}

var schemes = map[string]string{Okta: "SSWS", Entra: "Bearer", Google: "Bearer", GitHub: "Bearer"}

func runOne(t *testing.T, system, file, scenario, action string) (StepResult, *Report, *replay, []time.Duration) {
	t.Helper()
	svc, sleeps := testService(t)
	rp := newReplay(t, file, scenario, schemes[system])
	it := Item{Action: action, AccountID: 1, Target: targets[system], Connection: "conn-" + system,
		cred: &Credential{BaseURL: rp.srv.URL, Org: "acme", Token: "tok-secret"}}
	rep := svc.Run(context.Background(), &Job{IdentityID: 7, Identity: "Alice", Trigger: "manual", Items: []Item{it}})
	if len(rep.Steps) != 1 {
		t.Fatalf("steps = %d", len(rep.Steps))
	}
	return rep.Steps[0], rep, rp, *sleeps
}

func TestProviders(t *testing.T) {
	S, G := ActionRevokeSessions, ActionRevokeGrants
	cases := []struct {
		name, system, file, scenario, action string
		outcome                              string
		revoked                              int
		detail                               string   // substring of Detail
		calls                                []string // exact provider calls, when pinned
		sleeps                               []time.Duration
		manual                               int
	}{
		{name: "okta sessions", system: Okta, file: "okta.json", scenario: "ok_sessions", action: S, outcome: OutcomeDone, revoked: 1,
			calls: []string{"DELETE /api/v1/users/00u1abcd/sessions", "GET /api/v1/users/00u1abcd/clients",
				"GET /api/v1/users/00u1abcd/clients/0oaCLIENT1/tokens"}},
		{name: "okta grants", system: Okta, file: "okta.json", scenario: "ok_grants", action: G, outcome: OutcomeDone, revoked: 2,
			calls: []string{"GET /api/v1/users/00u1abcd/grants", "DELETE /api/v1/users/00u1abcd/grants", "GET /api/v1/users/00u1abcd/grants"}},
		{name: "okta 404 user", system: Okta, file: "okta.json", scenario: "not_found", action: S, outcome: OutcomeFailed,
			detail: "does not know this user"},
		{name: "okta 429 then ok", system: Okta, file: "okta.json", scenario: "rate_limited", action: S, outcome: OutcomeDone, revoked: 1,
			sleeps: []time.Duration{2 * time.Second}},
		{name: "okta 429 exhausted", system: Okta, file: "okta.json", scenario: "rate_limit_exhausted", action: S, outcome: OutcomeFailed,
			detail: "rate limit", sleeps: []time.Duration{time.Second, time.Second, time.Second}},
		{name: "okta refresh token remains", system: Okta, file: "okta.json", scenario: "still_has_token", action: S, outcome: OutcomeFailed,
			revoked: 1, detail: "still found 1 active session"},
		{name: "okta grant remains", system: Okta, file: "okta.json", scenario: "still_has_grant", action: G, outcome: OutcomeFailed,
			revoked: 1, detail: "still found 1 grant"},
		{name: "okta refused", system: Okta, file: "okta.json", scenario: "forbidden", action: G, outcome: OutcomeFailed,
			detail: "answered 403 to DELETE /api/v1/users/00u1abcd/grants"},

		{name: "entra sessions", system: Entra, file: "entra.json", scenario: "ok_sessions", action: S, outcome: OutcomeDone, revoked: 1,
			calls: []string{"POST /v1.0/users/11111111-2222-3333-4444-555555555555/revokeSignInSessions",
				"GET /v1.0/users/11111111-2222-3333-4444-555555555555"}},
		{name: "entra grants", system: Entra, file: "entra.json", scenario: "ok_grants", action: G, outcome: OutcomeDone, revoked: 2},
		{name: "entra 404 user", system: Entra, file: "entra.json", scenario: "not_found", action: S, outcome: OutcomeFailed,
			detail: "does not know this user"},
		{name: "entra 429 twice then ok", system: Entra, file: "entra.json", scenario: "rate_limited", action: S, outcome: OutcomeDone,
			revoked: 1, sleeps: []time.Duration{time.Second, time.Second}},
		{name: "entra stale sessions", system: Entra, file: "entra.json", scenario: "stale_session", action: S, outcome: OutcomeFailed,
			revoked: 1, detail: "still found 1 active session"},
		{name: "entra not confirmed", system: Entra, file: "entra.json", scenario: "not_confirmed", action: S, outcome: OutcomeFailed,
			detail: "did not confirm"},
		{name: "entra partial grants", system: Entra, file: "entra.json", scenario: "partial", action: G, outcome: OutcomeFailed,
			revoked: 1, detail: "answered 403 to DELETE /v1.0/oauth2PermissionGrants/g-2"},

		{name: "google sessions", system: Google, file: "google.json", scenario: "ok_sessions", action: S, outcome: OutcomeDone, revoked: 3,
			calls: []string{"POST /admin/directory/v1/users/alice@example.com/signOut", "GET /admin/directory/v1/users/alice@example.com/tokens",
				"DELETE /admin/directory/v1/users/alice@example.com/tokens/1234.apps.googleusercontent.com",
				"DELETE /admin/directory/v1/users/alice@example.com/tokens/5678.apps.googleusercontent.com",
				"GET /admin/directory/v1/users/alice@example.com/tokens"}},
		{name: "google grants", system: Google, file: "google.json", scenario: "ok_grants", action: G, outcome: OutcomeDone, revoked: 1},
		{name: "google 404 user", system: Google, file: "google.json", scenario: "not_found", action: S, outcome: OutcomeFailed,
			detail: "does not know this user"},
		{name: "google 429 then ok", system: Google, file: "google.json", scenario: "rate_limited", action: S, outcome: OutcomeDone,
			revoked: 1, sleeps: []time.Duration{250 * time.Millisecond}},
		{name: "google token remains", system: Google, file: "google.json", scenario: "token_remains", action: S, outcome: OutcomeFailed,
			revoked: 2, detail: "still found 1 active session"},
		{name: "google partial tokens", system: Google, file: "google.json", scenario: "partial", action: G, outcome: OutcomeFailed,
			revoked: 1, detail: "answered 500 to DELETE"},

		{name: "github credentials", system: GitHub, file: "github.json", scenario: "ok_grants", action: G, outcome: OutcomeDone, revoked: 2,
			manual: 1, calls: []string{"GET /orgs/acme/credential-authorizations", "DELETE /orgs/acme/credential-authorizations/1001",
				"DELETE /orgs/acme/credential-authorizations/1002", "GET /orgs/acme/credential-authorizations"}},
		{name: "github 404", system: GitHub, file: "github.json", scenario: "not_found", action: G, outcome: OutcomeFailed,
			detail: "does not know this user"},
		{name: "github authorization remains", system: GitHub, file: "github.json", scenario: "remains", action: G, outcome: OutcomeFailed,
			revoked: 1, detail: "still found 1 grant"},
		{name: "github partial", system: GitHub, file: "github.json", scenario: "partial", action: G, outcome: OutcomeFailed,
			revoked: 1, detail: "answered 403"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, rep, rp, sleeps := runOne(t, tc.system, tc.file, tc.scenario, tc.action)
			if st.Outcome != tc.outcome || st.Revoked != tc.revoked {
				t.Errorf("outcome %s revoked %d (%s), want %s revoked %d", st.Outcome, st.Revoked, st.Detail, tc.outcome, tc.revoked)
			}
			if !strings.Contains(st.Detail, tc.detail) {
				t.Errorf("detail %q lacks %q", st.Detail, tc.detail)
			}
			if st.Verified != (tc.outcome == OutcomeDone) {
				t.Errorf("verified = %v for outcome %s", st.Verified, st.Outcome)
			}
			if rep.OK != (tc.outcome == OutcomeDone) {
				t.Errorf("report ok = %v for a %s step", rep.OK, tc.outcome)
			}
			if tc.calls != nil && !reflect.DeepEqual(rp.Calls(), tc.calls) {
				t.Errorf("calls\n got %v\nwant %v", rp.Calls(), tc.calls)
			}
			if len(sleeps) != len(tc.sleeps) || (len(sleeps) > 0 && !reflect.DeepEqual(sleeps, tc.sleeps)) {
				t.Errorf("retry waits = %v, want %v", sleeps, tc.sleeps)
			}
			if len(rep.Manual) != tc.manual {
				t.Errorf("manual tasks = %v, want %d", rep.Manual, tc.manual)
			}
			if strings.Contains(st.Detail, "tok-secret") {
				t.Error("the token is in the report")
			}
		})
	}
}

// A verification that still finds something fails the step and the run, and
// never reads as done, whichever provider it is.
func TestVerificationFailureFailsReport(t *testing.T) {
	_, rep, _, _ := runOne(t, Okta, "okta.json", "still_has_token", ActionRevokeSessions)
	if rep.OK || len(rep.Failed()) != 1 || rep.Providers[0].Outcome != OutcomeFailed {
		t.Errorf("report = %+v", rep)
	}
}

// A partial failure: the other steps still run and report, the run fails.
func TestPartialFailureAcrossProviders(t *testing.T) {
	svc, _ := testService(t)
	svc.Clock = advancing()
	okta := newReplay(t, "okta.json", "ok_sessions", "SSWS")
	goog := newReplay(t, "google.json", "partial", "Bearer")
	gh := newReplay(t, "github.json", "ok_grants", "Bearer")
	items := []Item{
		{Action: ActionRevokeSessions, AccountID: 1, Target: targets[Okta], Connection: "c1", cred: &Credential{BaseURL: okta.srv.URL, Token: "tok-secret"}},
		{Action: ActionRevokeGrants, AccountID: 2, Target: targets[Google], Connection: "c2", cred: &Credential{BaseURL: goog.srv.URL, Token: "tok-secret"}},
		{Action: ActionRevokeGrants, AccountID: 3, Target: targets[GitHub], Connection: "c3", cred: &Credential{BaseURL: gh.srv.URL, Org: "acme", Token: "tok-secret"}},
	}
	rep := svc.Run(context.Background(), &Job{IdentityID: 7, Identity: "Alice", Trigger: "leaver", Items: items})
	got := []string{rep.Steps[0].Outcome, rep.Steps[1].Outcome, rep.Steps[2].Outcome}
	if !reflect.DeepEqual(got, []string{OutcomeDone, OutcomeFailed, OutcomeDone}) || rep.OK {
		t.Fatalf("outcomes %v ok=%v", got, rep.OK)
	}
	byProv := map[string]ProviderOutcome{}
	for _, p := range rep.Providers {
		byProv[p.System] = p
	}
	if byProv[Okta].Outcome != OutcomeDone || byProv[Google].Outcome != OutcomeFailed || byProv[Google].Failed != 1 {
		t.Errorf("providers %+v", rep.Providers)
	}
	// timings: every step and the run have a start, a finish and a duration
	for _, st := range rep.Steps {
		if st.StartedAt == "" || st.FinishedAt == "" || st.DurationMS <= 0 {
			t.Errorf("step timing %+v", st)
		}
	}
	if rep.StartedAt == "" || rep.DurationMS <= 0 || rep.DurationMS < rep.Steps[0].DurationMS {
		t.Errorf("run timing %s %s %d", rep.StartedAt, rep.FinishedAt, rep.DurationMS)
	}
}

// With no credential nothing is called and the step is a manual task, never done.
func TestNoCredentialIsManualNeverDone(t *testing.T) {
	svc, _ := testService(t)
	items := []Item{
		{Action: ActionRevokeSessions, AccountID: 1, Target: targets[Okta]},                 // no connection
		{Action: ActionRevokeGrants, AccountID: 1, Target: targets[Okta], Connection: "c1"}, // connection, no credential
		{Action: ActionRevokeGrants, AccountID: 1, Target: targets[Entra], Connection: "c2", prepErr: "the stored credential cannot be unsealed"},
	}
	rep := svc.Run(context.Background(), &Job{IdentityID: 7, Identity: "Alice", Trigger: "manual", Items: items})
	if rep.Steps[0].Outcome != OutcomeManual || rep.Steps[1].Outcome != OutcomeManual || rep.Steps[0].Verified {
		t.Errorf("steps %+v", rep.Steps)
	}
	if rep.Steps[2].Outcome != OutcomeFailed {
		t.Errorf("an unusable stored credential must fail, got %+v", rep.Steps[2])
	}
	if len(rep.Manual) != 2 || !strings.Contains(rep.Manual[0].Instructions, "Not done") || rep.OK {
		t.Errorf("manual %+v ok=%v", rep.Manual, rep.OK)
	}
}

// Without an outbound client every step is refused, not skipped.
func TestNoHTTPClientFailsClosed(t *testing.T) {
	svc := &Service{Clock: func() time.Time { return t0 }}
	it := Item{Action: ActionRevokeSessions, AccountID: 1, Target: targets[Okta], Connection: "c", cred: &Credential{BaseURL: "https://x.okta.com", Token: "t"}}
	rep := svc.Run(context.Background(), &Job{Items: []Item{it}})
	if rep.OK || rep.Steps[0].Outcome != OutcomeFailed {
		t.Errorf("%+v", rep.Steps[0])
	}
}

func TestTargetIDsAreValidated(t *testing.T) {
	for _, id := range []string{"", "a/b", "a b", "x'y", "../etc", strings.Repeat("a", 300)} {
		svc, _ := testService(t)
		it := Item{Action: ActionRevokeSessions, AccountID: 1, Target: Target{System: Okta, UserID: id, Username: "u"}, Connection: "c",
			cred: &Credential{BaseURL: "http://127.0.0.1:1", Token: "t"}}
		rep := svc.Run(context.Background(), &Job{Items: []Item{it}})
		if rep.OK || !strings.Contains(rep.Steps[0].Detail, "invalid provider user id") {
			t.Errorf("id %q: %+v", id, rep.Steps[0])
		}
	}
}

// A provider call outside the SSRF guard is refused (private address, no loopback exception).
func TestSafeHTTPGuardApplies(t *testing.T) {
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Prod})
	if err != nil {
		t.Fatal(err)
	}
	svc := &Service{HTTP: hc, Clock: func() time.Time { return t0 }}
	it := Item{Action: ActionRevokeSessions, AccountID: 1, Target: targets[Okta], Connection: "c",
		cred: &Credential{BaseURL: "http://169.254.169.254", Token: "t"}}
	rep := svc.Run(context.Background(), &Job{Items: []Item{it}})
	if rep.OK || rep.Steps[0].Outcome != OutcomeFailed {
		t.Errorf("%+v", rep.Steps[0])
	}
}

type oneHost map[string]netip.Addr

func (h oneHost) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := h[host]; ok {
		return []netip.Addr{a}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// TestConfiguredBaseURLPort (L6): safehttp allows only 443 and 8443, but a
// provider connection whose base_url names another port reaches it: the
// port comes from the connection's configuration, for that host only.
func TestConfiguredBaseURLPort(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Dev, AllowLoopback: true,
		RootCAs:  srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
		Resolver: oneHost{"okta.example.com": netip.MustParseAddr("127.0.0.1")}})
	if err != nil {
		t.Fatal(err)
	}
	// the base client alone refuses the port
	if _, err := safehttp.Get(context.Background(), hc, "https://okta.example.com:"+u.Port()+"/"); !errors.Is(err, safehttp.ErrPort) {
		t.Fatalf("base client: %v, want ErrPort", err)
	}
	svc := &Service{HTTP: hc, Clock: func() time.Time { return t0 }}
	it := Item{Action: ActionRevokeSessions, AccountID: 1, Target: targets[Okta], Connection: "c",
		cred: &Credential{BaseURL: "https://okta.example.com:" + u.Port(), Token: "t"}}
	rep := svc.Run(context.Background(), &Job{Items: []Item{it}})
	if hits.Load() == 0 {
		t.Errorf("the configured base_url port was not reached: %+v", rep.Steps)
	}
}

func TestRetryWait(t *testing.T) {
	for _, tc := range []struct {
		h       string
		attempt int
		want    time.Duration
	}{{"2", 1, 2 * time.Second}, {"0", 1, 0}, {"900", 1, 3 * time.Second}, {"", 1, 250 * time.Millisecond},
		{"", 3, time.Second}, {"soon", 2, 500 * time.Millisecond}, {"-4", 1, 250 * time.Millisecond}} {
		if got := retryWait(tc.h, tc.attempt); got != tc.want {
			t.Errorf("retryWait(%q, %d) = %v, want %v", tc.h, tc.attempt, got, tc.want)
		}
	}
}
