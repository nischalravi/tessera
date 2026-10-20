package workday

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

var now0 = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)

const (
	tenant      = "fixture_tenant"
	workersPath = "/ccx/api/v1/" + tenant + "/workers"
	eventsPath  = "/ccx/api/v1/" + tenant + "/workerEvents"
	tokenPath   = "/ccx/oauth2/" + tenant + "/token"
	clientID    = "api-client-1"
	clientSec   = "client-secret-xyz"
	refreshTok  = "refresh-token-abc"
)

// fake replays the recorded fixtures as a Workday tenant.
type fake struct {
	t   *testing.T
	srv *connsynctest.Server

	mu              sync.Mutex
	now             time.Time
	changed         bool              // serve the updated fixtures for Updated_From
	refuseWatermark int               // when set, the status answered to any request with Updated_From
	status          map[string]int    // path -> forced status
	statusBody      map[string]string // path -> body for a forced status
	body            map[string]string // path -> override body
	retry429        map[string]int    // path -> number of 429s to answer first
	forms           []url.Values
	basics          []string
	override        http.HandlerFunc
}

func newFake(t *testing.T) *fake {
	f := &fake{t: t, now: now0, status: map[string]int{}, statusBody: map[string]string{}, body: map[string]string{},
		retry429: map[string]int{}}
	f.srv = connsynctest.New(t, http.HandlerFunc(f.serve))
	return f
}

func (f *fake) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.override != nil {
		f.override(w, r)
		return
	}
	if f.refuseWatermark != 0 && r.URL.Query().Has("Updated_From") {
		w.WriteHeader(f.refuseWatermark)
		fmt.Fprint(w, `{"error":"invalid_request","error_description":"leaky-body-should-never-surface"}`)
		return
	}
	if s := f.status[r.URL.Path]; s != 0 {
		w.WriteHeader(s)
		b := f.statusBody[r.URL.Path]
		if b == "" {
			b = `{"error":"forbidden","error_description":"leaky-body-should-never-surface"}`
		}
		fmt.Fprint(w, b)
		return
	}
	if n := f.retry429[r.URL.Path]; n > 0 {
		f.retry429[r.URL.Path] = n - 1
		w.Header().Set("Retry-After", "4")
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	if b, ok := f.body[r.URL.Path]; ok {
		fmt.Fprint(w, b)
		return
	}
	out := func(name string) { _, _ = w.Write(connsynctest.Fixture(f.t, name, f.srv.URL)) }
	empty := func() { fmt.Fprint(w, `{"total":0,"data":[]}`) }
	q := r.URL.Query()
	switch r.URL.Path {
	case tokenPath:
		_ = r.ParseForm()
		f.forms = append(f.forms, r.PostForm)
		f.basics = append(f.basics, r.Header.Get("Authorization"))
		fmt.Fprint(w, `{"token_type":"Bearer","expires_in":3600,"access_token":"wd-token-1"}`)
	case workersPath:
		switch {
		case q.Get("Updated_From") != "":
			if f.changed {
				out("workers_updated.json")
			} else {
				empty()
			}
		case q.Get("offset") == "3":
			out("workers_p2.json")
		default:
			out("workers_p1.json")
		}
	case eventsPath:
		switch {
		case q.Get("Updated_From") != "":
			if f.changed {
				out("events_updated.json")
			} else {
				empty()
			}
		case q.Get("Effective_From") == "":
			f.t.Errorf("events request without a window or watermark: %s", r.URL.RawQuery)
		case q.Get("offset") == "4":
			out("events_p2.json")
		default:
			out("events_p1.json")
		}
	default:
		f.t.Errorf("unexpected request %s %s", r.Method, r.URL.String())
		http.NotFound(w, r)
	}
}

// fullWorkerReads and fullEventReads count the first pages read without a watermark.
func (f *fake) fullWorkerReads() int { return f.reads(workersPath, "Effective_From", false) }
func (f *fake) fullEventReads() int  { return f.reads(eventsPath, "Effective_From", true) }
func (f *fake) reads(path, param string, want bool) int {
	n := 0
	for _, r := range f.srv.Requests() {
		q, _ := url.ParseQuery(r.Query)
		if r.Path != path || q.Get("offset") != "0" {
			continue
		}
		if want && q.Has(param) || !want && !q.Has("Updated_From") {
			n++
		}
	}
	return n
}

func (f *fake) updatedReads(path string) int {
	n := 0
	for _, r := range f.srv.Requests() {
		if q, _ := url.ParseQuery(r.Query); r.Path == path && q.Has("Updated_From") {
			n++
		}
	}
	return n
}

func baseCfg() Config {
	return Config{Tenant: tenant, ClientID: clientID, ClientSecret: connsync.NewSecret(clientSec), EmitIdentities: true}
}

func (f *fake) connector(cfg Config) *Connector {
	f.t.Helper()
	cfg.BaseURL = f.srv.URL
	c, err := New(cfg, connsynctest.Runtime, testClient(f.t, f.srv, 0), func() time.Time { return f.now })
	if err != nil {
		f.t.Fatal(err)
	}
	c.api.Backoff = connsync.Backoff{Base: time.Millisecond, Max: 10 * time.Second, Sleep: (&connsynctest.NoSleep{}).Sleep}
	return c
}

func acctMap(res *connectors.DiscoveryResult) map[string]connectors.AccountRecord {
	m := map[string]connectors.AccountRecord{}
	for _, a := range res.Accounts {
		m[a.ExternalID] = a
	}
	return m
}

func identMap(res *connectors.DiscoveryResult) map[string]connectors.IdentityRecord {
	m := map[string]connectors.IdentityRecord{}
	for _, i := range res.Identities {
		m[i.ExternalID] = i
	}
	return m
}

func collect(t *testing.T, c *Connector, ctx context.Context, since *time.Time) []*connectors.HrisEventRecord {
	t.Helper()
	var out []*connectors.HrisEventRecord
	err := c.StreamEvents(ctx, since, func(e connectors.Event) error {
		h, ok := e.(*connectors.HrisEventRecord)
		if !ok {
			t.Fatalf("event is %T, want an HRIS event", e)
		}
		out = append(out, h)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func byID(evs []*connectors.HrisEventRecord) map[string]*connectors.HrisEventRecord {
	m := map[string]*connectors.HrisEventRecord{}
	for _, e := range evs {
		m[e.ExternalID] = e
	}
	return m
}

func payload(t *testing.T, e *connectors.HrisEventRecord) map[string]any {
	t.Helper()
	m := map[string]any{}
	for _, kv := range e.Payload {
		m[kv.Key] = kv.Value
	}
	return m
}

// ---------------------------------------------------------------- discovery

func TestDiscoverFull(t *testing.T) {
	f := newFake(t)
	res, err := f.connector(baseCfg()).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	accts, idents := acctMap(res), identMap(res)
	// five people: the not-yet-hired worker and the row without an id are not among them
	if len(accts) != 5 || len(idents) != 5 {
		t.Fatalf("accounts = %d, identities = %d: %v", len(accts), len(idents), accts)
	}
	a := idents["E1001"]
	if a.Name != "Avery Example" || a.Type != "human" || *a.Email != "Avery.Example@Example.com" || *a.Title != "Platform Engineer" ||
		*a.Department != "Platform Engineering" || a.Status != "active" || a.Manager == nil || a.Manager.ExternalID != "E1000" ||
		a.HiredAt == nil || !a.HiredAt.Equal(time.Date(2021, 4, 12, 0, 0, 0, 0, time.UTC)) || a.TerminatedAt != nil {
		t.Errorf("avery = %+v", a)
	}
	acct := accts["E1001"]
	if acct.Username != "E1001" || acct.Kind != "user" || acct.Status != "active" || acct.Identity.ExternalID != "E1001" ||
		acct.Identity.Email != "Avery.Example@Example.com" || acct.Attributes["workerType"] != "Employee" {
		t.Errorf("avery's account = %+v", acct)
	}
	if r := idents["E1002"]; r.Status != "terminated" || r.TerminatedAt == nil || !r.TerminatedAt.Equal(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)) ||
		r.Manager == nil || r.Manager.ExternalID != "E1000" { // the manager is given by worker id only
		t.Errorf("riley (terminated, manager by id) = %+v", r)
	}
	if accts["E1002"].Status != "disabled" {
		t.Errorf("a terminated worker's account = %+v", accts["E1002"])
	}
	if c := idents["workday:w-1005"]; c.Name != "Taylor Contractor" || accts["workday:w-1005"].Attributes["workerType"] != "Contingent Worker" {
		t.Errorf("worker without an employee id = %+v", c)
	}
	if len(res.Groups) != 2 || res.Groups[0].Kind != "supervisory_org" || res.Groups[0].ExternalID != "org:SUP-100" || res.Groups[0].Privileged {
		t.Errorf("groups = %+v", res.Groups)
	}
	if len(res.Edges) != 4 { // the terminated worker is in no organization
		t.Errorf("edges = %+v", res.Edges)
	}
}

func TestEmitIdentitiesOff(t *testing.T) {
	f := newFake(t)
	cfg := baseCfg()
	cfg.EmitIdentities = false
	res, err := f.connector(cfg).Discover(context.Background())
	if err != nil || len(res.Identities) != 0 || len(res.Accounts) != 5 {
		t.Fatalf("Discover = %+v, %v", res, err)
	}
}

// Workday records changes before they take effect. Discover reflects what is
// true on the day it runs, so a future-dated change is not applied early, and
// is applied once its day comes, with no change to the data read.
func TestFutureDatedChangesAreNotAppliedEarly(t *testing.T) {
	f := newFake(t)
	ms := &connsync.MemoryStore{}
	ctx := connsync.WithStore(context.Background(), ms)
	c := f.connector(baseCfg())
	res, err := c.Discover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	accts, idents := acctMap(res), identMap(res)
	if _, ok := accts["E1003"]; ok {
		t.Error("a worker hired on 2026-11-02 is an account on 2026-10-08")
	}
	if _, ok := idents["E1003"]; ok {
		t.Error("a worker hired on 2026-11-02 is an identity on 2026-10-08")
	}
	if i := idents["E1004"]; i.Status != "active" || i.TerminatedAt != nil || accts["E1004"].Status != "active" {
		t.Errorf("a termination dated 2026-12-31 was applied on 2026-10-08: %+v / %+v", i, accts["E1004"])
	}
	if i := idents["E1001"]; *i.Title != "Platform Engineer" || *i.Department != "Platform Engineering" {
		t.Errorf("a job change dated 2026-11-16 was applied on 2026-10-08: %+v", i)
	}

	f.now = time.Date(2026, 11, 3, 6, 0, 0, 0, time.UTC) // the hire date has passed
	res, err = c.Discover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if i, ok := identMap(res)["E1003"]; !ok || i.Status != "active" || *i.Email != "jordan.pending@example.com" {
		t.Errorf("on 2026-11-03 the new hire is missing: %+v", i)
	}
	if i := identMap(res)["E1004"]; i.Status != "active" {
		t.Errorf("E1004 terminated early: %+v", i)
	}
	if f.fullWorkerReads() != 1 {
		t.Errorf("full worker reads = %d: the date, not a re-read, moves the state", f.fullWorkerReads())
	}

	f.now = time.Date(2026, 12, 31, 0, 0, 1, 0, time.UTC) // the termination date has come
	res, err = c.Discover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if i := identMap(res)["E1004"]; i.Status != "terminated" || i.TerminatedAt == nil || !i.TerminatedAt.Equal(time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)) ||
		acctMap(res)["E1004"].Status != "disabled" {
		t.Errorf("on 2026-12-31 the termination was not applied: %+v", i)
	}
}

func TestRequestsAreReadOnlyAuthorizedAndStayOnTheTenant(t *testing.T) {
	f := newFake(t)
	c := f.connector(baseCfg())
	ctx := context.Background()
	if _, err := c.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	collect(t, c, ctx, nil)
	for _, r := range f.srv.Requests() {
		if r.Path == tokenPath {
			continue
		}
		if r.Authorization != "Bearer wd-token-1" {
			t.Errorf("%s: Authorization = %q", r.Path, r.Authorization)
		}
		if r.Path != workersPath && r.Path != eventsPath {
			t.Errorf("request to %s", r.Path)
		}
		q, _ := url.ParseQuery(r.Query)
		if lim, _ := strconv.Atoi(q.Get("limit")); lim != 100 {
			t.Errorf("%s: limit = %q", r.Path, q.Get("limit"))
		}
		if r.Method != http.MethodGet {
			t.Errorf("%s %s", r.Method, r.Path)
		}
	}
	if len(f.forms) != 1 {
		t.Fatalf("token requests = %d, want 1 (cached)", len(f.forms))
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":"+clientSec))
	if f.basics[0] != want || f.forms[0].Get("grant_type") != "client_credentials" || f.forms[0].Has("client_secret") {
		t.Errorf("token request: %q %v", f.basics[0], f.forms[0])
	}
}

func TestRefreshTokenGrant(t *testing.T) {
	f := newFake(t)
	cfg := baseCfg()
	cfg.RefreshToken = connsync.NewSecret(refreshTok)
	if _, err := f.connector(cfg).Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := f.forms[0]; got.Get("grant_type") != "refresh_token" || got.Get("refresh_token") != refreshTok {
		t.Errorf("token form = %v", got)
	}
}

func TestThrottling(t *testing.T) {
	f := newFake(t)
	f.retry429[workersPath] = 2
	c := f.connector(baseCfg())
	ns := &connsynctest.NoSleep{}
	c.api.Backoff = connsync.Backoff{Base: time.Millisecond, Max: 10 * time.Second, Sleep: ns.Sleep}
	res, err := c.Discover(context.Background())
	if err != nil || len(res.Accounts) != 5 {
		t.Fatalf("Discover = %v, %v", res, err)
	}
	if len(ns.Waits) != 2 || ns.Waits[0] != 4*time.Second || ns.Waits[1] != 4*time.Second {
		t.Fatalf("waits = %v, want two of the Retry-After 4s", ns.Waits)
	}
	f2 := newFake(t)
	f2.status[workersPath] = 429
	f2.statusBody[workersPath] = `{"error":"slow_down","error_description":"leaky-body"}`
	_, err = f2.connector(baseCfg()).Discover(context.Background())
	if !errors.Is(err, connsync.ErrRateLimited) || strings.Contains(err.Error(), "leaky-body") {
		t.Errorf("err = %v", err)
	}
	f3 := newFake(t)
	f3.retry429[eventsPath] = 1
	if _, err := f3.connector(baseCfg()).Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	collect(t, f3.connector(baseCfg()), context.Background(), nil)
}

func TestMalformedAndOversizedPages(t *testing.T) {
	for name, body := range map[string]string{
		"array instead of object": `[]`,
		"truncated":               `{"total":1,"data":[{"id":`,
		"data of the wrong type":  `{"total":1,"data":"nope"}`,
		"total of the wrong type": `{"total":"many","data":[]}`,
		"trailing garbage":        `{"total":0,"data":[]} {}`,
		"empty":                   ``,
		"implausible total":       `{"total":99999999999,"data":[{"id":"w-1"}]}`,
		"negative total":          `{"total":-5,"data":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			f.body[workersPath] = body
			if _, err := f.connector(baseCfg()).Discover(context.Background()); !errors.Is(err, connsync.ErrMalformed) {
				t.Errorf("err = %v, want ErrMalformed", err)
			}
		})
	}
	t.Run("malformed events page", func(t *testing.T) {
		f := newFake(t)
		f.body[eventsPath] = `{"total":1,"data":[{"id":5}]}`
		c := f.connector(baseCfg())
		ctx := context.Background()
		if _, err := c.Discover(ctx); err != nil {
			t.Fatal(err)
		}
		if err := c.StreamEvents(ctx, nil, func(connectors.Event) error { return nil }); !errors.Is(err, connsync.ErrMalformed) {
			t.Errorf("err = %v, want ErrMalformed", err)
		}
	})
	t.Run("oversized", func(t *testing.T) {
		f := newFake(t)
		f.body[workersPath] = `{"total":1,"data":[{"id":"w-1","descriptor":"` + strings.Repeat("x", 8192) + `"}]}`
		cfg := baseCfg()
		cfg.BaseURL = f.srv.URL
		c, err := New(cfg, connsynctest.Runtime, testClient(t, f.srv, 2048), func() time.Time { return now0 })
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Discover(context.Background()); !errors.Is(err, safehttp.ErrTooLarge) {
			t.Errorf("err = %v, want ErrTooLarge", err)
		}
	})
	t.Run("a page that never advances ends at the total", func(t *testing.T) {
		f := newFake(t)
		f.body[workersPath] = `{"total":3,"data":[{"id":"w-1","employeeId":"E1","hireDate":"2020-01-01"}]}`
		res, err := f.connector(baseCfg()).Discover(context.Background())
		if err != nil || len(res.Accounts) != 1 {
			t.Errorf("Discover = %v, %v", res, err)
		}
		if n := f.srv.Count(workersPath); n != 3 {
			t.Errorf("requests = %d, want 3 (offsets 0, 1, 2)", n)
		}
	})
	t.Run("long strings are cut", func(t *testing.T) {
		f := newFake(t)
		f.body[workersPath] = `{"total":1,"data":[{"id":"w-1","employeeId":"E1","descriptor":"` + strings.Repeat("n", 5000) + `"}]}`
		res, err := f.connector(baseCfg()).Discover(context.Background())
		if err != nil || len(res.Identities[0].Name) != maxField {
			t.Errorf("name length = %d, %v", len(res.Identities[0].Name), err)
		}
	})
}

// Workday answers with data only; a link a response carries is never followed.
func TestLinksInResponsesAreNotFollowed(t *testing.T) {
	f := newFake(t)
	f.body[workersPath] = `{"total":1,"next":"https://evil.example.net/ccx/api/workers?offset=1","data":[{"id":"w-1","employeeId":"E1","hireDate":"2020-01-01"}],"href":"https://evil.example.net/x"}`
	if _, err := f.connector(baseCfg()).Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, r := range f.srv.Requests() {
		if r.Path != workersPath && r.Path != tokenPath {
			t.Errorf("request to %s", r.Path)
		}
	}
}

// ---------------------------------------------------------------- incremental

func TestIncrementalSync(t *testing.T) {
	f := newFake(t)
	ms := &connsync.MemoryStore{}
	ctx := connsync.WithStore(context.Background(), ms)
	c := f.connector(baseCfg())
	if _, err := c.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	cp, _ := ms.Load(ctx, System, checkpointName)
	if cp == nil || cp.FullSyncAt == nil || len(cp.State) == 0 || cp.Cursor != now0.Add(-watermarkOverlap).Format(time.RFC3339) {
		t.Fatalf("checkpoint = %+v", cp)
	}
	f.now = now0.Add(time.Hour)
	f.changed = true
	res, err := c.Discover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if f.fullWorkerReads() != 1 || f.updatedReads(workersPath) != 1 {
		t.Errorf("full reads = %d, watermark reads = %d, want 1 and 1", f.fullWorkerReads(), f.updatedReads(workersPath))
	}
	var wm string
	for _, r := range f.srv.Requests() {
		if q, _ := url.ParseQuery(r.Query); q.Has("Updated_From") {
			wm = q.Get("Updated_From")
		}
	}
	if wm != now0.Add(-watermarkOverlap).Format(time.RFC3339) {
		t.Errorf("Updated_From = %q", wm)
	}
	idents := identMap(res)
	if len(idents) != 6 || *idents["E1001"].Title != "Senior Platform Engineer" || idents["E1006"].Name != "Sam Newhire" {
		t.Errorf("identities after the delta = %d, avery's title %v", len(idents), *idents["E1001"].Title)
	}
	if idents["E1002"].Status != "terminated" || len(res.Accounts) != 6 {
		t.Errorf("unchanged workers did not survive the merge: %+v", idents["E1002"])
	}
	cp2, _ := ms.Load(ctx, System, checkpointName)
	if cp2.FullSyncAt == nil || !cp2.FullSyncAt.Equal(*cp.FullSyncAt) || cp2.Cursor != now0.Add(time.Hour-watermarkOverlap).Format(time.RFC3339) {
		t.Errorf("checkpoint after an incremental sync = %+v", cp2)
	}
}

func TestInvalidOrExpiredCheckpointsFallBackToFullRead(t *testing.T) {
	blob := func(v any) []byte {
		b, err := connsync.EncodeState(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for name, mod := range map[string]func(cp *connsync.Checkpoint){
		"cursor is not a time":      func(cp *connsync.Checkpoint) { cp.Cursor = "not-a-time" },
		"cursor is in the future":   func(cp *connsync.Checkpoint) { cp.Cursor = now0.Add(48 * time.Hour).Format(time.RFC3339) },
		"state is not a snapshot":   func(cp *connsync.Checkpoint) { cp.State = []byte("garbage") },
		"state is another version":  func(cp *connsync.Checkpoint) { cp.State = blob(&state{Version: 99, Workers: map[string]*wWorker{}}) },
		"state has no worker map":   func(cp *connsync.Checkpoint) { cp.State = blob(&state{Version: stateVersion}) },
		"cursor is empty":           func(cp *connsync.Checkpoint) { cp.Cursor = "" },
		"last full read is too old": func(cp *connsync.Checkpoint) { old := now0.Add(-48 * time.Hour); cp.FullSyncAt = &old },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			ms := &connsync.MemoryStore{}
			ctx := connsync.WithStore(context.Background(), ms)
			cfg := baseCfg()
			cfg.MaxIncrementalAge = 24 * time.Hour
			if _, err := f.connector(cfg).Discover(ctx); err != nil {
				t.Fatal(err)
			}
			cp, _ := ms.Load(ctx, System, checkpointName)
			mod(cp)
			_ = ms.Save(ctx, System, checkpointName, cp)
			res, err := f.connector(cfg).Discover(ctx)
			if err != nil || len(res.Accounts) != 5 {
				t.Fatalf("Discover = %v, %v", res, err)
			}
			if f.fullWorkerReads() != 2 {
				t.Errorf("full worker reads = %d, want 2 (the damaged checkpoint is not used)", f.fullWorkerReads())
			}
			if cp2, _ := ms.Load(ctx, System, checkpointName); cp2 == nil || cp2.FullSyncAt == nil || !cp2.FullSyncAt.Equal(now0) {
				t.Errorf("the repaired checkpoint = %+v", cp2)
			}
		})
	}
	for _, status := range []int{400, 410} {
		t.Run(fmt.Sprintf("workday refuses the watermark with %d", status), func(t *testing.T) {
			f := newFake(t)
			ms := &connsync.MemoryStore{}
			ctx := connsync.WithStore(context.Background(), ms)
			c := f.connector(baseCfg())
			if _, err := c.Discover(ctx); err != nil {
				t.Fatal(err)
			}
			f.refuseWatermark = status
			f.now = now0.Add(time.Hour)
			res, err := c.Discover(ctx)
			if err != nil || len(res.Accounts) != 5 {
				t.Fatalf("Discover = %v, %v", res, err)
			}
			if f.updatedReads(workersPath) != 1 || f.fullWorkerReads() != 2 {
				t.Errorf("watermark reads = %d, full reads = %d, want 1 and 2", f.updatedReads(workersPath), f.fullWorkerReads())
			}
			// events fall back the same way
			if err := c.StreamEvents(ctx, nil, func(connectors.Event) error { return nil }); err != nil {
				t.Fatal(err)
			}
			evs := collect(t, c, ctx, nil)
			if len(evs) != 6 || f.updatedReads(eventsPath) != 1 {
				t.Errorf("events = %d, watermark event reads = %d", len(evs), f.updatedReads(eventsPath))
			}
		})
	}
}

func TestFullResyncOnDemand(t *testing.T) {
	f := newFake(t)
	ms := &connsync.MemoryStore{}
	ctx := connsync.WithStore(context.Background(), ms)
	c := f.connector(baseCfg())
	if _, err := c.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	if f.fullWorkerReads() != 1 {
		t.Fatalf("full reads before = %d", f.fullWorkerReads())
	}
	if _, err := c.Discover(connsync.WithMode(ctx, connsync.Full)); err != nil {
		t.Fatal(err)
	}
	if f.fullWorkerReads() != 2 {
		t.Errorf("a requested full re-sync did not read everything: %d", f.fullWorkerReads())
	}
	collect(t, c, ctx, nil)
	collect(t, c, ctx, nil)
	collect(t, c, connsync.WithMode(ctx, connsync.Full), nil)
	if f.fullEventReads() != 2 || f.updatedReads(eventsPath) != 1 {
		t.Errorf("event reads: full %d, incremental %d, want 2 and 1", f.fullEventReads(), f.updatedReads(eventsPath))
	}
}

func TestNoStoreMeansAlwaysFull(t *testing.T) {
	f := newFake(t)
	c := f.connector(baseCfg())
	for i := 0; i < 2; i++ {
		if _, err := c.Discover(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if f.fullWorkerReads() != 2 {
		t.Errorf("full reads = %d, want 2", f.fullWorkerReads())
	}
}

// ---------------------------------------------------------------- events

func TestStreamEventsMapsToTheHRISModel(t *testing.T) {
	f := newFake(t)
	c := f.connector(baseCfg())
	ms := &connsync.MemoryStore{}
	ctx := connsync.WithStore(context.Background(), ms)
	if _, err := c.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	evs := collect(t, c, ctx, nil)
	if len(evs) != 6 { // the unknown type and the unreadable date are dropped
		t.Fatalf("events = %d", len(evs))
	}
	var order []string
	for _, e := range evs {
		order = append(order, e.ExternalID)
	}
	if strings.Join(order, ",") != "wd-evt-EVT-6,wd-evt-EVT-5,wd-evt-EVT-4,wd-evt-EVT-1,wd-evt-EVT-3,wd-evt-EVT-2" {
		t.Errorf("order (oldest effective date first) = %v", order)
	}
	m := byID(evs)

	// hire, still ahead: a pending joiner with the future effective date and no identity yet
	j := m["wd-evt-EVT-1"]
	p := payload(t, j)
	if j.Type != "joiner" || j.Identity != nil || !j.EffectiveAt.Equal(time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)) ||
		p["name"] != "Jordan Pending" || p["email"] != "jordan.pending@example.com" || p["department"] != "Platform Engineering" ||
		p["team"] != "platform-engineering" || p["title"] != "Data Engineer" || p["manager_external_id"] != "E1000" || p["employee_id"] != "E1003" {
		t.Errorf("joiner = %+v %v", j, p)
	}
	if _, ok := p["historical"]; ok {
		t.Error("a future hire is marked historical (ingest would call it executed)")
	}

	// termination, still ahead
	l := m["wd-evt-EVT-2"]
	p = payload(t, l)
	if l.Type != "leaver" || l.Identity == nil || l.Identity.ExternalID != "E1004" || l.Identity.Email != "casey.leaving@example.com" ||
		!l.EffectiveAt.Equal(time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)) || p["reason"] != "Resignation" || p["last_day"] != "2026-12-31" {
		t.Errorf("future leaver = %+v %v", l, p)
	}
	if _, ok := p["historical"]; ok {
		t.Error("a future leaver is marked historical")
	}

	// job change with an organization change
	mv := m["wd-evt-EVT-3"]
	p = payload(t, mv)
	if mv.Type != "mover" || mv.Identity.ExternalID != "E1001" || !mv.EffectiveAt.Equal(time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)) ||
		p["from_team"] != "platform-engineering" || p["to_team"] != "site-reliability" || p["to_department"] != "Site Reliability" ||
		p["new_title"] != "Senior SRE" || p["change"] != "job_change" {
		t.Errorf("job change = %+v %v", mv, p)
	}

	// manager change: no team change, so the mover flow changes no access
	mc := m["wd-evt-EVT-4"]
	p = payload(t, mc)
	if mc.Type != "mover" || mc.Identity.ExternalID != "workday:w-1005" || p["from_team"] != "customer-support" || p["to_team"] != "customer-support" ||
		p["from_manager_external_id"] != "E1000" || p["to_manager_external_id"] != "E1001" || p["change"] != "manager_change" {
		t.Errorf("manager change = %+v %v", mc, p)
	}
	if _, ok := p["new_title"]; ok {
		t.Error("a manager change carries a title")
	}

	// a termination that took effect within the window is pending; a hire already realized is historical
	if e := m["wd-evt-EVT-5"]; e.Type != "leaver" || e.Identity.ExternalID != "E1002" {
		t.Errorf("recent leaver = %+v", e)
	} else if _, ok := payload(t, e)["historical"]; ok {
		t.Error("a termination from last week is historical")
	}
	if e := m["wd-evt-EVT-6"]; e.Type != "joiner" || e.Identity == nil || e.Identity.ExternalID != "E1001" {
		t.Errorf("old hire = %+v", e)
	} else if h, _ := payload(t, e)["historical"].(bool); !h {
		t.Error("a hire that already took effect is not historical (executing it would duplicate the identity)")
	}
}

func TestEventWindowMarksOldEventsHistorical(t *testing.T) {
	f := newFake(t)
	f.body[eventsPath] = `{"total":2,"data":[
	 {"id":"OLD","type":"TERMINATE","effectiveDate":"2026-08-01","worker":{"id":"w-1002","employeeId":"E1002"}},
	 {"id":"EDGE","type":"TERMINATE","effectiveDate":"2026-09-10","worker":{"id":"w-1002","employeeId":"E1002"}}]}`
	evs := byID(collect(t, f.connector(baseCfg()), context.Background(), nil))
	if _, ok := payload(t, evs["wd-evt-OLD"])["historical"]; !ok {
		t.Error("an event older than the window is pending")
	}
	if _, ok := payload(t, evs["wd-evt-EDGE"])["historical"]; ok {
		t.Error("an event inside the window is historical")
	}
	cfg := baseCfg()
	cfg.EventWindow = 90 * 24 * time.Hour
	evs = byID(collect(t, f.connector(cfg), context.Background(), nil))
	if _, ok := payload(t, evs["wd-evt-OLD"])["historical"]; ok {
		t.Error("the window is not configurable")
	}
	q := ""
	for _, r := range f.srv.Requests() {
		if r.Path == eventsPath {
			q = r.Query
		}
	}
	if !strings.Contains(q, "Effective_From=2026-07-10") {
		t.Errorf("the full read asked for %q, want Effective_From 90 days back", q)
	}
}

func TestEventsIncrementalAndSince(t *testing.T) {
	f := newFake(t)
	ms := &connsync.MemoryStore{}
	ctx := connsync.WithStore(context.Background(), ms)
	c := f.connector(baseCfg())
	if _, err := c.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(collect(t, c, ctx, nil)); n != 6 {
		t.Fatalf("first read = %d events", n)
	}
	cp, _ := ms.Load(ctx, System, eventsCheckpoint)
	if cp == nil || cp.FullSyncAt == nil || cp.Cursor != now0.Add(-watermarkOverlap).Format(time.RFC3339) || len(cp.State) == 0 {
		t.Fatalf("events checkpoint = %+v", cp)
	}
	// the second read asks only for what was updated: a rescheduled event keeps its id and moves its date
	f.changed = true
	f.now = now0.Add(time.Hour)
	evs := collect(t, c, ctx, nil)
	if len(evs) != 1 || evs[0].ExternalID != "wd-evt-EVT-3" || !evs[0].EffectiveAt.Equal(time.Date(2026, 11, 30, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("incremental events = %+v", evs)
	}
	if f.fullEventReads() != 1 || f.updatedReads(eventsPath) != 1 {
		t.Errorf("event reads: full %d, incremental %d", f.fullEventReads(), f.updatedReads(eventsPath))
	}
	// since overrides the checkpoint and leaves it alone
	cpBefore, _ := ms.Load(ctx, System, eventsCheckpoint)
	since := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	collect(t, c, ctx, &since)
	cpAfter, _ := ms.Load(ctx, System, eventsCheckpoint)
	if cpAfter.Cursor != cpBefore.Cursor {
		t.Errorf("a read with an explicit since moved the checkpoint: %s -> %s", cpBefore.Cursor, cpAfter.Cursor)
	}
	var last string
	for _, r := range f.srv.Requests() {
		if q, _ := url.ParseQuery(r.Query); r.Path == eventsPath && q.Has("Updated_From") {
			last = q.Get("Updated_From")
		}
	}
	if last != "2026-10-01T00:00:00Z" {
		t.Errorf("Updated_From for since = %q", last)
	}
}

func TestEventsCheckpointNotAdvancedWhenYieldFails(t *testing.T) {
	f := newFake(t)
	ms := &connsync.MemoryStore{}
	ctx := connsync.WithStore(context.Background(), ms)
	c := f.connector(baseCfg())
	if _, err := c.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	n := 0
	err := c.StreamEvents(ctx, nil, func(connectors.Event) error {
		if n++; n == 2 {
			return boom
		}
		return nil
	})
	if !errors.Is(err, boom) || n != 2 {
		t.Fatalf("err = %v after %d events", err, n)
	}
	if cp, _ := ms.Load(ctx, System, eventsCheckpoint); cp != nil {
		t.Errorf("a failed stream saved a checkpoint: %+v", cp)
	}
}

func TestEventsWithoutAStoredSnapshotReadTheWorkers(t *testing.T) {
	f := newFake(t)
	evs := byID(collect(t, f.connector(baseCfg()), context.Background(), nil))
	if p := payload(t, evs["wd-evt-EVT-1"]); p["name"] != "Jordan Pending" || p["email"] != "jordan.pending@example.com" {
		t.Errorf("joiner payload without a snapshot = %v", p)
	}
	if f.fullWorkerReads() != 1 {
		t.Errorf("worker reads = %d", f.fullWorkerReads())
	}
}

func TestRecordDropsWhatItCannotUse(t *testing.T) {
	c := newFake(t).connector(baseCfg())
	st := newState()
	st.Workers["w-1"] = &wWorker{ID: "w-1", EmployeeID: "E1", Org: wOrg{Descriptor: "Ops"}}
	ok := wEvent{ID: "E-1", Type: "terminate", EffectiveDate: "2026-10-20", Worker: wRef{ID: "w-1"}}
	if r := c.record(ok, st, now0); r == nil || r.Type != "leaver" || r.Identity.ExternalID != "E1" {
		t.Fatalf("record = %+v", r)
	}
	for name, mod := range map[string]func(*wEvent){
		"unknown type":      func(e *wEvent) { e.Type = "TRANSFER" },
		"no date":           func(e *wEvent) { e.EffectiveDate = "" },
		"bad date":          func(e *wEvent) { e.EffectiveDate = "10/20/2026" },
		"no id":             func(e *wEvent) { e.ID = "" },
		"id with a slash":   func(e *wEvent) { e.ID = "a/b" },
		"unknown worker":    func(e *wEvent) { e.Worker = wRef{ID: "w-404"} },
		"no worker at all":  func(e *wEvent) { e.Worker = wRef{} },
		"mover, no team":    func(e *wEvent) { e.Type = "JOB_CHANGE"; e.Worker = wRef{EmployeeID: "E7"} },
		"id longer than 64": func(e *wEvent) { e.ID = strings.Repeat("x", 65) },
	} {
		e := ok
		mod(&e)
		if r := c.record(e, st, now0); r != nil {
			t.Errorf("%s: record = %+v", name, r)
		}
	}
	// a timestamp is a usable effective date
	e := ok
	e.EffectiveDate = "2026-10-20T04:00:00-04:00"
	if r := c.record(e, st, now0); r == nil || !r.EffectiveAt.Equal(time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)) {
		t.Errorf("timestamp date: %+v", r)
	}
}

// ---------------------------------------------------------------- credentials

func TestTokenFailureDoesNotLeakSecrets(t *testing.T) {
	f := newFake(t)
	f.status[tokenPath] = 401
	f.statusBody[tokenPath] = `{"error":"invalid_client","error_description":"` + clientSec + ` and ` + refreshTok + ` are wrong"}`
	cfg := baseCfg()
	cfg.RefreshToken = connsync.NewSecret(refreshTok)
	_, err := f.connector(cfg).Discover(context.Background())
	if connsync.Status(err) != 401 || !strings.Contains(err.Error(), "invalid_client") {
		t.Fatalf("err = %v", err)
	}
	basic := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSec))
	for _, leak := range []string{clientSec, refreshTok, "are wrong", basic} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error %q leaks %q", err, leak)
		}
	}
	if s := fmt.Sprintf("%v %+v %#v", cfg, cfg, cfg); strings.Contains(s, clientSec) || strings.Contains(s, refreshTok) {
		t.Error("the config prints a secret")
	}
	// an API failure names neither the token nor the body
	f2 := newFake(t)
	f2.status[workersPath] = 403
	_, err = f2.connector(baseCfg()).Discover(context.Background())
	if connsync.Status(err) != 403 || strings.Contains(err.Error(), "leaky") || strings.Contains(err.Error(), "wd-token-1") {
		t.Errorf("err = %v", err)
	}
}

func TestExpiredTokenIsRefreshedOnce(t *testing.T) {
	f := newFake(t)
	calls := 0
	f.override = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == tokenPath {
			f.forms = append(f.forms, nil)
			fmt.Fprint(w, `{"token_type":"Bearer","expires_in":3600,"access_token":"wd-token-1"}`)
			return
		}
		if calls++; calls == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"invalid_token"}`)
			return
		}
		fmt.Fprint(w, `{"total":0,"data":[]}`)
	}
	if _, err := f.connector(baseCfg()).Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.forms) != 2 {
		t.Errorf("token requests = %d, want 2 (one refresh after the 401)", len(f.forms))
	}
}

// ---------------------------------------------------------------- configuration

func TestNewValidatesConfiguration(t *testing.T) {
	prod := prodRT
	hc := prodClient(t)
	ok := baseCfg()
	ok.BaseURL = "https://wd2-impl-services1.workday.com"
	with := func(mod func(*Config)) Config { c := ok; mod(&c); return c }
	tests := []struct {
		name string
		cfg  Config
		good bool
	}{
		{"defaults", ok, true},
		{"refresh token", with(func(c *Config) { c.RefreshToken = connsync.NewSecret("r") }), true},
		{"custom report paths", with(func(c *Config) {
			c.WorkersPath = "/ccx/service/customreport2/{tenant}/isu/Workers_JSON"
			c.EventsPath = "/ccx/service/customreport2/{tenant}/isu/Worker_Events_JSON"
		}), true},
		{"explicit token url", with(func(c *Config) { c.TokenURL = "https://auth.example.com/token" }), true},
		{"no tenant", with(func(c *Config) { c.Tenant = "" }), false},
		{"tenant with a slash", with(func(c *Config) { c.Tenant = "a/b" }), false},
		{"no client id", with(func(c *Config) { c.ClientID = "" }), false},
		{"no secret", with(func(c *Config) { c.ClientSecret = connsync.Secret{} }), false},
		{"http base", with(func(c *Config) { c.BaseURL = "http://wd2-impl-services1.workday.com" }), false},
		{"base with a path", with(func(c *Config) { c.BaseURL = "https://wd2-impl-services1.workday.com/ccx" }), false},
		{"private base", with(func(c *Config) { c.BaseURL = "https://10.0.0.5" }), false},
		{"no base", with(func(c *Config) { c.BaseURL = "" }), false},
		{"loopback token url in prod", with(func(c *Config) { c.TokenURL = "https://127.0.0.1:9/token" }), false},
		{"path without a slash", with(func(c *Config) { c.WorkersPath = "workers" }), false},
		{"path with a query", with(func(c *Config) { c.WorkersPath = "/workers?x=1" }), false},
		{"path with ..", with(func(c *Config) { c.EventsPath = "/ccx/../admin" }), false},
		{"path with //", with(func(c *Config) { c.EventsPath = "//evil.example.net/x" }), false},
		{"window under a day", with(func(c *Config) { c.EventWindow = time.Hour }), false},
	}
	for _, tc := range tests {
		if _, err := New(tc.cfg, prod, hc, nil); (err == nil) != tc.good {
			t.Errorf("%s: New = %v, want ok=%v", tc.name, err, tc.good)
		}
	}
	if _, err := New(ok, prod, nil, nil); err == nil {
		t.Error("New accepted a nil HTTP client")
	}
}

func TestFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	good := map[string]string{"TESSERA_ENV": "prod", "TESSERA_WORKDAY_BASE_URL": "https://wd2-impl-services1.workday.com",
		"TESSERA_WORKDAY_TENANT": "acme_dpt1", "TESSERA_WORKDAY_CLIENT_ID": "cid", "TESSERA_WORKDAY_CLIENT_SECRET": "env:WD_SECRET", "WD_SECRET": "s3cret"}
	c, err := FromEnv(env(good), now0, prodRT, prodClient(t))
	if err != nil || c.System() != "workday" || c.TypeName() != "WorkdayConnector" || c.DisplayName() != "Workday" {
		t.Fatalf("FromEnv = %v, %v", c, err)
	}
	cfg := c.(*Connector).cfg
	if !cfg.EmitIdentities || cfg.MaxIncrementalAge != 24*time.Hour || cfg.EventWindow != 30*24*time.Hour || !cfg.RefreshToken.Empty() ||
		cfg.TokenURL != "https://wd2-impl-services1.workday.com/ccx/oauth2/acme_dpt1/token" || cfg.WorkersPath != DefaultWorkersPath {
		t.Errorf("defaults = %+v", cfg)
	}
	mod := func(k, v string) map[string]string {
		m := map[string]string{}
		for kk, vv := range good {
			m[kk] = vv
		}
		m[k] = v
		return m
	}
	for name, m := range map[string]map[string]string{
		"literal secret":      mod("TESSERA_WORKDAY_CLIENT_SECRET", "literal-secret"),
		"unset secret":        mod("TESSERA_WORKDAY_CLIENT_SECRET", ""),
		"missing env":         mod("TESSERA_WORKDAY_CLIENT_SECRET", "env:NOPE"),
		"literal refresh":     mod("TESSERA_WORKDAY_REFRESH_TOKEN", "literal-refresh"),
		"bad tenant":          mod("TESSERA_WORKDAY_TENANT", "a b"),
		"no base":             mod("TESSERA_WORKDAY_BASE_URL", ""),
		"bad bool":            mod("TESSERA_WORKDAY_EMIT_IDENTITIES", "sometimes"),
		"bad age":             mod("TESSERA_WORKDAY_MAX_INCREMENTAL_AGE", "1s"),
		"negative age":        mod("TESSERA_WORKDAY_MAX_INCREMENTAL_AGE", "-1h"),
		"bad window":          mod("TESSERA_WORKDAY_EVENT_WINDOW", "1h"),
		"http base":           mod("TESSERA_WORKDAY_BASE_URL", "http://wd2-impl-services1.workday.com"),
		"bad workers path":    mod("TESSERA_WORKDAY_WORKERS_PATH", "workers"),
		"loopback in prod":    mod("TESSERA_OUTBOUND_ALLOW_LOOPBACK", "true"),
		"token url over http": mod("TESSERA_WORKDAY_TOKEN_URL", "http://auth.example.com/token"),
	} {
		_, err := FromEnv(env(m), now0, prodRT, prodClient(t))
		if name == "loopback in prod" {
			if err != nil {
				t.Errorf("%s: %v (the flag is ignored in prod, the defaults are valid)", name, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: FromEnv succeeded", name)
		} else if strings.Contains(err.Error(), "literal-secret") || strings.Contains(err.Error(), "literal-refresh") {
			t.Errorf("%s: error echoes the credential: %v", name, err)
		}
	}
	off := mod("TESSERA_WORKDAY_EMIT_IDENTITIES", "false")
	off["TESSERA_WORKDAY_MAX_INCREMENTAL_AGE"] = "0"
	off["TESSERA_WORKDAY_EVENT_WINDOW"] = "72h"
	off["TESSERA_WORKDAY_REFRESH_TOKEN"] = "env:WD_REFRESH"
	off["WD_REFRESH"] = "r"
	c, err = FromEnv(env(off), now0, prodRT, prodClient(t))
	if err != nil {
		t.Fatal(err)
	}
	if g := c.(*Connector).cfg; g.EmitIdentities || g.MaxIncrementalAge != 0 || g.EventWindow != 72*time.Hour || g.RefreshToken.Empty() {
		t.Errorf("FromEnv(off) = %+v", g)
	}
}

func TestHelpers(t *testing.T) {
	for in, want := range map[string]string{"Platform Engineering": "platform-engineering", "  Site Reliability (EMEA) ": "site-reliability-emea",
		"Support": "support", "": "", "---": ""} {
		if got := teamSlug(in); got != want {
			t.Errorf("teamSlug(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"hire": "HIRE", "Job Change": "JOB_CHANGE", "manager-change": "MANAGER_CHANGE"} {
		if got := normType(in); got != want {
			t.Errorf("normType(%q) = %q, want %q", in, got, want)
		}
	}
	for _, s := range []string{"2026-10-08", "2026-10-08T00:00:00Z", "2026-10-08T02:00:00+02:00"} {
		if d := parseDate(s); d == nil || !d.Equal(time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)) {
			t.Errorf("parseDate(%q) = %v", s, d)
		}
	}
	for _, s := range []string{"", "yesterday", "2026-13-40"} {
		if parseDate(s) != nil {
			t.Errorf("parseDate(%q) parsed", s)
		}
	}
}

// prodRT is the production runtime; prodClient is a production-rules safehttp
// test client (no loopback, https, default ports).
var prodRT = connsync.Runtime{Env: "prod"}

func prodClient(t testing.TB) *http.Client {
	t.Helper()
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	return hc
}

// testClient is a safehttp test client that reaches srv.
func testClient(t testing.TB, srv *connsynctest.Server, maxBody int64) *http.Client {
	t.Helper()
	hc, err := safehttp.NewForTest(t, srv.Options(maxBody))
	if err != nil {
		t.Fatal(err)
	}
	return hc
}
