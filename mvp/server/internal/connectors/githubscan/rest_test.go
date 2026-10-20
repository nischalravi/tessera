package githubscan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

var now0 = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)

const testToken = "test-token-not-real"

// fakeGitHub replays recorded REST responses for the org "acme".
type fakeGitHub struct {
	t        *testing.T
	srv      *connsynctest.Server
	mu       sync.Mutex
	override http.HandlerFunc
}

func (f *fakeGitHub) setOverride(h http.HandlerFunc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.override = h
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	f := &fakeGitHub{t: t}
	f.srv = connsynctest.New(t, http.HandlerFunc(f.serve))
	return f
}

func (f *fakeGitHub) fixture(name string) string {
	return string(connsynctest.Fixture(f.t, name, f.srv.URL))
}

func (f *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	ov := f.override
	f.mu.Unlock()
	if ov != nil {
		ov(w, r)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+testToken {
		f.t.Errorf("request %s without the token: %q", r.URL.Path, r.Header.Get("Authorization"))
	}
	q := r.URL.Query()
	switch {
	case r.URL.Path == "/orgs/acme/repos" && q.Get("page") == "2":
		fmt.Fprint(w, f.fixture("repos_p2.json"))
	case r.URL.Path == "/orgs/acme/repos":
		w.Header().Set("Link", fmt.Sprintf(`<%s/orgs/acme/repos?per_page=100&page=2>; rel="next"`, f.srv.URL))
		fmt.Fprint(w, f.fixture("repos_p1.json"))
	case r.URL.Path == "/repos/acme/agents/git/trees/main":
		fmt.Fprint(w, f.fixture("tree_agents.json"))
	case r.URL.Path == "/repos/acme/platform/git/trees/trunk":
		fmt.Fprint(w, f.fixture("tree_platform.json"))
	case r.URL.Path == "/repos/acme/empty-repo/git/trees/main":
		w.WriteHeader(http.StatusConflict)
		fmt.Fprint(w, `{"message":"Git Repository is empty."}`)
	case r.URL.Path == "/repos/acme/agents/contents/.github/CODEOWNERS":
		fmt.Fprint(w, f.fixture("CODEOWNERS"))
	case r.URL.Path == "/repos/acme/agents/contents/.mcp.json":
		_, _ = w.Write(render(f.t, "mcp_json.tmpl"))
	case r.URL.Path == "/repos/acme/agents/contents/.cursor/mcp.json":
		fmt.Fprint(w, f.fixture("cursor_mcp.json"))
	case r.URL.Path == "/repos/acme/agents/contents/.env":
		_, _ = w.Write(render(f.t, "env.tmpl"))
	case r.URL.Path == "/repos/acme/platform/contents/mcp.json":
		_, _ = w.Write(render(f.t, "platform_mcp.json"))
	case r.URL.Path == "/repos/acme/platform/commits" && q.Get("path") == "mcp.json":
		fmt.Fprint(w, `[{"sha":"c0ffee0000000000000000000000000000000001","author":{"login":"devon"},"commit":{"author":{"email":"12345+devon@users.noreply.github.com"}}}]`)
	case r.URL.Path == "/repos/acme/agents/commits":
		fmt.Fprintf(w, `[{"sha":"abc1230000000000000000000000000000000002","author":null,"commit":{"author":{"email":"pat@example.com"}}}]`)
	default:
		f.t.Errorf("unexpected request %s %s", r.Method, r.URL.String())
		http.NotFound(w, r)
	}
}

func (f *fakeGitHub) source(t *testing.T, cfg RESTConfig) *REST {
	t.Helper()
	cfg.APIURL, cfg.Org = f.srv.URL, "acme"
	if cfg.Token.Empty() {
		cfg.Token = connsync.NewSecret(testToken)
	}
	g, err := NewREST(cfg, connsynctest.Runtime, testClient(t, f.srv, 0), func() time.Time { return now0 })
	if err != nil {
		t.Fatal(err)
	}
	g.api.Backoff = connsync.Backoff{Base: time.Millisecond, Max: time.Second, MaxAttempts: 2, Sleep: (&connsynctest.NoSleep{}).Sleep}
	return g
}

func (f *fakeGitHub) connector(t *testing.T) *Connector {
	t.Helper()
	c, err := New(f.source(t, RESTConfig{}), func() time.Time { return now0 })
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRESTScanEndToEnd(t *testing.T) {
	f := newFakeGitHub(t)
	res, err := f.connector(t).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.AgentSnapshotOf) != 1 || res.AgentSnapshotOf[0] != System || len(res.Identities)+len(res.Accounts) != 0 {
		t.Fatalf("snapshot %v, identities %d", res.AgentSnapshotOf, len(res.Identities))
	}
	// only reads, and only the repositories worth scanning: no archived repo, no fork, no empty repo, no path-traversal name
	methods := map[string]int{}
	for _, r := range f.srv.Requests() {
		methods[r.Method]++
	}
	if methods[http.MethodGet] == 0 || len(methods) != 1 {
		t.Errorf("methods = %v", methods)
	}
	for _, r := range f.srv.Requests() {
		for _, bad := range []string{"old-stuff", "forked", "escape", "node_modules", ".env.example", "README", "big/"} {
			if strings.Contains(r.Path, bad) && !strings.Contains(r.Path, "/orgs/") {
				t.Errorf("fetched %s", r.Path)
			}
		}
	}
	type key struct{ repo, path, loc string }
	got := map[key]connectors.MCPFindingRecord{}
	for _, m := range res.MCPFindings {
		if m.System != System || m.Org != "acme" {
			t.Errorf("finding = %+v", m)
		}
		got[key{m.Repo, m.Path, m.Location}] = m
	}
	// .mcp.json is owned by CODEOWNERS: the person, not the team
	gh := got[key{"agents", ".mcp.json", "mcpServers.github.env.GITHUB_PERSONAL_ACCESS_TOKEN"}]
	if gh.SecretType != "github_token" || gh.OwnerSource != "codeowners" || gh.OwnerRef != "ada.fixture@example.com" ||
		gh.Owner == nil || gh.Owner.Email != "ada.fixture@example.com" || gh.CommitSHA != "abc1230000000000000000000000000000000002" {
		t.Errorf("github token finding = %+v", gh)
	}
	// .cursor/mcp.json is owned by a team: the owner of record, with no person to resolve to
	if cur := got[key{"agents", ".cursor/mcp.json", "mcpServers.docs"}]; cur.Kind != KindMCPServer || cur.OwnerRef != "github-team:acme/ai-platform" || cur.Owner != nil {
		t.Errorf("cursor finding = %+v", cur)
	}
	// .env falls under "*": the team again
	if env := got[key{"agents", ".env", "L3"}]; env.SecretType != "anthropic_api_key" || env.OwnerRef != "github-team:acme/engineering" {
		t.Errorf("env finding = %+v", env)
	}
	// platform has no CODEOWNERS: the committer, found through a noreply address
	pf := got[key{"platform", "mcp.json", "servers.fetch.headers.Authorization"}]
	if pf.SecretType != "bearer_token" || pf.OwnerSource != "committer" || pf.OwnerRef != "github:devon" ||
		pf.Owner == nil || pf.Owner.ExternalID != "github:devon" || pf.CommitSHA != "c0ffee0000000000000000000000000000000001" {
		t.Errorf("platform finding = %+v", pf)
	}
	raw, _ := json.Marshal(res)
	for name, v := range fakeSecrets() {
		if strings.Contains(string(raw), v) {
			t.Errorf("the result contains the %s value", name)
		}
	}
	if strings.Contains(string(raw), testToken) {
		t.Error("the result contains the API token")
	}
}

func TestRESTRefusals(t *testing.T) {
	f := newFakeGitHub(t)
	hc := testClient(t, f.srv, 0)
	tok := connsync.NewSecret(testToken)
	for name, cfg := range map[string]RESTConfig{
		"plain http":     {APIURL: "http://api.github.example.com", Org: "acme", Token: tok},
		"bad org":        {APIURL: f.srv.URL, Org: "../acme", Token: tok},
		"no token":       {APIURL: f.srv.URL, Org: "acme"},
		"url with creds": {APIURL: "https://u:p@api.github.com", Org: "acme", Token: tok},
	} {
		if _, err := NewREST(cfg, connsync.Runtime{Env: "prod"}, hc, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NewREST(RESTConfig{Org: "acme", Token: tok}, connsynctest.Runtime, nil, nil); err == nil {
		t.Error("built without a safehttp client")
	}
}

func TestRESTPageLinkMustStayOnTheHost(t *testing.T) {
	f := newFakeGitHub(t)
	f.setOverride(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<https://evil.example.net/orgs/acme/repos?page=2>; rel="next"`)
		fmt.Fprint(w, `[]`)
	})
	if _, err := f.source(t, RESTConfig{}).Repos(context.Background()); err == nil {
		t.Error("followed a next link to another host with the token")
	}
}

func TestRESTErrorsDoNotQuoteTheBody(t *testing.T) {
	f := newFakeGitHub(t)
	f.setOverride(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"message":"leaky-body-should-never-surface"}`)
	})
	_, err := f.connector(t).Discover(context.Background())
	if err == nil || strings.Contains(err.Error(), "leaky") || strings.Contains(err.Error(), testToken) {
		t.Errorf("err = %v", err)
	}
}

func TestFromEnvRequiresAToken(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if _, err := FromEnv(env(map[string]string{"TESSERA_GITHUB_SCAN_ORG": "acme"}), now0, prodRT, prodClient(t)); err == nil {
		t.Error("built without a token")
	}
	if _, err := FromEnv(env(map[string]string{"TESSERA_GITHUB_SCAN_ORG": "acme", "TESSERA_GITHUB_SCAN_TOKEN": "env:NOPE"}), now0, prodRT, prodClient(t)); err == nil {
		t.Error("built with an unset token reference")
	}
	c, err := FromEnv(env(map[string]string{"TESSERA_GITHUB_SCAN_ORG": "acme", "TESSERA_GITHUB_SCAN_TOKEN": "env:T", "T": "x"}), now0, prodRT, prodClient(t))
	if err != nil || c.System() != System {
		t.Errorf("FromEnv = %v, %v", c, err)
	}
}

// Integration test against a real GitHub organization (needs-human). It is
// skipped unless the variables below are set, so CI makes no live call.
//
//	TESSERA_GITHUB_DEV_ORG      an organization you may read
//	TESSERA_GITHUB_DEV_TOKEN    a read-only token (Contents: read, Metadata: read)
//
// Run: go test ./internal/connectors/githubscan -run Integration -v
func TestIntegrationDevOrg(t *testing.T) {
	org, tok := os.Getenv("TESSERA_GITHUB_DEV_ORG"), os.Getenv("TESSERA_GITHUB_DEV_TOKEN")
	if org == "" || tok == "" {
		t.Skip("TESSERA_GITHUB_DEV_ORG and TESSERA_GITHUB_DEV_TOKEN are not set: skipping the live GitHub test (needs-human)")
	}
	rt := connsync.Runtime{Env: "prod"}
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: "prod", Timeout: 30 * time.Second, MaxBodyBytes: 16 << 20})
	if err != nil {
		t.Fatal(err)
	}
	src, err := NewREST(RESTConfig{Org: org, Token: connsync.NewSecret(tok), MaxRepos: 5}, rt, hc, nil)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := New(src, nil)
	res, err := c.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d findings in %s", len(res.MCPFindings), org)
}

var tenantA = tenancy.MustParse("00000000-0000-4000-8000-0000000000f1")

// A scan is stored without a secret value, linked to an owner who exists, and
// replaced wholesale by the next one.
func TestIngestStoresFindingsAndReplacesThem(t *testing.T) {
	f := newFakeGitHub(t)
	db := testkit.Open(t)
	testkit.CreateTenant(t, db, tenantA, "github-scan")
	sync := func(conns ...connectors.Connector) ingest.SyncStats {
		var st ingest.SyncStats
		if err := db.InTenant(context.Background(), tenantA, func(c *store.TenantTx) error {
			var err error
			st, err = ingest.Sync(c, testkit.Now, conns, nil)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return st
	}
	st := sync(hr{}, f.connector(t))
	if st.Discovery.MCPFindings == 0 {
		t.Fatal("no findings stored")
	}
	var total int
	tdb := &testkit.DB{DB: db, Tenant: tenantA}
	testkit.Read(t, tdb, func(tx *store.TenantTx) error {
		fs, err := tx.MCPFindings()
		if err != nil {
			t.Fatal(err)
		}
		total = len(fs)
		idents, _ := tx.Identities()
		ada := int64(0)
		for _, i := range idents {
			if i.ExternalID == "EMP-1" {
				ada = i.ID
			}
		}
		linked := 0
		for _, m := range fs {
			if m.OwnerID != nil && *m.OwnerID == ada && m.Path == ".mcp.json" {
				linked++
			}
			raw, _ := json.Marshal(m)
			for name, v := range fakeSecrets() {
				if strings.Contains(string(raw), v) {
					t.Errorf("stored finding contains the %s value", name)
				}
			}
		}
		if linked == 0 {
			t.Error("no .mcp.json finding is linked to Ada, the CODEOWNERS person")
		}
		return nil
	})
	// the next scan finds nothing: the stored findings go
	f.setOverride(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/orgs/acme/repos" {
			fmt.Fprint(w, `[]`)
			return
		}
		http.NotFound(w, r)
	})
	sync(hr{}, f.connector(t))
	testkit.Read(t, tdb, func(tx *store.TenantTx) error {
		if fs, _ := tx.MCPFindings(); len(fs) != 0 {
			t.Errorf("findings after an empty scan = %d (had %d)", len(fs), total)
		}
		return nil
	})
}

type hr struct{}

func (hr) System() string      { return "workday" }
func (hr) DisplayName() string { return "HR (test)" }
func (hr) TypeName() string    { return "TestHR" }
func (hr) Discover(context.Context) (*connectors.DiscoveryResult, error) {
	e := "ada.fixture@example.com"
	return &connectors.DiscoveryResult{Identities: []connectors.IdentityRecord{
		{ExternalID: "EMP-1", Name: "Ada Fixture", Type: "human", Email: &e, Status: "active"}}}, nil
}
func (hr) StreamEvents(context.Context, *time.Time, func(connectors.Event) error) error { return nil }

// testClient is a safehttp test client that reaches srv.
func testClient(t testing.TB, srv *connsynctest.Server, maxBody int64) *http.Client {
	t.Helper()
	hc, err := safehttp.NewForTest(t, srv.Options(maxBody))
	if err != nil {
		t.Fatal(err)
	}
	return hc
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
