package google

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

var now0 = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)

const (
	saEmail = "tessera-reader@fixture-project.iam.example.com"
	adminEm = "admin@example.com"
	ada     = "10000000001"
	ben     = "10000000002"
	cy      = "10000000003"
	gEng    = "g-eng"
	gPlat   = "g-plat"
	gFin    = "g-fin"
	roleSup = "9100000001"
	roleHD  = "9100000002"
	roleRd  = "9100000003"
)

const dirPrefix = "/admin/directory/v1"

var (
	keyOnce sync.Once
	testKey *rsa.PrivateKey
)

func signingKey(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	keyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		testKey = k
	})
	return testKey
}

func keyPEM(t testing.TB) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(signingKey(t))
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// fake replays the recorded fixtures as a Workspace customer.
type fake struct {
	t   *testing.T
	srv *connsynctest.Server

	mu         sync.Mutex
	changed    bool              // serve the changed groups and members
	status     map[string]int    // path prefix -> forced status
	statusBody map[string]string // path prefix -> body for a forced status
	body       map[string]string // path -> override body
	retry429   map[string]int    // path -> number of 429s to answer first
	retryRate  map[string]int    // path -> number of 403 rateLimitExceeded to answer first
	claims     []map[string]any  // verified assertion claims
	headers    []map[string]any  // assertion headers
	forms      []url.Values
	override   http.HandlerFunc
}

func newFake(t *testing.T) *fake {
	f := &fake{t: t, status: map[string]int{}, statusBody: map[string]string{}, body: map[string]string{},
		retry429: map[string]int{}, retryRate: map[string]int{}}
	f.srv = connsynctest.New(t, http.HandlerFunc(f.serve))
	return f
}

func (f *fake) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.forms = append(f.forms, r.PostForm)
	if r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		f.t.Errorf("grant_type = %q", r.PostForm.Get("grant_type"))
	}
	obj, err := jose.ParseSigned(r.PostForm.Get("assertion"), []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		f.t.Errorf("assertion is not an RS256 JWS: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	payload, err := obj.Verify(&signingKey(f.t).PublicKey)
	if err != nil {
		f.t.Errorf("assertion signature: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var claims map[string]any
	_ = json.Unmarshal(payload, &claims)
	f.claims = append(f.claims, claims)
	hdr := map[string]any{"alg": obj.Signatures[0].Header.Algorithm, "kid": obj.Signatures[0].Header.KeyID}
	f.headers = append(f.headers, hdr)
	fmt.Fprint(w, `{"token_type":"Bearer","expires_in":3599,"access_token":"google-token-1"}`)
}

func (f *fake) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.override != nil {
		f.override(w, r)
		return
	}
	if r.URL.Path == "/token" {
		if f.status["/token"] != 0 {
			w.WriteHeader(f.status["/token"])
			fmt.Fprint(w, f.statusBody["/token"])
			return
		}
		f.token(w, r)
		return
	}
	for p, s := range f.status {
		if strings.HasPrefix(r.URL.Path, p) {
			w.WriteHeader(s)
			b := f.statusBody[p]
			if b == "" {
				b = `{"error":{"code":403,"message":"leaky-body-should-never-surface","errors":[{"reason":"forbidden"}],"status":"PERMISSION_DENIED"}}`
			}
			fmt.Fprint(w, b)
			return
		}
	}
	if n := f.retry429[r.URL.Path]; n > 0 {
		f.retry429[r.URL.Path] = n - 1
		w.Header().Set("Retry-After", "4")
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	if n := f.retryRate[r.URL.Path]; n > 0 {
		f.retryRate[r.URL.Path] = n - 1
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":{"code":403,"message":"Rate Limit Exceeded","errors":[{"domain":"usageLimits","reason":"rateLimitExceeded"}]}}`)
		return
	}
	if b, ok := f.body[r.URL.Path]; ok {
		fmt.Fprint(w, b)
		return
	}
	out := func(name string) { _, _ = w.Write(connsynctest.Fixture(f.t, name, f.srv.URL)) }
	q := r.URL.Query()
	if r.Method != http.MethodGet {
		f.t.Errorf("non-GET request %s %s", r.Method, r.URL.Path)
	}
	switch p := strings.TrimPrefix(r.URL.Path, dirPrefix); p {
	case "/users":
		if q.Get("customer") != "my_customer" && q.Get("domain") == "" {
			f.t.Errorf("users list without a customer: %s", r.URL.RawQuery)
		}
		if q.Get("pageToken") == "u2" {
			out("users_p2.json")
		} else {
			out("users_p1.json")
		}
	case "/groups":
		if f.changed {
			out("groups_changed.json")
		} else {
			out("groups.json")
		}
	case "/groups/" + gEng + "/members":
		switch {
		case f.changed:
			out("members_eng_changed.json")
		case q.Get("pageToken") == "m2":
			out("members_eng_p2.json")
		default:
			out("members_eng_p1.json")
		}
	case "/groups/" + gPlat + "/members":
		out("members_plat.json")
	case "/groups/" + gFin + "/members":
		out("members_fin.json")
	case "/customer/my_customer/roles":
		out("roles.json")
	case "/customer/my_customer/roleassignments":
		out("roleassignments.json")
	default:
		f.t.Errorf("unexpected request %s %s", r.Method, r.URL.String())
		http.NotFound(w, r)
	}
}

func (f *fake) members() int { return f.srv.Count(dirPrefix + "/groups/") }

func baseCfg(t testing.TB) Config {
	return Config{ServiceAccountEmail: saEmail, AdminEmail: adminEm, KeyID: "key-id-1", PrivateKey: connsync.NewSecret(keyPEM(t)),
		EmitIdentities: true, Groups: true, Roles: true}
}

func (f *fake) connector(cfg Config) *Connector {
	f.t.Helper()
	cfg.APIURL, cfg.TokenURL = f.srv.URL, f.srv.URL+"/token"
	c, err := New(cfg, connsynctest.Runtime, testClient(f.t, f.srv, 0), func() time.Time { return now0 })
	if err != nil {
		f.t.Fatal(err)
	}
	c.api.Backoff = connsync.Backoff{Base: time.Millisecond, Max: 10 * time.Second, Sleep: (&connsynctest.NoSleep{}).Sleep}
	return c
}

func edgeSet(res *connectors.DiscoveryResult) map[string]bool {
	out := map[string]bool{}
	for _, e := range res.Edges {
		out[fmt.Sprintf("%s:%s->%s:%s %s", e.Src.Kind, e.Src.ExternalID, e.Dst.Kind, e.Dst.ExternalID, e.Relation)] = true
	}
	return out
}

func acctMap(res *connectors.DiscoveryResult) map[string]connectors.AccountRecord {
	m := map[string]connectors.AccountRecord{}
	for _, a := range res.Accounts {
		m[a.ExternalID] = a
	}
	return m
}

func groupMap(res *connectors.DiscoveryResult) map[string]connectors.GroupRecord {
	m := map[string]connectors.GroupRecord{}
	for _, g := range res.Groups {
		m[g.ExternalID] = g
	}
	return m
}

// ---------------------------------------------------------------- discovery

func TestDiscoverFull(t *testing.T) {
	f := newFake(t)
	res, err := f.connector(baseCfg(t)).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	accts := acctMap(res)
	if len(accts) != 3 { // the duplicate row and the row without an id are dropped
		t.Fatalf("accounts = %d: %v", len(accts), accts)
	}
	a := accts[ada]
	if a.Username != "ada.fixture@example.com" || a.Kind != "user" || a.Status != "active" || a.Identity.ExternalID != "EMP-3001" ||
		a.Identity.Email != "ada.fixture@example.com" || a.LastLoginAt == nil || !a.LastLoginAt.Equal(time.Date(2026, 10, 7, 8, 15, 0, 0, time.UTC)) ||
		a.CreatedAt == nil || a.Attributes["isAdmin"] != "true" || a.Attributes["department"] != "Engineering" {
		t.Errorf("ada = %+v", a)
	}
	b := accts[ben]
	if b.Status != "disabled" || b.LastLoginAt != nil || b.Identity.ExternalID != "google:"+ben || b.Attributes["suspended"] != "true" {
		t.Errorf("ben (suspended, never signed in) = %+v", b)
	}
	if c := accts[cy]; c.Status != "disabled" || c.Identity.ExternalID != "EMP-3003" || c.Attributes["archived"] != "true" {
		t.Errorf("cy (archived, custom employee id) = %+v", c)
	}
	if len(res.Identities) != 3 || res.Identities[0].ExternalID != "EMP-3001" || *res.Identities[0].Email != "ada.fixture@example.com" ||
		*res.Identities[0].Title != "Staff Engineer" {
		t.Errorf("identities = %+v", res.Identities)
	}
	groups := groupMap(res)
	if len(groups) != 6 {
		t.Fatalf("groups = %d: %v", len(groups), groups)
	}
	if g := groups[gEng]; g.Name != "Engineering" || g.Kind != "group" || g.Privileged {
		t.Errorf("engineering = %+v", g)
	}
	if g := groups["role:"+roleSup]; g.Kind != "role" || !g.Privileged || g.Name != "_SEED_ADMIN_ROLE" {
		t.Errorf("super admin role = %+v", g)
	}
	if g := groups["role:"+roleHD]; !g.Privileged {
		t.Errorf("help desk role = %+v", g)
	}
	if g := groups["role:"+roleRd]; g.Privileged {
		t.Errorf("reader role is privileged: %+v", g)
	}
	if _, ok := groups["role:9100000004"]; ok {
		t.Error("a role without assignments was emitted")
	}
	edges := edgeSet(res)
	for _, want := range []string{
		"account:" + ada + "->group:" + gEng + " member_of",
		"account:" + ben + "->group:" + gEng + " member_of",
		"account:" + cy + "->group:" + gEng + " member_of",  // from the second page of members
		"group:" + gEng + "->group:" + gPlat + " member_of", // nested group
		"account:" + cy + "->group:" + gFin + " member_of",
		"account:" + ada + "->group:role:" + roleSup + " member_of",
		"group:" + gPlat + "->group:role:" + roleHD + " member_of", // a role assigned to a group
		"account:" + ben + "->group:role:" + roleRd + " member_of",
	} {
		if !edges[want] {
			t.Errorf("missing edge %s in %v", want, edges)
		}
	}
	if len(edges) != 8 {
		t.Errorf("edges = %d, want 8 (external, customer-wide and unknown members are dropped): %v", len(edges), edges)
	}
}

func TestEmitIdentitiesOffLeavesCorrelationToHR(t *testing.T) {
	f := newFake(t)
	cfg := baseCfg(t)
	cfg.EmitIdentities = false
	res, err := f.connector(cfg).Discover(context.Background())
	if err != nil || len(res.Identities) != 0 || len(res.Accounts) != 3 {
		t.Fatalf("Discover = %+v, %v", res, err)
	}
	if res.Accounts[0].Identity.ExternalID == "" || res.Accounts[0].Identity.Email == "" {
		t.Errorf("account lacks the references correlation needs: %+v", res.Accounts[0])
	}
}

func TestRequestsAreReadOnlyScopedAndSigned(t *testing.T) {
	f := newFake(t)
	if _, err := f.connector(baseCfg(t)).Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, r := range f.srv.Requests() {
		if r.Path == "/token" {
			if r.Method != http.MethodPost {
				t.Errorf("token request is %s", r.Method)
			}
			continue
		}
		if r.Method != http.MethodGet {
			t.Errorf("%s %s: a read connector sent a %s", r.Method, r.Path, r.Method)
		}
		if r.Authorization != "Bearer google-token-1" {
			t.Errorf("%s: Authorization = %q", r.Path, r.Authorization)
		}
		if !strings.HasPrefix(r.Path, dirPrefix+"/") {
			t.Errorf("request left the Directory API: %s", r.Path)
		}
	}
	if len(f.claims) != 1 {
		t.Fatalf("token requests = %d, want 1 (the token is cached)", len(f.claims))
	}
	cl := f.claims[0]
	if cl["iss"] != saEmail || cl["sub"] != adminEm || cl["aud"] != f.srv.URL+"/token" {
		t.Errorf("claims = %v", cl)
	}
	if f.headers[0]["alg"] != "RS256" || f.headers[0]["kid"] != "key-id-1" {
		t.Errorf("header = %v", f.headers[0])
	}
	if exp, iat := cl["exp"].(float64), cl["iat"].(float64); exp-iat != 3600 || int64(iat) != now0.Unix() {
		t.Errorf("iat/exp = %v/%v", iat, exp)
	}
	scopes := strings.Fields(cl["scope"].(string))
	if len(scopes) != 4 {
		t.Errorf("scopes = %v", scopes)
	}
	for _, s := range scopes {
		if !strings.HasPrefix(s, "https://www.googleapis.com/auth/admin.directory.") || !strings.HasSuffix(s, ".readonly") {
			t.Errorf("scope %q is not a read-only Directory scope", s)
		}
	}
	// the assertion and the key never reach the API requests
	for _, form := range f.forms {
		if strings.Contains(form.Get("assertion"), "PRIVATE KEY") {
			t.Error("the assertion carries a key")
		}
	}
}

func TestScopesFollowConfiguration(t *testing.T) {
	f := newFake(t)
	cfg := baseCfg(t)
	cfg.Groups, cfg.Roles = false, false
	res, err := f.connector(cfg).Discover(context.Background())
	if err != nil || len(res.Groups) != 0 || len(res.Edges) != 0 || len(res.Accounts) != 3 {
		t.Fatalf("Discover = %+v, %v", res, err)
	}
	if got := strings.Fields(f.claims[0]["scope"].(string)); len(got) != 1 || got[0] != ScopeUsers {
		t.Errorf("scopes = %v, want only the users scope", got)
	}
	if f.srv.Count(dirPrefix+"/groups") != 0 || f.srv.Count(dirPrefix+"/customer") != 0 {
		t.Error("groups or roles were read although turned off")
	}
}

func TestDegradedScopes(t *testing.T) {
	t.Run("groups forbidden", func(t *testing.T) {
		f := newFake(t)
		f.status[dirPrefix+"/groups"] = 403
		res, err := f.connector(baseCfg(t)).Discover(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		g := groupMap(res)
		if _, ok := g[gEng]; ok || len(res.Accounts) != 3 || !g["role:"+roleSup].Privileged {
			t.Errorf("groups = %v, accounts = %d", g, len(res.Accounts))
		}
		if n := len(edgeSet(res)); n != 2 { // role edges to users remain; the group-held role needs the group
			t.Errorf("edges = %d: %v", n, edgeSet(res))
		}
	})
	t.Run("roles forbidden", func(t *testing.T) {
		f := newFake(t)
		f.status[dirPrefix+"/customer"] = 403
		res, err := f.connector(baseCfg(t)).Discover(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for id := range groupMap(res) {
			if strings.HasPrefix(id, "role:") {
				t.Errorf("role %s without the roles scope", id)
			}
		}
		if len(res.Groups) != 3 || len(res.Edges) != 5 {
			t.Errorf("groups = %d, edges = %d", len(res.Groups), len(res.Edges))
		}
	})
	t.Run("members of one group forbidden or gone", func(t *testing.T) {
		f := newFake(t)
		f.status[dirPrefix+"/groups/"+gFin] = 403
		f.status[dirPrefix+"/groups/"+gPlat] = 404
		res, err := f.connector(baseCfg(t)).Discover(context.Background())
		if err != nil || len(res.Groups) != 6 {
			t.Fatalf("Discover = %v, %v", res, err)
		}
		if edgeSet(res)["account:"+cy+"->group:"+gFin+" member_of"] {
			t.Error("edge from a group that could not be read")
		}
	})
	t.Run("users forbidden is an error", func(t *testing.T) {
		f := newFake(t)
		f.status[dirPrefix+"/users"] = 403
		_, err := f.connector(baseCfg(t)).Discover(context.Background())
		if connsync.Status(err) != 403 || strings.Contains(err.Error(), "leaky-body") {
			t.Errorf("err = %v", err)
		}
	})
}

func TestThrottling(t *testing.T) {
	f := newFake(t)
	f.retry429[dirPrefix+"/users"] = 2
	f.retryRate[dirPrefix+"/groups"] = 2 // 403 rateLimitExceeded is a throttle, not a refusal
	f.retryRate[dirPrefix+"/groups/"+gEng+"/members"] = 1
	c := f.connector(baseCfg(t))
	ns := &connsynctest.NoSleep{}
	c.api.Backoff = connsync.Backoff{Base: time.Millisecond, Max: 10 * time.Second, Sleep: ns.Sleep}
	res, err := c.Discover(context.Background())
	if err != nil || len(res.Accounts) != 3 || len(res.Groups) != 6 {
		t.Fatalf("Discover = %v, %v", res, err)
	}
	if len(ns.Waits) != 5 {
		t.Fatalf("waits = %v, want 5", ns.Waits)
	}
	if ns.Waits[0] != 4*time.Second || ns.Waits[1] != 4*time.Second {
		t.Errorf("429 waits = %v, want the Retry-After of 4s", ns.Waits[:2])
	}
	if ns.Waits[2] != time.Millisecond || ns.Waits[3] != 2*time.Millisecond {
		t.Errorf("403 rate-limit waits = %v, want exponential back-off", ns.Waits[2:4])
	}
	// a permanent throttle fails and names nothing from the body
	f2 := newFake(t)
	f2.status[dirPrefix+"/users"] = 403
	f2.statusBody[dirPrefix+"/users"] = `{"error":{"code":403,"message":"leaky-body","errors":[{"reason":"userRateLimitExceeded"}]}}`
	_, err = f2.connector(baseCfg(t)).Discover(context.Background())
	if !errors.Is(err, connsync.ErrRateLimited) || strings.Contains(err.Error(), "leaky-body") {
		t.Errorf("err = %v", err)
	}
	// a plain 429 that never clears
	f3 := newFake(t)
	f3.status[dirPrefix+"/users"] = 429
	if _, err = f3.connector(baseCfg(t)).Discover(context.Background()); !errors.Is(err, connsync.ErrRateLimited) {
		t.Errorf("err = %v", err)
	}
}

func TestMalformedAndOversizedPages(t *testing.T) {
	for name, body := range map[string]string{
		"array instead of object": `[]`,
		"truncated":               `{"users":[{"id":`,
		"users of the wrong type": `{"users":"nope"}`,
		"trailing garbage":        `{"users":[]} {}`,
		"empty":                   ``,
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			f.body[dirPrefix+"/users"] = body
			if _, err := f.connector(baseCfg(t)).Discover(context.Background()); !errors.Is(err, connsync.ErrMalformed) {
				t.Errorf("err = %v, want ErrMalformed", err)
			}
		})
	}
	t.Run("malformed members page", func(t *testing.T) {
		f := newFake(t)
		f.body[dirPrefix+"/groups/"+gFin+"/members"] = `{"members":{"id":1}}`
		if _, err := f.connector(baseCfg(t)).Discover(context.Background()); !errors.Is(err, connsync.ErrMalformed) {
			t.Errorf("err = %v, want ErrMalformed", err)
		}
	})
	t.Run("oversized", func(t *testing.T) {
		f := newFake(t)
		f.body[dirPrefix+"/users"] = `{"users":[{"id":"1","primaryEmail":"` + strings.Repeat("x", 8192) + `@example.com"}]}`
		cfg := baseCfg(t)
		cfg.APIURL, cfg.TokenURL = f.srv.URL, f.srv.URL+"/token"
		c, err := New(cfg, connsynctest.Runtime, testClient(t, f.srv, 2048), func() time.Time { return now0 })
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Discover(context.Background()); !errors.Is(err, safehttp.ErrTooLarge) {
			t.Errorf("err = %v, want ErrTooLarge", err)
		}
	})
	t.Run("endless token loop", func(t *testing.T) {
		f := newFake(t)
		f.body[dirPrefix+"/users"] = `{"users":[],"nextPageToken":"same"}`
		if _, err := f.connector(baseCfg(t)).Discover(context.Background()); !errors.Is(err, connsync.ErrPaging) {
			t.Errorf("err = %v, want ErrPaging", err)
		}
	})
	t.Run("page token that is far too long", func(t *testing.T) {
		f := newFake(t)
		f.body[dirPrefix+"/users"] = `{"users":[],"nextPageToken":"` + strings.Repeat("t", maxPageToken+1) + `"}`
		if _, err := f.connector(baseCfg(t)).Discover(context.Background()); !errors.Is(err, connsync.ErrMalformed) {
			t.Errorf("err = %v, want ErrMalformed", err)
		}
	})
}

// Google pages by token, not by link. A token that looks like a URL is only
// ever a query value on the configured host.
func TestPageTokenCannotLeaveTheHost(t *testing.T) {
	f := newFake(t)
	var seen []string
	f.override = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			f.token(w, r)
			return
		}
		seen = append(seen, r.URL.Query().Get("pageToken"))
		if r.URL.Query().Get("pageToken") == "" {
			fmt.Fprint(w, `{"users":[],"nextPageToken":"https://evil.example.net/admin/directory/v1/users?x=1"}`)
			return
		}
		fmt.Fprint(w, `{"users":[]}`)
	}
	cfg := baseCfg(t)
	cfg.Groups, cfg.Roles = false, false
	if _, err := f.connector(cfg).Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[1] != "https://evil.example.net/admin/directory/v1/users?x=1" {
		t.Errorf("page tokens seen = %v", seen)
	}
	for _, r := range f.srv.Requests() {
		if !strings.HasPrefix(r.Path, "/admin/directory/v1/users") && r.Path != "/token" {
			t.Errorf("request to %s", r.Path)
		}
	}
}

// ---------------------------------------------------------------- incremental

func TestIncrementalSyncRereadsOnlyChangedGroups(t *testing.T) {
	f := newFake(t)
	ms := &connsync.MemoryStore{}
	ctx := connsync.WithStore(context.Background(), ms)
	c := f.connector(baseCfg(t))
	first, err := c.Discover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cp, _ := ms.Load(ctx, System, checkpointName)
	if cp == nil || cp.FullSyncAt == nil || len(cp.State) == 0 || cp.Cursor != now0.Add(-watermarkOverlap).Format(time.RFC3339) {
		t.Fatalf("checkpoint = %+v", cp)
	}
	if n := f.members(); n != 4 { // eng twice (two pages), plat, fin
		t.Fatalf("member requests after the full read = %d, want 4", n)
	}

	// nothing changed: the listings are read again, no member list is
	second, err := c.Discover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n := f.members(); n != 4 {
		t.Errorf("member requests after an unchanged sync = %d, want still 4", n)
	}
	if len(edgeSet(second)) != len(edgeSet(first)) || len(second.Accounts) != 3 {
		t.Errorf("the incremental snapshot differs: edges %d vs %d", len(edgeSet(second)), len(edgeSet(first)))
	}
	if f.srv.Count(dirPrefix+"/users") != 4 {
		t.Errorf("user pages = %d, want the users read in full both times", f.srv.Count(dirPrefix+"/users"))
	}

	// Engineering changed (etag and count): only its members are read again
	f.changed = true
	third, err := c.Discover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n := f.members(); n != 5 {
		t.Errorf("member requests after one changed group = %d, want 5", n)
	}
	e := edgeSet(third)
	if e["account:"+ben+"->group:"+gEng+" member_of"] || !e["account:"+cy+"->group:"+gEng+" member_of"] || !e["group:"+gEng+"->group:"+gPlat+" member_of"] {
		t.Errorf("edges after the change = %v", e)
	}
	cp2, _ := ms.Load(ctx, System, checkpointName)
	if cp2.FullSyncAt == nil || !cp2.FullSyncAt.Equal(*cp.FullSyncAt) {
		t.Errorf("FullSyncAt moved on an incremental sync: %v -> %v", cp.FullSyncAt, cp2.FullSyncAt)
	}
}

func TestInvalidOrExpiredCheckpointsFallBackToFullRead(t *testing.T) {
	good := func(t *testing.T, f *fake, ms *connsync.MemoryStore) context.Context {
		ctx := connsync.WithStore(context.Background(), ms)
		if _, err := f.connector(baseCfg(t)).Discover(ctx); err != nil {
			t.Fatal(err)
		}
		return ctx
	}
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
		"state is another version":  func(cp *connsync.Checkpoint) { cp.State = blob(&state{Version: 99, Groups: map[string]*groupState{}}) },
		"state has no group map":    func(cp *connsync.Checkpoint) { cp.State = blob(&state{Version: stateVersion}) },
		"cursor is empty":           func(cp *connsync.Checkpoint) { cp.Cursor = "" },
		"last full read is too old": func(cp *connsync.Checkpoint) { old := now0.Add(-48 * time.Hour); cp.FullSyncAt = &old },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			ms := &connsync.MemoryStore{}
			ctx := good(t, f, ms)
			cp, _ := ms.Load(ctx, System, checkpointName)
			mod(cp)
			_ = ms.Save(ctx, System, checkpointName, cp)
			before := f.members()
			cfg := baseCfg(t)
			cfg.MaxIncrementalAge = 24 * time.Hour
			res, err := f.connector(cfg).Discover(ctx)
			if err != nil || len(res.Accounts) != 3 {
				t.Fatalf("Discover = %v, %v", res, err)
			}
			if f.members()-before != 4 {
				t.Errorf("member requests = %d, want a full read (4)", f.members()-before)
			}
			if cp2, _ := ms.Load(ctx, System, checkpointName); cp2 == nil || cp2.FullSyncAt == nil || !cp2.FullSyncAt.Equal(now0) {
				t.Errorf("the repaired checkpoint = %+v", cp2)
			}
		})
	}
}

func TestFullResyncOnDemand(t *testing.T) {
	f := newFake(t)
	ms := &connsync.MemoryStore{}
	ctx := connsync.WithStore(context.Background(), ms)
	c := f.connector(baseCfg(t))
	if _, err := c.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	before := f.members()
	if _, err := c.Discover(connsync.WithMode(ctx, connsync.Full)); err != nil {
		t.Fatal(err)
	}
	if f.members()-before != 4 {
		t.Errorf("a requested full re-sync made %d member requests, want 4", f.members()-before)
	}
}

func TestNoStoreMeansAlwaysFull(t *testing.T) {
	f := newFake(t)
	c := f.connector(baseCfg(t))
	for i := 0; i < 2; i++ {
		if _, err := c.Discover(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.members(); n != 8 {
		t.Errorf("member requests = %d, want 8", n)
	}
}

func TestStreamEventsYieldsNothing(t *testing.T) {
	f := newFake(t)
	err := f.connector(baseCfg(t)).StreamEvents(context.Background(), nil, func(connectors.Event) error {
		t.Error("an event was yielded")
		return nil
	})
	if err != nil || len(f.srv.Requests()) != 0 {
		t.Errorf("err = %v, requests = %d", err, len(f.srv.Requests()))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.connector(baseCfg(t)).StreamEvents(ctx, nil, nil); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
}

// ---------------------------------------------------------------- credentials

func TestTokenFailureDoesNotLeakKeyOrBody(t *testing.T) {
	f := newFake(t)
	f.status["/token"] = 400
	f.statusBody["/token"] = `{"error":"invalid_grant","error_description":"Invalid email or User ID: admin@example.com PRIVATE KEY"}`
	cfg := baseCfg(t)
	_, err := f.connector(cfg).Discover(context.Background())
	if connsync.Status(err) != 400 || !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("err = %v", err)
	}
	for _, leak := range []string{"Invalid email", "PRIVATE KEY", "BEGIN", adminEm, strings.Fields(cfg.PrivateKey.Reveal())[3]} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error %q leaks %q", err, leak)
		}
	}
	if strings.Contains(fmt.Sprintf("%v %+v %#v", cfg, cfg, cfg), "BEGIN") {
		t.Error("the config prints the key")
	}
}

func TestExpiredTokenIsRefreshedOnce(t *testing.T) {
	f := newFake(t)
	calls := 0
	f.override = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			f.token(w, r)
			return
		}
		if calls++; calls == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":{"code":401,"message":"Invalid Credentials"}}`)
			return
		}
		fmt.Fprint(w, `{"users":[]}`)
	}
	cfg := baseCfg(t)
	cfg.Groups, cfg.Roles = false, false
	if _, err := f.connector(cfg).Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.claims) != 2 {
		t.Errorf("token requests = %d, want 2 (one refresh after the 401)", len(f.claims))
	}
}

func TestParseServiceAccountKey(t *testing.T) {
	pemKey := keyPEM(t)
	js := func(m map[string]string) string { b, _ := json.Marshal(m); return string(b) }
	email, key, kid, err := parseServiceAccountKey(js(map[string]string{"type": "service_account", "client_email": saEmail,
		"private_key": pemKey, "private_key_id": "kid-1", "token_uri": "https://evil.example.net/token"}))
	if err != nil || email != saEmail || key.Reveal() != pemKey || kid != "kid-1" {
		t.Fatalf("parse = %q %v %q, %v", email, key, kid, err)
	}
	for name, raw := range map[string]string{
		"not json":      "-----BEGIN PRIVATE KEY-----",
		"wrong type":    js(map[string]string{"type": "authorized_user", "client_email": saEmail, "private_key": pemKey}),
		"no key":        js(map[string]string{"type": "service_account", "client_email": saEmail}),
		"no email":      js(map[string]string{"type": "service_account", "private_key": pemKey}),
		"empty":         "",
		"array of keys": "[]",
	} {
		_, _, _, err := parseServiceAccountKey(raw)
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "BEGIN") {
			t.Errorf("%s: error echoes the key: %v", name, err)
		}
	}
}

func TestParseKey(t *testing.T) {
	if _, err := parseKey(keyPEM(t)); err != nil {
		t.Fatal(err)
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	pkcs1 := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(signingKey(t))}))
	if _, err := parseKey(pkcs1); err != nil {
		t.Errorf("PKCS#1: %v", err)
	}
	for name, p := range map[string]string{
		"not pem":   "nope",
		"too short": string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(small)})),
		"wrong pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")})),
		"bad der":   string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")})),
	} {
		if _, err := parseKey(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// ---------------------------------------------------------------- configuration

func TestNewValidatesConfiguration(t *testing.T) {
	prod := prodRT
	hc := prodClient(t)
	ok := baseCfg(t)
	with := func(mod func(*Config)) Config { c := ok; mod(&c); return c }
	tests := []struct {
		name string
		cfg  Config
		good bool
	}{
		{"defaults", ok, true},
		{"customer id", with(func(c *Config) { c.Customer = "C01a2b3c4" }), true},
		{"domain", with(func(c *Config) { c.Domain = "example.com" }), true},
		{"no service account", with(func(c *Config) { c.ServiceAccountEmail = "" }), false},
		{"service account is not an e-mail", with(func(c *Config) { c.ServiceAccountEmail = "tessera" }), false},
		{"no admin to impersonate", with(func(c *Config) { c.AdminEmail = "" }), false},
		{"admin with a header injection", with(func(c *Config) { c.AdminEmail = "a@example.com\r\nX: y" }), false},
		{"no key", with(func(c *Config) { c.PrivateKey = connsync.Secret{} }), false},
		{"key is not PEM", with(func(c *Config) { c.PrivateKey = connsync.NewSecret("nope") }), false},
		{"customer with a path", with(func(c *Config) { c.Customer = "../x" }), false},
		{"domain is an IP", with(func(c *Config) { c.Domain = "10.0.0.1" }), false},
		{"http api", with(func(c *Config) { c.APIURL = "http://admin.googleapis.com" }), false},
		{"http token url", with(func(c *Config) { c.TokenURL = "http://oauth2.googleapis.com/token" }), false},
		{"private api", with(func(c *Config) { c.APIURL = "https://10.0.0.5" }), false},
		{"loopback token url in prod", with(func(c *Config) { c.TokenURL = "https://127.0.0.1:9/token" }), false},
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
	keyJSON, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": saEmail, "private_key": keyPEM(t), "private_key_id": "k1"})
	good := map[string]string{"TESSERA_ENV": "prod", "TESSERA_GOOGLE_SERVICE_ACCOUNT_KEY": "env:GOOGLE_SA_KEY", "GOOGLE_SA_KEY": string(keyJSON),
		"TESSERA_GOOGLE_ADMIN_EMAIL": adminEm}
	c, err := FromEnv(env(good), now0, prodRT, prodClient(t))
	if err != nil || c.System() != "google" || c.TypeName() != "GoogleConnector" || c.DisplayName() != "Google Workspace" {
		t.Fatalf("FromEnv = %v, %v", c, err)
	}
	cfg := c.(*Connector).cfg
	if !cfg.EmitIdentities || !cfg.Groups || !cfg.Roles || cfg.APIURL != DefaultAPIURL || cfg.TokenURL != DefaultTokenURL ||
		cfg.Customer != "my_customer" || cfg.MaxIncrementalAge != 24*time.Hour || cfg.KeyID != "k1" || cfg.ServiceAccountEmail != saEmail {
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
		"literal key":      mod("TESSERA_GOOGLE_SERVICE_ACCOUNT_KEY", string(keyJSON)),
		"unset key":        mod("TESSERA_GOOGLE_SERVICE_ACCOUNT_KEY", ""),
		"missing env":      mod("TESSERA_GOOGLE_SERVICE_ACCOUNT_KEY", "env:NOPE"),
		"key is not json":  mod("GOOGLE_SA_KEY", "just-a-secret"),
		"no admin":         mod("TESSERA_GOOGLE_ADMIN_EMAIL", ""),
		"bad bool":         mod("TESSERA_GOOGLE_ROLES", "sometimes"),
		"bad age":          mod("TESSERA_GOOGLE_MAX_INCREMENTAL_AGE", "1s"),
		"negative age":     mod("TESSERA_GOOGLE_MAX_INCREMENTAL_AGE", "-1h"),
		"bad customer":     mod("TESSERA_GOOGLE_CUSTOMER", "acme"),
		"http api":         mod("TESSERA_GOOGLE_API_URL", "http://admin.googleapis.com"),
		"loopback in prod": mod("TESSERA_OUTBOUND_ALLOW_LOOPBACK", "true"),
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
		} else if strings.Contains(err.Error(), "just-a-secret") || strings.Contains(err.Error(), "PRIVATE KEY") {
			t.Errorf("%s: error echoes the credential: %v", name, err)
		}
	}
	off := mod("TESSERA_GOOGLE_GROUPS", "false")
	off["TESSERA_GOOGLE_ROLES"] = "false"
	off["TESSERA_GOOGLE_EMIT_IDENTITIES"] = "false"
	off["TESSERA_GOOGLE_MAX_INCREMENTAL_AGE"] = "0"
	off["TESSERA_GOOGLE_DOMAIN"] = "example.com"
	c, err = FromEnv(env(off), now0, prodRT, prodClient(t))
	if err != nil {
		t.Fatal(err)
	}
	if g := c.(*Connector).cfg; g.Groups || g.Roles || g.EmitIdentities || g.MaxIncrementalAge != 0 || g.Domain != "example.com" {
		t.Errorf("FromEnv(off) = %+v", g)
	}
}

func TestReaderRoleAndScopes(t *testing.T) {
	for n, want := range map[string]bool{"Groups Reader": true, "_GROUPS_READER_ROLE": true, "Billing Readers": true,
		"_SEED_ADMIN_ROLE": false, "Help Desk Admin": false, "Reader Of Things Admin": false, "": false} {
		if readerRole(n) != want {
			t.Errorf("readerRole(%q) = %v", n, !want)
		}
	}
	for _, s := range (Config{Groups: true, Roles: true}).Scopes() {
		if !strings.HasSuffix(s, ".readonly") {
			t.Errorf("scope %s is not read-only", s)
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
