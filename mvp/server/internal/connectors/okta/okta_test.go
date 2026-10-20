package okta

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
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
	avery   = "00u1averyexample01"
	morgan  = "00u1morganexample2"
	casey   = "00u1caseyexample03"
	drew    = "00u1drewexample004"
	engGrp  = "00g1engineers0001"
	admGrp  = "00g1admins0000002"
	wikiApp = "0oa1wiki000000001"

	// edge endpoints as edgeSet prints them: kind ":" external id
	engRef = "group:group:" + engGrp
	admRef = "group:group:" + admGrp
)

// fake replays the recorded fixtures as an Okta org.
type fake struct {
	t   *testing.T
	srv *connsynctest.Server

	mu         sync.Mutex
	changed    bool           // serve the "changed since" fixtures for lastUpdated searches
	userStatus map[int]int    // call number -> forced status for GET /api/v1/users (the plain list)
	userCalls  int            // plain user list calls
	status     map[string]int // path prefix -> forced status
	tokenCalls int
	pub        *rsa.PublicKey // verifies client assertions when set
	assertions []map[string]any
	scopes     []string
	body       map[string]string // path -> override body
	override   http.HandlerFunc  // replaces every route when set
}

func newFake(t *testing.T) *fake {
	f := &fake{t: t, userStatus: map[int]int{}, status: map[string]int{}, body: map[string]string{}}
	f.srv = connsynctest.New(t, http.HandlerFunc(f.serve))
	return f
}

func (f *fake) fixture(name string) []byte { return connsynctest.Fixture(f.t, name, f.srv.URL) }

func (f *fake) link(w http.ResponseWriter, next string) {
	w.Header().Add("Link", fmt.Sprintf(`<%s/api/v1/self>; rel="self"`, f.srv.URL))
	w.Header().Add("Link", fmt.Sprintf(`<%s>; rel="next"`, next))
}

func (f *fake) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.override != nil {
		f.override(w, r)
		return
	}
	for p, s := range f.status {
		if strings.HasPrefix(r.URL.Path, p) {
			w.WriteHeader(s)
			fmt.Fprint(w, `{"errorCode":"E0000006","errorSummary":"leaky-body-should-never-surface"}`)
			return
		}
	}
	if b, ok := f.body[r.URL.Path]; ok {
		fmt.Fprint(w, b)
		return
	}
	q := r.URL.Query()
	search := q.Get("search")
	out := func(name string) { _, _ = w.Write(f.fixture(name)) }
	segs := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case r.URL.Path == "/oauth2/v1/token":
		f.tokenCalls++
		f.checkAssertion(r)
		fmt.Fprint(w, `{"token_type":"Bearer","expires_in":3600,"access_token":"tok-oauth-1","scope":"okta.users.read"}`)
	case r.URL.Path == "/api/v1/users":
		switch {
		case strings.Contains(search, "DEPROVISIONED"):
			out("users_deprovisioned.json")
		case strings.HasPrefix(search, "lastUpdated gt"):
			if f.changed {
				out("users_changed.json")
			} else {
				fmt.Fprint(w, `[]`)
			}
		case q.Get("after") == "p2":
			out("users_p2.json")
		default:
			f.userCalls++
			if s, ok := f.userStatus[f.userCalls]; ok {
				if s == 429 {
					w.Header().Set("Retry-After", "2")
				}
				w.WriteHeader(s)
				return
			}
			f.link(w, f.srv.URL+"/api/v1/users?limit=200&after=p2")
			out("users_p1.json")
		}
	case r.URL.Path == "/api/v1/groups":
		if strings.HasPrefix(search, "lastUpdated gt") {
			if f.changed {
				out("groups_changed.json")
			} else {
				fmt.Fprint(w, `[]`)
			}
		} else {
			out("groups.json")
		}
	case len(segs) == 5 && segs[2] == "groups" && segs[4] == "users":
		switch segs[3] {
		case engGrp:
			if f.changed {
				out("members_engineers_changed.json")
			} else {
				out("members_engineers.json")
			}
		case admGrp:
			out("members_admins.json")
		default:
			http.NotFound(w, r)
		}
	case len(segs) == 5 && segs[2] == "groups" && segs[4] == "roles":
		if segs[3] == admGrp {
			out("group_roles_admins.json")
		} else {
			fmt.Fprint(w, `[]`)
		}
	case r.URL.Path == "/api/v1/iam/assignees/users":
		out("assignees.json")
	case len(segs) == 5 && segs[2] == "users" && segs[4] == "roles":
		if segs[3] == avery {
			out("user_roles_avery.json")
		} else {
			fmt.Fprint(w, `[]`)
		}
	case r.URL.Path == "/api/v1/apps":
		out("apps.json")
	case len(segs) == 5 && segs[2] == "apps" && segs[3] == wikiApp && segs[4] == "users":
		out("app_users.json")
	case len(segs) == 5 && segs[2] == "apps" && segs[3] == wikiApp && segs[4] == "groups":
		out("app_groups.json")
	case r.URL.Path == "/api/v1/logs":
		if q.Get("after") == "c2" {
			fmt.Fprint(w, `[]`)
			return
		}
		f.link(w, f.srv.URL+"/api/v1/logs?after=c2")
		out("logs.json")
	default:
		f.t.Errorf("unexpected request %s %s", r.Method, r.URL.String())
		http.NotFound(w, r)
	}
}

// checkAssertion verifies the private_key_jwt client assertion in a token request.
func (f *fake) checkAssertion(r *http.Request) {
	if err := r.ParseForm(); err != nil {
		f.t.Errorf("token form: %v", err)
		return
	}
	if r.Form.Get("grant_type") != "client_credentials" ||
		r.Form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		f.t.Errorf("token request form = %v", r.Form)
	}
	f.scopes = strings.Fields(r.Form.Get("scope"))
	if r.Header.Get("Authorization") != "" {
		f.t.Error("token request carries an Authorization header")
	}
	if f.pub == nil {
		return
	}
	obj, err := jose.ParseSigned(r.Form.Get("client_assertion"), []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		f.t.Errorf("assertion does not parse: %v", err)
		return
	}
	if obj.Signatures[0].Header.KeyID != "kid-1" {
		f.t.Errorf("kid = %q", obj.Signatures[0].Header.KeyID)
	}
	payload, err := obj.Verify(f.pub)
	if err != nil {
		f.t.Errorf("assertion signature: %v", err)
		return
	}
	var claims map[string]any
	if err := connsync.DecodeJSON(payload, &claims); err != nil {
		f.t.Errorf("claims: %v", err)
	}
	f.assertions = append(f.assertions, claims)
}

func (f *fake) connector(cfg Config) *Connector {
	f.t.Helper()
	cfg.OrgURL = f.srv.URL
	c, err := New(cfg, connsynctest.Runtime, testClient(f.t, f.srv, 0), func() time.Time { return now0 })
	if err != nil {
		f.t.Fatal(err)
	}
	c.api.Backoff = connsync.Backoff{Base: time.Millisecond, Max: time.Second, Sleep: (&connsynctest.NoSleep{}).Sleep}
	return c
}

func ssws() Config {
	return Config{APIToken: connsync.NewSecret("ssws-token-xyz"), EmitIdentities: true}
}

func genKey(t *testing.T) (pemKey string, pub *rsa.PublicKey) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), &k.PublicKey
}

// ---------------------------------------------------------------- discovery

func TestDiscoverFull(t *testing.T) {
	f := newFake(t)
	res, err := f.connector(ssws()).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// users: two pages plus the deprovisioned one
	accts := map[string]connectors.AccountRecord{}
	for _, a := range res.Accounts {
		accts[a.ExternalID] = a
	}
	if len(accts) != 4 {
		t.Fatalf("accounts = %d, want 4 (2 pages + deprovisioned)", len(accts))
	}
	a := accts[avery]
	if a.Username != "avery.example@example.com" || a.Kind != "user" || a.Status != "active" ||
		a.LastLoginAt == nil || !a.LastLoginAt.Equal(time.Date(2026, 10, 7, 8, 15, 0, 0, time.UTC)) {
		t.Errorf("avery = %+v", a)
	}
	if a.Identity == nil || a.Identity.ExternalID != "E1001" || a.Identity.Email != "avery.example@example.com" {
		t.Errorf("avery identity ref = %+v", a.Identity)
	}
	if accts[morgan].LastLoginAt != nil || accts[morgan].Identity.ExternalID != "okta:"+morgan {
		t.Errorf("morgan = %+v (no lastLogin, no employeeNumber)", accts[morgan])
	}
	if accts[casey].Status != "disabled" || accts[drew].Status != "disabled" {
		t.Errorf("suspended/deprovisioned status = %q/%q, want disabled", accts[casey].Status, accts[drew].Status)
	}
	if got := accts[avery].Attributes["employeeNumber"]; got != "E1001" {
		t.Errorf("attributes = %v", accts[avery].Attributes)
	}
	// identities: employeeNumber else okta:<id>; the manager reference resolves to morgan's identity
	ids := map[string]connectors.IdentityRecord{}
	for _, i := range res.Identities {
		ids[i.ExternalID] = i
	}
	if len(ids) != 4 || ids["E1001"].Name != "Avery Example" || ids["okta:"+morgan].Name != "Morgan Sample" ||
		ids["E1001"].Manager == nil || ids["E1001"].Manager.ExternalID != "okta:"+morgan || *ids["E1001"].Department != "Engineering" {
		t.Errorf("identities = %+v", ids)
	}
	// groups: two groups plus the two roles in use (ORG_ADMIN on a group, SUPER_ADMIN and READ_ONLY_ADMIN on a user)
	groups := map[string]connectors.GroupRecord{}
	for _, g := range res.Groups {
		groups[g.ExternalID] = g
	}
	for _, want := range []string{"group:" + engGrp, "group:" + admGrp, "role:ORG_ADMIN", "role:SUPER_ADMIN", "role:READ_ONLY_ADMIN"} {
		if _, ok := groups[want]; !ok {
			t.Errorf("missing group %s; have %v", want, keysOf(groups))
		}
	}
	if len(groups) != 5 {
		t.Errorf("groups = %v (the inactive role assignment must not appear)", keysOf(groups))
	}
	if !groups["role:SUPER_ADMIN"].Privileged || !groups["role:ORG_ADMIN"].Privileged || groups["role:READ_ONLY_ADMIN"].Privileged ||
		groups["group:"+engGrp].Privileged || groups["role:SUPER_ADMIN"].Kind != "role" || groups["group:"+engGrp].Kind != "group" {
		t.Errorf("group kinds/privilege wrong: %+v", groups)
	}
	if d := groups["group:"+admGrp].Description; d != nil {
		t.Errorf("null description should be nil, got %q", *d)
	}
	// apps: one valid app; the path-traversal id is dropped
	if len(res.Resources) != 1 || res.Resources[0].ExternalID != "app:"+wikiApp || res.Resources[0].Kind != "app" ||
		len(res.Permissions) != 1 || res.Permissions[0].ExternalID != "app:"+wikiApp+":access" {
		t.Errorf("resources/permissions = %+v / %+v", res.Resources, res.Permissions)
	}
	// edges
	want := map[string]bool{
		"account:" + avery + "->" + engRef + " member_of":                      true,
		"account:" + morgan + "->" + engRef + " member_of":                     true,
		"account:" + casey + "->" + admRef + " member_of":                      true,
		admRef + "->group:role:ORG_ADMIN member_of":                            true,
		"account:" + avery + "->group:role:SUPER_ADMIN member_of":              true,
		"account:" + avery + "->group:role:READ_ONLY_ADMIN member_of":          true,
		"account:" + morgan + "->perm:app:" + wikiApp + ":access direct_grant": true,
		engRef + "->perm:app:" + wikiApp + ":access grants":                    true,
	}
	got := edgeSet(res)
	for e := range want {
		if !got[e] {
			t.Errorf("missing edge %s", e)
		}
	}
	for e := range got {
		if !want[e] {
			t.Errorf("unexpected edge %s (unknown members and GROUP-scope app users must not produce edges)", e)
		}
	}
}

func edgeSet(res *connectors.DiscoveryResult) map[string]bool {
	out := map[string]bool{}
	for _, e := range res.Edges {
		out[fmt.Sprintf("%s:%s->%s:%s %s", e.Src.Kind, e.Src.ExternalID, e.Dst.Kind, e.Dst.ExternalID, e.Relation)] = true
	}
	return out
}

func keysOf[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestEveryRequestIsAuthorizedAndReadOnly(t *testing.T) {
	f := newFake(t)
	c := f.connector(ssws())
	if _, err := c.Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.StreamEvents(context.Background(), nil, func(connectors.Event) error { return nil }); err != nil {
		t.Fatal(err)
	}
	reqs := f.srv.Requests()
	if len(reqs) < 15 {
		t.Fatalf("only %d requests", len(reqs))
	}
	for _, r := range reqs {
		if r.Method != http.MethodGet {
			t.Errorf("%s %s: the connector must only read", r.Method, r.Path)
		}
		if r.Authorization != "SSWS ssws-token-xyz" {
			t.Errorf("%s %s: Authorization = %q", r.Method, r.Path, r.Authorization)
		}
		if strings.Contains(r.Path, "..") {
			t.Errorf("request path %q was built from an unvalidated id", r.Path)
		}
	}
}

func TestDiscoverOAuthPrivateKeyJWT(t *testing.T) {
	f := newFake(t)
	pemKey, pub := genKey(t)
	f.pub = pub
	c := f.connector(Config{ClientID: "0oaclientexample01", PrivateKey: connsync.NewSecret(pemKey), KeyID: "kid-1",
		EmitIdentities: true})
	if _, err := c.Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.tokenCalls != 1 {
		t.Errorf("token endpoint called %d times, want 1 (cached)", f.tokenCalls)
	}
	if len(f.assertions) != 1 {
		t.Fatalf("assertions = %v", f.assertions)
	}
	cl := f.assertions[0]
	if cl["iss"] != "0oaclientexample01" || cl["sub"] != "0oaclientexample01" || cl["aud"] != f.srv.URL+"/oauth2/v1/token" || cl["jti"] == "" {
		t.Errorf("claims = %v", cl)
	}
	if exp, iat := cl["exp"].(float64), cl["iat"].(float64); exp-iat > 300 || exp <= iat {
		t.Errorf("assertion lifetime = %vs, want at most 5 minutes", exp-iat)
	}
	if got := strings.Join(f.scopes, " "); got != strings.Join(DefaultScopes, " ") {
		t.Errorf("scopes = %q", got)
	}
	for _, r := range f.srv.Requests() {
		if r.Path != "/oauth2/v1/token" && r.Authorization != "Bearer tok-oauth-1" {
			t.Errorf("%s: Authorization = %q", r.Path, r.Authorization)
		}
	}
}

func TestOAuthTokenIsRefreshedAfterExpiry(t *testing.T) {
	f := newFake(t)
	pemKey, pub := genKey(t)
	f.pub = pub
	clock := now0
	c := f.connector(Config{ClientID: "0oaclientexample01", PrivateKey: connsync.NewSecret(pemKey), KeyID: "kid-1"})
	c.tok.now = func() time.Time { return clock }
	if _, err := c.tok.authorization(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(30 * time.Minute)
	if _, err := c.tok.authorization(context.Background()); err != nil || f.tokenCalls != 1 {
		t.Fatalf("within lifetime: err=%v calls=%d", err, f.tokenCalls)
	}
	clock = clock.Add(31 * time.Minute) // past expires_in minus the one-minute margin
	if _, err := c.tok.authorization(context.Background()); err != nil || f.tokenCalls != 2 {
		t.Fatalf("after expiry: err=%v calls=%d", err, f.tokenCalls)
	}
}

func TestRateLimitThen429ThenSuccess(t *testing.T) {
	f := newFake(t)
	f.userStatus[1] = 429
	f.userStatus[2] = 503
	c := f.connector(ssws())
	ns := &connsynctest.NoSleep{}
	c.api.Backoff = connsync.Backoff{Base: time.Millisecond, Max: 10 * time.Second, Sleep: ns.Sleep}
	res, err := c.Discover(context.Background())
	if err != nil || len(res.Accounts) != 4 {
		t.Fatalf("Discover = %v accounts, %v", len(res.Accounts), err)
	}
	if len(ns.Waits) != 2 || ns.Waits[0] != 2*time.Second {
		t.Errorf("waits = %v, want Retry-After (2s) then the backoff schedule", ns.Waits)
	}
}

func TestPersistentRateLimitFailsWithoutLeakingTheBody(t *testing.T) {
	f := newFake(t)
	f.status["/api/v1/users"] = 429
	_, err := f.connector(ssws()).Discover(context.Background())
	if !errors.Is(err, connsync.ErrRateLimited) {
		t.Fatalf("err = %v, want ErrRateLimited", err)
	}
	for _, leak := range []string{"leaky-body", "ssws-token-xyz"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error %q leaks %q", err, leak)
		}
	}
}

func TestMalformedAndOversizedPages(t *testing.T) {
	for name, body := range map[string]string{
		"object instead of array": `{"errorCode":"E0000001"}`,
		"truncated":               `[{"id":"00u1averyexample01","status":`,
		"wrong field type":        `[{"id":["x"]}]`,
		"trailing garbage":        `[] []`,
		"empty body":              ``,
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			f.body["/api/v1/users"] = body
			_, err := f.connector(ssws()).Discover(context.Background())
			if !errors.Is(err, connsync.ErrMalformed) {
				t.Errorf("err = %v, want ErrMalformed", err)
			}
		})
	}
	t.Run("oversized", func(t *testing.T) {
		f := newFake(t)
		f.body["/api/v1/users"] = `[{"id":"00u1averyexample01","profile":{"title":"` + strings.Repeat("x", 8192) + `"}}]`
		cfg := ssws()
		cfg.OrgURL = f.srv.URL
		c, err := New(cfg, connsynctest.Runtime, testClient(t, f.srv, 2048), func() time.Time { return now0 })
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Discover(context.Background()); !errors.Is(err, safehttp.ErrTooLarge) {
			t.Errorf("err = %v, want ErrTooLarge", err)
		}
	})
}

func TestNextLinkToAnotherHostIsNotFollowed(t *testing.T) {
	f := newFake(t)
	f.mu.Lock()
	f.override = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<https://evil.example.net/api/v1/users?after=x>; rel="next"`)
		fmt.Fprint(w, `[]`)
	}
	f.mu.Unlock()
	_, err := f.connector(ssws()).Discover(context.Background())
	if err == nil || !strings.Contains(err.Error(), "leaves the configured host") {
		t.Fatalf("err = %v", err)
	}
}

func TestRoleListingForbiddenDegrades(t *testing.T) {
	f := newFake(t)
	f.status["/api/v1/iam/assignees"] = 403
	f.status["/api/v1/groups/"+admGrp+"/roles"] = 403
	res, err := f.connector(ssws()).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range res.Groups {
		if g.Kind == "role" {
			t.Errorf("role %s present although role listing was forbidden", g.ExternalID)
		}
	}
	if len(res.Accounts) != 4 || len(res.Groups) != 2 {
		t.Errorf("accounts/groups = %d/%d", len(res.Accounts), len(res.Groups))
	}
}

func TestBadStatusFromUsersIsAnError(t *testing.T) {
	f := newFake(t)
	f.status["/api/v1/users"] = 401
	_, err := f.connector(ssws()).Discover(context.Background())
	if connsync.Status(err) != 401 {
		t.Fatalf("err = %v, want a 401 status error", err)
	}
}

func TestNoIdentitiesWhenConfiguredOff(t *testing.T) {
	f := newFake(t)
	cfg := ssws()
	cfg.EmitIdentities = false
	res, err := f.connector(cfg).Discover(context.Background())
	if err != nil || len(res.Identities) != 0 || len(res.Accounts) != 4 {
		t.Fatalf("identities = %d accounts = %d err = %v", len(res.Identities), len(res.Accounts), err)
	}
}

// ---------------------------------------------------------------- incremental

func TestIncrementalSyncMergesChanges(t *testing.T) {
	f := newFake(t)
	ms := &connsync.MemoryStore{}
	ctx := connsync.WithStore(context.Background(), ms)
	c := f.connector(ssws())
	if _, err := c.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	cp, _ := ms.Load(ctx, System, checkpointName)
	if cp == nil || cp.FullSyncAt == nil || len(cp.State) == 0 {
		t.Fatalf("checkpoint after full sync = %+v", cp)
	}
	wantCursor := now0.Add(-watermarkSkew).Format(time.RFC3339)
	if cp.Cursor != wantCursor {
		t.Errorf("cursor = %q, want %q (start minus skew)", cp.Cursor, wantCursor)
	}
	fullCalls := f.srv.Count("/api/v1/users")

	// Second sync: avery changed, Engineers lost morgan.
	f.changed = true
	c2 := f.connector(ssws())
	c2.now = func() time.Time { return now0.Add(time.Hour) }
	before := len(f.srv.Requests())
	res, err := c2.Discover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var searches []string
	for _, r := range f.srv.Requests()[before:] {
		if r.Path == "/api/v1/users" || r.Path == "/api/v1/groups" {
			q, _ := url.ParseQuery(r.Query)
			searches = append(searches, q.Get("search"))
			if q.Get("search") == "" {
				t.Errorf("incremental sync made an unfiltered list call: %s?%s", r.Path, r.Query)
			}
		}
	}
	if len(searches) != 2 || !strings.Contains(searches[0], `lastUpdated gt "`+wantCursor+`"`) ||
		!strings.Contains(searches[1], `lastMembershipUpdated gt "`+wantCursor+`"`) {
		t.Errorf("searches = %q", searches)
	}
	if f.srv.Count("/api/v1/users") <= fullCalls {
		t.Error("no user calls on the second sync")
	}
	if len(res.Accounts) != 4 {
		t.Fatalf("accounts = %d, want all 4 (snapshot merged)", len(res.Accounts))
	}
	for _, i := range res.Identities {
		if i.ExternalID == "E1001" && *i.Title != "Principal Engineer" {
			t.Errorf("avery's title = %q, want the changed value", *i.Title)
		}
	}
	got := edgeSet(res)
	if got["account:"+morgan+"->"+engRef+" member_of"] || !got["account:"+avery+"->"+engRef+" member_of"] {
		t.Errorf("Engineers membership not refreshed: %v", got)
	}
	if !got["account:"+casey+"->"+admRef+" member_of"] {
		t.Error("an unchanged group lost its members")
	}
	// the incremental sync did not repeat the full-sync group member calls for unchanged groups
	if n := countPath(f.srv.Requests()[before:], "/api/v1/groups/"+admGrp+"/users"); n != 0 {
		t.Errorf("unchanged group's members were re-read %d times", n)
	}
	cp2, _ := ms.Load(ctx, System, checkpointName)
	if cp2.FullSyncAt == nil || !cp2.FullSyncAt.Equal(*cp.FullSyncAt) {
		t.Errorf("FullSyncAt moved on an incremental sync: %v -> %v", cp.FullSyncAt, cp2.FullSyncAt)
	}
}

func countPath(reqs []connsynctest.Req, path string) int {
	n := 0
	for _, r := range reqs {
		if r.Path == path {
			n++
		}
	}
	return n
}

func TestFullResyncOnDemandAndWhenTooOld(t *testing.T) {
	f := newFake(t)
	ms := &connsync.MemoryStore{}
	ctx := connsync.WithStore(context.Background(), ms)
	c := f.connector(ssws())
	if _, err := c.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	plainUsers := func() int { return countQuery(f.srv.Requests(), "/api/v1/users", "") }
	base := plainUsers()

	// on demand
	if _, err := c.Discover(connsync.WithMode(ctx, connsync.Full)); err != nil {
		t.Fatal(err)
	}
	if plainUsers() != base+1 { // the unfiltered list again (page 1; page 2 has an after cursor)
		t.Errorf("full re-sync on demand did not re-read the users (%d -> %d)", base, plainUsers())
	}
	// stale chain: 25 hours later with a 24h limit
	c.now = func() time.Time { return now0.Add(25 * time.Hour) }
	b2 := plainUsers()
	if _, err := c.Discover(ctx); err != nil || plainUsers() != b2+1 {
		t.Errorf("a chain older than MaxIncrementalAge was not repaired by a full read: %v (%d -> %d)", err, b2, plainUsers())
	}
	cp, _ := ms.Load(ctx, System, checkpointName)
	if cp.FullSyncAt == nil || !cp.FullSyncAt.Equal(now0.Add(25*time.Hour)) {
		t.Errorf("FullSyncAt = %v", cp.FullSyncAt)
	}
}

func countQuery(reqs []connsynctest.Req, path, search string) int {
	n := 0
	for _, r := range reqs {
		q, _ := url.ParseQuery(r.Query)
		if r.Path == path && q.Get("search") == search && q.Get("after") == "" {
			n++
		}
	}
	return n
}

func TestCorruptCheckpointFallsBackToFullRead(t *testing.T) {
	f := newFake(t)
	ms := &connsync.MemoryStore{}
	ctx := connsync.WithStore(context.Background(), ms)
	full := now0
	_ = ms.Save(ctx, System, checkpointName, &connsync.Checkpoint{Cursor: "not-a-time", State: []byte("garbage"), FullSyncAt: &full})
	res, err := f.connector(ssws()).Discover(ctx)
	if err != nil || len(res.Accounts) != 4 {
		t.Fatalf("Discover = %v, %v", len(res.Accounts), err)
	}
	// a bad cursor with a good snapshot is also a full read
	cp, _ := ms.Load(ctx, System, checkpointName)
	cp.Cursor = "yesterday"
	_ = ms.Save(ctx, System, checkpointName, cp)
	if res, err = f.connector(ssws()).Discover(ctx); err != nil || len(res.Accounts) != 4 {
		t.Fatalf("Discover with a bad cursor = %v, %v", len(res.Accounts), err)
	}
}

func TestNoStoreMeansAlwaysFull(t *testing.T) {
	f := newFake(t)
	c := f.connector(ssws())
	for i := 0; i < 2; i++ {
		if res, err := c.Discover(context.Background()); err != nil || len(res.Accounts) != 4 {
			t.Fatalf("run %d = %v, %v", i, len(res.Accounts), err)
		}
	}
	if n := countQuery(f.srv.Requests(), "/api/v1/users", ""); n != 2 {
		t.Errorf("unfiltered user list calls = %d, want 2 (one per run)", n)
	}
}

// ---------------------------------------------------------------- events

func TestStreamEventsAggregatesSignInsPerDay(t *testing.T) {
	f := newFake(t)
	ms := &connsync.MemoryStore{}
	ctx := connsync.WithStore(context.Background(), ms)
	c := f.connector(ssws())
	if _, err := c.Discover(ctx); err != nil { // stores the snapshot that maps actors to identities
		t.Fatal(err)
	}
	var got []*connectors.UsageRecord
	err := c.StreamEvents(ctx, nil, func(e connectors.Event) error { got = append(got, e.(*connectors.UsageRecord)); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("events = %d, want 2 (avery x2 on 5 Oct collapses; morgan's failure is dropped)", len(got))
	}
	a, m := got[0], got[1]
	if a.Identity.ExternalID != "E1001" || a.Count != 2 || !a.Day.Equal(time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)) ||
		a.Permission.ExternalID != "app:"+wikiApp+":access" || a.Account == nil || a.Account.ExternalID != avery {
		t.Errorf("avery usage = %+v", a)
	}
	if m.Identity.ExternalID != "okta:"+morgan || m.Count != 1 {
		t.Errorf("morgan usage = %+v", m)
	}
	// the window starts at since, when given
	var logReq connsynctest.Req
	for _, r := range f.srv.Requests() {
		if r.Path == "/api/v1/logs" {
			logReq = r
			break
		}
	}
	q, _ := url.ParseQuery(logReq.Query)
	if q.Get("since") != now0.Add(-30*24*time.Hour).Format(time.RFC3339) || q.Get("sortOrder") != "ASCENDING" ||
		q.Get("filter") != `eventType eq "user.authentication.sso"` {
		t.Errorf("log query = %v", q)
	}
	since := now0.Add(-48 * time.Hour)
	if err := c.StreamEvents(ctx, &since, func(connectors.Event) error { return nil }); err != nil {
		t.Fatal(err)
	}
	reqs := f.srv.Requests()
	q2, _ := url.ParseQuery(reqs[len(reqs)-2].Query) // the last two calls are the two log pages
	if q2.Get("since") != since.Format(time.RFC3339) {
		t.Errorf("since = %q, want %q", q2.Get("since"), since.Format(time.RFC3339))
	}
}

func TestStreamEventsWithoutLogScopeYieldsNothing(t *testing.T) {
	f := newFake(t)
	f.status["/api/v1/logs"] = 403
	n := 0
	if err := f.connector(ssws()).StreamEvents(context.Background(), nil, func(connectors.Event) error { n++; return nil }); err != nil || n != 0 {
		t.Fatalf("err = %v, events = %d", err, n)
	}
}

func TestStreamEventsStopsWhenYieldFails(t *testing.T) {
	f := newFake(t)
	stop := errors.New("stop")
	err := f.connector(ssws()).StreamEvents(context.Background(), nil, func(connectors.Event) error { return stop })
	if !errors.Is(err, stop) {
		t.Fatalf("err = %v", err)
	}
}

// ---------------------------------------------------------------- configuration

func TestNewValidatesConfiguration(t *testing.T) {
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	pemKey, _ := genKey(t)
	prod := connsync.Runtime{Env: "prod"}
	tests := []struct {
		name string
		cfg  Config
		ok   bool
	}{
		{"ssws", Config{OrgURL: "https://example.okta.com", APIToken: connsync.NewSecret("t")}, true},
		{"oauth", Config{OrgURL: "https://example.okta.com", ClientID: "0oa1", PrivateKey: connsync.NewSecret(pemKey)}, true},
		{"http", Config{OrgURL: "http://example.okta.com", APIToken: connsync.NewSecret("t")}, false},
		{"private ip", Config{OrgURL: "https://10.0.0.1", APIToken: connsync.NewSecret("t")}, false},
		{"localhost in prod", Config{OrgURL: "https://localhost", APIToken: connsync.NewSecret("t")}, false},
		{"path", Config{OrgURL: "https://example.okta.com/oauth2/default", APIToken: connsync.NewSecret("t")}, false},
		{"no credential", Config{OrgURL: "https://example.okta.com"}, false},
		{"both", Config{OrgURL: "https://example.okta.com", APIToken: connsync.NewSecret("t"), ClientID: "0oa1", PrivateKey: connsync.NewSecret(pemKey)}, false},
		{"oauth without key", Config{OrgURL: "https://example.okta.com", ClientID: "0oa1"}, false},
		{"oauth without client", Config{OrgURL: "https://example.okta.com", PrivateKey: connsync.NewSecret(pemKey)}, false},
		{"garbage key", Config{OrgURL: "https://example.okta.com", ClientID: "0oa1", PrivateKey: connsync.NewSecret("not a key")}, false},
	}
	for _, tc := range tests {
		_, err := New(tc.cfg, prod, hc, nil)
		if (err == nil) != tc.ok {
			t.Errorf("%s: New = %v, want ok=%v", tc.name, err, tc.ok)
		}
		if err != nil && strings.Contains(err.Error(), "BEGIN") {
			t.Errorf("%s: error quotes key material", tc.name)
		}
	}
	if _, err := New(Config{OrgURL: "https://example.okta.com", APIToken: connsync.NewSecret("t")}, prod, nil, nil); err == nil {
		t.Error("New accepted a nil HTTP client")
	}
}

func TestFromEnv(t *testing.T) {
	pemKey, _ := genKey(t)
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	good := map[string]string{"TESSERA_OKTA_ORG_URL": "https://example.okta.com", "TESSERA_OKTA_API_TOKEN": "env:OKTA_TOKEN",
		"OKTA_TOKEN": "tok", "TESSERA_ENV": "prod"}
	c, err := FromEnv(env(good), now0, prodRT, prodClient(t))
	if err != nil || c.System() != "okta" || c.TypeName() != "OktaConnector" || c.DisplayName() != "Okta" {
		t.Fatalf("FromEnv = %v, %v", c, err)
	}
	if !c.(*Connector).cfg.EmitIdentities || c.(*Connector).cfg.MaxIncrementalAge != 24*time.Hour {
		t.Errorf("defaults = %+v", c.(*Connector).cfg)
	}
	oauth := map[string]string{"TESSERA_OKTA_ORG_URL": "https://example.okta.com", "TESSERA_OKTA_CLIENT_ID": "0oa1",
		"TESSERA_OKTA_PRIVATE_KEY": "env:KEY", "KEY": pemKey, "TESSERA_OKTA_KEY_ID": "k", "TESSERA_OKTA_EMIT_IDENTITIES": "false",
		"TESSERA_OKTA_MAX_INCREMENTAL_AGE": "6h", "TESSERA_ENV": "prod"}
	c, err = FromEnv(env(oauth), now0, prodRT, prodClient(t))
	if err != nil || c.(*Connector).cfg.EmitIdentities || c.(*Connector).cfg.MaxIncrementalAge != 6*time.Hour || c.(*Connector).tok == nil {
		t.Fatalf("oauth FromEnv = %v, %v", c, err)
	}
	for name, mod := range map[string]map[string]string{
		"unset url":        {"TESSERA_OKTA_API_TOKEN": "env:OKTA_TOKEN", "OKTA_TOKEN": "tok"},
		"literal token":    {"TESSERA_OKTA_ORG_URL": "https://example.okta.com", "TESSERA_OKTA_API_TOKEN": "literal-token"},
		"missing env":      {"TESSERA_OKTA_ORG_URL": "https://example.okta.com", "TESSERA_OKTA_API_TOKEN": "env:NOPE"},
		"bad bool":         {"TESSERA_OKTA_ORG_URL": "https://example.okta.com", "TESSERA_OKTA_API_TOKEN": "env:OKTA_TOKEN", "OKTA_TOKEN": "t", "TESSERA_OKTA_EMIT_IDENTITIES": "maybe"},
		"bad age":          {"TESSERA_OKTA_ORG_URL": "https://example.okta.com", "TESSERA_OKTA_API_TOKEN": "env:OKTA_TOKEN", "OKTA_TOKEN": "t", "TESSERA_OKTA_MAX_INCREMENTAL_AGE": "5s"},
		"loopback in prod": {"TESSERA_OKTA_ORG_URL": "https://127.0.0.1", "TESSERA_OKTA_API_TOKEN": "env:OKTA_TOKEN", "OKTA_TOKEN": "t", "TESSERA_OUTBOUND_ALLOW_LOOPBACK": "true", "TESSERA_ENV": "prod"},
	} {
		m := map[string]string{"TESSERA_ENV": "prod"}
		for k, v := range mod {
			m[k] = v
		}
		if _, err := FromEnv(env(m), now0, prodRT, prodClient(t)); err == nil {
			t.Errorf("%s: FromEnv succeeded", name)
		} else if strings.Contains(err.Error(), "literal-token") {
			t.Errorf("%s: error echoes the literal credential: %v", name, err)
		}
	}
}

func TestTokenFailureDoesNotLeakCredentials(t *testing.T) {
	f := newFake(t)
	pemKey, _ := genKey(t)
	f.status["/oauth2/v1/token"] = 401
	c := f.connector(Config{ClientID: "0oaclientexample01", PrivateKey: connsync.NewSecret(pemKey), KeyID: "kid-1"})
	_, err := c.Discover(context.Background())
	if connsync.Status(err) != 401 {
		t.Fatalf("err = %v", err)
	}
	for _, leak := range []string{"BEGIN", "client_assertion", "leaky-body", "eyJ"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error %q leaks %q", err, leak)
		}
	}
}

func TestLinkHeaderParsing(t *testing.T) {
	h := http.Header{}
	h.Add("Link", `<https://example.okta.com/api/v1/users?limit=1>; rel="self"`)
	h.Add("Link", `<https://example.okta.com/api/v1/users?after=a>; rel="next"`)
	if got := nextLink(h); got != "https://example.okta.com/api/v1/users?after=a" {
		t.Errorf("nextLink = %q", got)
	}
	one := http.Header{"Link": {`<https://x.example.com/a>; rel="self", <https://x.example.com/b>; rel="next"`}}
	if got := nextLink(one); got != "https://x.example.com/b" {
		t.Errorf("combined header nextLink = %q", got)
	}
	if nextLink(http.Header{}) != "" || nextLink(http.Header{"Link": {`<x>; rel="prev"`}}) != "" {
		t.Error("nextLink found a next link that is not there")
	}
}

func TestValidID(t *testing.T) {
	for id, ok := range map[string]bool{"00u1averyexample01": true, "a-b_c": true, "": false, "../x": false, "a/b": false,
		"a b": false, "a?b": false, strings.Repeat("a", 65): false} {
		if validID(id) != ok {
			t.Errorf("validID(%q) = %v", id, !ok)
		}
	}
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
