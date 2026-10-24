package restgen

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/restgen/fakerest"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

var devRT = connsync.Runtime{Env: config.Dev, AllowLoopback: true}

func httpClient(t *testing.T) *http.Client {
	t.Helper()
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Dev, AllowLoopback: true, MaxBodyBytes: 8 << 20, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return hc
}

func newFake(t *testing.T, n int) *fakerest.Fake {
	t.Helper()
	f := fakerest.New(n)
	t.Cleanup(f.Close)
	return f
}

var userFieldMap = map[string]string{"id": "$.id", "username": "$.login", "email": "$.email", "display_name": "$.name",
	"status": "$.state", "department": "$.dept", "created_at": "$.created", "last_login_at": "$.last_seen"}

var styles = map[string]*Resource{
	"page":    {Path: "/page/users", ItemsPath: "$.data.users", Pagination: Pagination{Style: PagePage, PageParam: "page", SizeParam: "per_page", PageSize: 10}},
	"offset":  {Path: "/offset/users", Pagination: Pagination{Style: PageOffset, OffsetParam: "offset", SizeParam: "limit", PageSize: 10}},
	"cursor":  {Path: "/cursor/users", ItemsPath: "$.items", Pagination: Pagination{Style: PageCursor, CursorParam: "cursor", NextPath: "$.meta.next"}},
	"link":    {Path: "/link/users", Pagination: Pagination{Style: PageLinkHeader}},
	"nexturl": {Path: "/nexturl/users", ItemsPath: "$.results", Pagination: Pagination{Style: PageNextURL, NextPath: "$.next"}},
}

func usersRes(style string) *Resource {
	r := *styles[style]
	r.Fields = userFieldMap
	return &r
}

func bearerAuth() Auth { return Auth{Type: AuthBearer} }

func baseSpec(f *fakerest.Fake, style string) *Spec {
	return &Spec{BaseURL: f.URL, Auth: bearerAuth(), Users: usersRes(style),
		Limits: Limits{RequestsPerSecond: 100, Burst: 100}}
}

func bearerSecrets() Secrets { s, _ := ParseSecrets(AuthBearer, fakerest.Bearer); return s }

func noSleep(c *Client) *[]time.Duration {
	var slept []time.Duration
	c.Sleep = func(_ context.Context, d time.Duration) error {
		if d > 0 {
			slept = append(slept, d)
		}
		return nil
	}
	return &slept
}

func newSource(t *testing.T, spec *Spec, sec Secrets) (*Source, *[]time.Duration) {
	t.Helper()
	s, err := New(spec, sec, devRT, httpClient(t))
	if err != nil {
		t.Fatal(err)
	}
	return s, noSleep(s.c)
}

func TestCompilePath_Select(t *testing.T) {
	doc := map[string]any{"a": map[string]any{"b": []any{"x", map[string]any{"c": float64(7)}}}, "n": float64(1.5), "k.y": "dotted"}
	tests := []struct {
		path string
		want []string
		bad  bool
	}{
		{path: "$.a.b[0]", want: []string{"x"}},
		{path: "a.b[1].c", want: []string{"7"}},
		{path: "$['k.y']", want: []string{"dotted"}},
		{path: "$.n", want: []string{"1.5"}},
		{path: "$.a.b[*]", want: []string{"x"}}, // the object is not a scalar
		{path: "$.missing.deep", want: nil},
		{path: "$..c", bad: true},
		{path: "$.a[?(@.b)]", bad: true},
		{path: "$.a[0:2]", bad: true},
		{path: "", bad: true},
		{path: "$.a[", bad: true},
	}
	for _, tc := range tests {
		p, err := CompilePath(tc.path)
		if tc.bad {
			if err == nil {
				t.Errorf("%q compiled", tc.path)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", tc.path, err)
			continue
		}
		got := p.Strings(doc)
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("%q = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestParseSpec(t *testing.T) {
	yamlSpec := `
base_url: https://api.example.com/v2
auth: {type: bearer}
users:
  path: /users
  items_path: $.data
  fields: {id: $.id, username: $.login}
`
	s, err := ParseSpec([]byte(yamlSpec))
	if err != nil || s.Users.Path != "/users" || s.Users.Fields["username"] != "$.login" {
		t.Fatalf("yaml: %+v %v", s, err)
	}
	j, err := ParseSpec([]byte(`{"base_url":"https://a.example.com","auth":{"type":"bearer"},"users":{"path":"/u","fields":{"id":"$.id","username":"$.u"}}}`))
	if err != nil || j.BaseURL != "https://a.example.com" {
		t.Fatalf("json: %+v %v", j, err)
	}
	for name, raw := range map[string]string{
		"unknown field":      `{"base_url":"https://a.example.com","auth":{"type":"bearer","token":"hunter2"}}`,
		"password in config": `{"base_url":"https://a.example.com","auth":{"type":"basic","username":"u","password":"p"}}`,
		"typo":               `{"base_url":"https://a.example.com","pagenation":{}}`,
		"empty":              ``,
		"trailing":           `{"base_url":"https://a.example.com"} {}`,
		"not a spec":         `- 1`,
	} {
		if _, err := ParseSpec([]byte(raw)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

func goodSpec() *Spec {
	return &Spec{BaseURL: "https://api.example.com", Auth: Auth{Type: AuthBearer},
		Users: &Resource{Path: "/users", Fields: map[string]string{"id": "$.id", "username": "$.login"}}}
}

func TestValidate(t *testing.T) {
	prod := connsync.Runtime{Env: config.Prod}
	if errs := goodSpec().Validate(prod); len(errs) != 0 {
		t.Fatalf("good spec: %v", errs)
	}
	tests := []struct {
		name  string
		mod   func(s *Spec)
		field string
		rt    connsync.Runtime
	}{
		{"http in prod", func(s *Spec) { s.BaseURL = "http://api.example.com" }, "base_url", prod},
		{"loopback in prod", func(s *Spec) { s.BaseURL = "http://127.0.0.1:9" }, "base_url", prod},
		{"base url with query", func(s *Spec) { s.BaseURL = "https://api.example.com/?x=1" }, "base_url", prod},
		{"no auth type", func(s *Spec) { s.Auth = Auth{} }, "auth.type", prod},
		{"oauth no token url", func(s *Spec) { s.Auth = Auth{Type: AuthOAuth2, ClientID: "c"} }, "auth.token_url", prod},
		{"oauth http token url", func(s *Spec) { s.Auth = Auth{Type: AuthOAuth2, ClientID: "c", TokenURL: "http://idp.example.com/t"} }, "auth.token_url", prod},
		{"oauth no client", func(s *Spec) { s.Auth = Auth{Type: AuthOAuth2, TokenURL: "https://idp.example.com/t"} }, "auth.client_id", prod},
		{"api key no place", func(s *Spec) { s.Auth = Auth{Type: AuthAPIKey, Name: "X-Key"} }, "auth.in", prod},
		{"api key no name", func(s *Spec) { s.Auth = Auth{Type: AuthAPIKey, In: "header"} }, "auth.name", prod},
		{"basic no user", func(s *Spec) { s.Auth = Auth{Type: AuthBasic} }, "auth.username", prod},
		{"auth header in config", func(s *Spec) { s.Headers = map[string]string{"Authorization": "Bearer x"} }, "headers.Authorization", prod},
		{"api key header in config", func(s *Spec) { s.Headers = map[string]string{"X-Api-Key": "x"} }, "headers.X-Api-Key", prod},
		{"nothing configured", func(s *Spec) { s.Users = nil }, "users", prod},
		{"no id mapping", func(s *Spec) { s.Users.Fields = map[string]string{"username": "$.u"} }, "users.fields.id", prod},
		{"no username mapping", func(s *Spec) { s.Users.Fields = map[string]string{"id": "$.id"} }, "users.fields.username", prod},
		{"unknown field", func(s *Spec) { s.Users.Fields["nickname"] = "$.n" }, "users.fields.nickname", prod},
		{"bad jsonpath", func(s *Spec) { s.Users.Fields["email"] = "$..email" }, "users.fields.email", prod},
		{"path traversal", func(s *Spec) { s.Users.Path = "/users/../admin" }, "users.path", prod},
		{"path with query", func(s *Spec) { s.Users.Path = "/users?all=1" }, "users.path", prod},
		{"relative path", func(s *Spec) { s.Users.Path = "users" }, "users.path", prod},
		{"unknown pagination", func(s *Spec) { s.Users.Pagination.Style = "magic" }, "users.pagination.style", prod},
		{"page style missing params", func(s *Spec) { s.Users.Pagination = Pagination{Style: PagePage} }, "users.pagination.page_param", prod},
		{"cursor missing next", func(s *Spec) { s.Users.Pagination = Pagination{Style: PageCursor, CursorParam: "c"} }, "users.pagination.next_path", prod},
		{"groups without users", func(s *Spec) {
			s.Groups = &Resource{Path: "/groups", Fields: map[string]string{"id": "$.id", "name": "$.n"}}
			s.Users = nil
		}, "users", prod},
		{"members need a source", func(s *Spec) {
			s.Groups = &Resource{Path: "/g", Fields: map[string]string{"id": "$.id", "name": "$.n"}, Members: &Members{}}
		}, "groups.members", prod},
		{"members path needs id", func(s *Spec) {
			s.Groups = &Resource{Path: "/g", Fields: map[string]string{"id": "$.id", "name": "$.n"}, Members: &Members{Path: "/g/members"}}
		}, "groups.members.path", prod},
		{"limits too high", func(s *Spec) { s.Limits.MaxAttempts = 50 }, "limits.max_attempts", prod},
		{"write without lookup", func(s *Spec) {
			s.Writes = &Writes{Disable: &Operation{Method: "POST", Path: "/u/{external_id}/disable"}}
		}, "writes.lookup", prod},
		{"write unknown variable", func(s *Spec) {
			s.Writes = &Writes{Lookup: &Operation{Method: "GET", Path: "/u/{username}"}, Delete: &Operation{Method: "DELETE", Path: "/u/{secret}"}}
		}, "writes.delete.path", prod},
		{"write get", func(s *Spec) {
			s.Writes = &Writes{Lookup: &Operation{Method: "GET", Path: "/u/{username}"}, Delete: &Operation{Method: "GET", Path: "/u/{username}"}}
		}, "writes.delete.method", prod},
		{"body variable unknown", func(s *Spec) {
			s.Writes = &Writes{Lookup: &Operation{Method: "GET", Path: "/u/{username}"},
				Create: &Operation{Method: "POST", Path: "/u", Body: json.RawMessage(`{"x":"${nope}"}`)}}
		}, "writes.create.body", prod},
		{"member without is_member", func(s *Spec) {
			s.Writes = &Writes{AddMember: &Operation{Method: "PUT", Path: "/g/{group_id}/m/{external_id}"}}
		}, "writes.is_member", prod},
		{"expect not 2xx", func(s *Spec) {
			s.Writes = &Writes{Lookup: &Operation{Method: "GET", Path: "/u/{username}"}, Delete: &Operation{Method: "DELETE", Path: "/u/{username}", Expect: []int{500}}}
		}, "writes.delete.expect", prod},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := goodSpec()
			tc.mod(s)
			errs := s.Validate(tc.rt)
			for _, e := range errs {
				if e.Field == tc.field && e.Msg != "" {
					return
				}
			}
			t.Fatalf("no error on %s; got %v", tc.field, errs)
		})
	}
	// every problem is reported, not the first
	s := goodSpec()
	s.BaseURL, s.Auth, s.Users.Path = "http://x", Auth{}, "bad"
	if errs := s.Validate(prod); len(errs) < 3 {
		t.Errorf("want every error, got %v", errs)
	}
	// dev allows plain http to loopback
	l := goodSpec()
	l.BaseURL = "http://127.0.0.1:8080"
	if errs := l.Validate(devRT); len(errs) != 0 {
		t.Errorf("dev loopback: %v", errs)
	}
}

func TestExpandPath(t *testing.T) {
	tests := []struct {
		tmpl string
		v    Vars
		want string
		bad  bool
	}{
		{tmpl: "/users/{username}", v: Vars{"username": "alice"}, want: "/users/alice"},
		{tmpl: "/users/{username}", v: Vars{"username": "a/b"}, want: "/users/a%2Fb"},
		{tmpl: "/users/{username}", v: Vars{"username": "a b?x=1#f"}, want: "/users/a%20b%3Fx=1%23f"},
		{tmpl: "/users/{username}", v: Vars{"username": "..%2f"}, want: "/users/..%252f"},
		{tmpl: "/users/{username}", v: Vars{"username": ".."}, bad: true},
		{tmpl: "/users/{username}", v: Vars{"username": "."}, bad: true},
		{tmpl: "/users/{username}", v: Vars{"username": ""}, bad: true},
		{tmpl: "/users/{username}", v: Vars{"username": "a\nb"}, bad: true},
		{tmpl: "/users/{username}", v: Vars{"username": strings.Repeat("a", 300)}, bad: true},
		{tmpl: "/g/{group_id}/m/{external_id}", v: Vars{"group_id": "g1", "external_id": "u 1"}, want: "/g/g1/m/u%201"},
	}
	for _, tc := range tests {
		got, err := expandPath(tc.tmpl, tc.v)
		if tc.bad != (err != nil) || got != tc.want {
			t.Errorf("%q %v = %q, %v", tc.tmpl, tc.v, got, err)
		}
	}
}

func TestExpandBody_BuildsJSONNotStrings(t *testing.T) {
	tmpl := json.RawMessage(`{"userName":"${username}","emails":[{"value":"${email}"}],"name":"${display_name} (ext)","dept":"${attr.dept}","n":3,"on":true}`)
	got, err := expandBody(tmpl, Vars{"username": `a","admin":true,"x":"`, "email": "a@example.com", "display_name": "Al"})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatalf("not JSON: %s", got)
	}
	if m["userName"] != `a","admin":true,"x":"` || m["admin"] != nil {
		t.Errorf("injection through a variable: %s", got)
	}
	if _, ok := m["dept"]; ok {
		t.Errorf("an unset lone variable was kept: %s", got)
	}
	if m["name"] != "Al (ext)" || m["n"].(float64) != 3 || m["on"] != true {
		t.Errorf("body: %s", got)
	}
}

func TestDiscover_PaginationStyles(t *testing.T) {
	for style := range styles {
		t.Run(style, func(t *testing.T) {
			f := newFake(t, 25)
			s, _ := newSource(t, baseSpec(f, style), bearerSecrets())
			res, err := s.Discover(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Accounts) != 25 || len(res.Identities) != 25 || res.Partial != "" {
				t.Fatalf("accounts %d identities %d partial %q", len(res.Accounts), len(res.Identities), res.Partial)
			}
			seen := map[string]bool{}
			disabled := 0
			for _, a := range res.Accounts {
				if seen[a.ExternalID] {
					t.Errorf("duplicate account %s", a.ExternalID)
				}
				seen[a.ExternalID] = true
				if a.Status == "disabled" {
					disabled++
				}
			}
			if disabled != 3 { // u007, u014, u021
				t.Errorf("disabled = %d", disabled)
			}
			a := res.Accounts[0]
			if a.System != "rest" || a.Username != "user001" || a.Kind != "user" || a.CreatedAt == nil || a.LastLoginAt == nil ||
				a.LastLoginAt.Unix() != 1700000001 || a.Attributes["department"] != "eng" || a.Identity.Email != "user001@example.com" {
				t.Errorf("mapped account: %+v", a)
			}
			if got := len(f.APIRequests()); got < 3 {
				t.Errorf("only %d requests: not paginated", got)
			}
		})
	}
}

func TestDiscover_GroupsEntitlementsAndMembership(t *testing.T) {
	f := newFake(t, 5)
	grp := func() *Resource {
		return &Resource{Path: "/groups", ItemsPath: "$.groups", Fields: map[string]string{"id": "$.id", "name": "$.name", "privileged": "$.admin"}}
	}
	inline := grp()
	inline.Members = &Members{IDsPath: "$.member_ids[*]"}
	ent := &Resource{Path: "/roles", ItemsPath: "$.groups", Fields: map[string]string{"id": "$.id", "name": "$.name", "privileged": "$.admin"},
		Members: &Members{IDsPath: "$.member_ids[*]"}}
	endpoint := grp()
	endpoint.Members = &Members{Path: "/groups/{id}/members", ItemsPath: "$.data", IDPath: "$.user.id"}

	for name, groups := range map[string]*Resource{"inline ids": inline, "endpoint per group": endpoint} {
		t.Run(name, func(t *testing.T) {
			spec := baseSpec(f, "offset")
			spec.Groups, spec.Entitlements = groups, ent
			s, _ := newSource(t, spec, bearerSecrets())
			res, err := s.Discover(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Groups) != 3 { // g1, g2, entitlement g2
				t.Fatalf("groups: %+v", res.Groups)
			}
			byID := map[string]connectors.GroupRecord{}
			for _, g := range res.Groups {
				byID[g.ExternalID] = g
			}
			if g := byID["group:g2"]; g.Name != "Admins" || !g.Privileged || g.Kind != "group" {
				t.Errorf("g2: %+v", g)
			}
			if g := byID["group:g1"]; g.Privileged {
				t.Errorf("g1 privileged: %+v", g)
			}
			if g := byID["entitlement:g2"]; g.Kind != "role" || !g.Privileged {
				t.Errorf("entitlement: %+v", g)
			}
			edges := map[string]bool{}
			for _, e := range res.Edges {
				if e.Relation != "member_of" || e.Src.Kind != "account" || e.Dst.Kind != "group" {
					t.Errorf("edge %+v", e)
				}
				edges[e.Src.ExternalID+">"+e.Dst.ExternalID] = true
			}
			for _, want := range []string{"u001>group:g1", "u002>group:g1", "u003>group:g1", "u001>group:g2", "u001>entitlement:g2"} {
				if !edges[want] {
					t.Errorf("missing edge %s in %v", want, edges)
				}
			}
			if len(res.Edges) != 5 {
				t.Errorf("%d edges", len(res.Edges))
			}
		})
	}
}

func TestAuthModes(t *testing.T) {
	oauth := func(clientAuth string) Auth {
		return Auth{Type: AuthOAuth2, ClientID: fakerest.ClientID, ClientAuth: clientAuth, Scopes: []string{"read", "write"}}
	}
	tests := []struct {
		name   string
		fake   string
		auth   Auth
		secret string
		ok     bool
	}{
		{"bearer", "bearer", bearerAuth(), fakerest.Bearer, true},
		{"bearer wrong", "bearer", bearerAuth(), "wrong-token-value", false},
		{"api key header", "api_key_header", Auth{Type: AuthAPIKey, In: "header", Name: "X-Api-Key"}, fakerest.APIKey, true},
		{"api key header with prefix mismatch", "api_key_header", Auth{Type: AuthAPIKey, In: "header", Name: "X-Api-Key", Prefix: "Key "}, fakerest.APIKey, false},
		{"api key query", "api_key_query", Auth{Type: AuthAPIKey, In: "query", Name: "api_key"}, fakerest.APIKey, true},
		{"basic", "basic", Auth{Type: AuthBasic, Username: fakerest.Username}, fakerest.Password, true},
		{"basic wrong", "basic", Auth{Type: AuthBasic, Username: fakerest.Username}, "wrong-password", false},
		{"oauth2 basic client auth", "oauth2", oauth("basic"), fakerest.ClientSecret, true},
		{"oauth2 body client auth", "oauth2", oauth("body"), fakerest.ClientSecret, true},
		{"oauth2 wrong secret", "oauth2", oauth(""), "wrong-client-secret", false},
		{"oauth2 json secrets", "oauth2", oauth(""), `{"client_secret":"` + fakerest.ClientSecret + `"}`, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t, 12)
			f.Auth = tc.fake
			spec := baseSpec(f, "offset")
			spec.Auth = tc.auth
			if tc.auth.Type == AuthOAuth2 {
				spec.Auth.TokenURL = f.URL + "/oauth/token"
			}
			sec, err := ParseSecrets(tc.auth.Type, tc.secret)
			if err != nil {
				t.Fatal(err)
			}
			s, _ := newSource(t, spec, sec)
			res, err := s.Discover(context.Background())
			if !tc.ok {
				if err == nil {
					t.Fatal("a wrong credential was accepted")
				}
				if strings.Contains(err.Error(), tc.secret) {
					t.Errorf("the error leaks the secret: %v", err)
				}
				return
			}
			if err != nil || len(res.Accounts) != 12 {
				t.Fatalf("%v, %d accounts", err, len(res.Accounts))
			}
			if tc.auth.Type == AuthOAuth2 && f.TokenCalls != 1 {
				t.Errorf("token fetched %d times: not cached", f.TokenCalls)
			}
		})
	}
}

func TestOAuth_RefetchesTokenAfter401(t *testing.T) {
	f := newFake(t, 5)
	f.Auth, f.RejectTokenOnce = "oauth2", true
	spec := baseSpec(f, "offset")
	spec.Auth = Auth{Type: AuthOAuth2, ClientID: fakerest.ClientID, TokenURL: f.URL + "/oauth/token"}
	sec, _ := ParseSecrets(AuthOAuth2, fakerest.ClientSecret)
	s, _ := newSource(t, spec, sec)
	res, err := s.Discover(context.Background())
	if err != nil || len(res.Accounts) != 5 {
		t.Fatalf("%v %v", err, res)
	}
	if f.TokenCalls != 2 {
		t.Errorf("token calls = %d, want 2", f.TokenCalls)
	}
}

func TestParseSecrets(t *testing.T) {
	for _, tc := range []struct {
		typ, raw string
		ok       bool
	}{
		{AuthBearer, "tok", true},
		{AuthBearer, `{"token":"t"}`, true},
		{AuthBearer, `{"api_key":"k"}`, false}, // the wrong secret for the type
		{AuthBasic, `{"password":"p","extra":"x"}`, false},
		{AuthOAuth2, "", false},
		{AuthAPIKey, "k", true},
	} {
		if _, err := ParseSecrets(tc.typ, tc.raw); (err == nil) != tc.ok {
			t.Errorf("%s %q: %v", tc.typ, tc.raw, err)
		}
	}
	s, _ := ParseSecrets(AuthBearer, "very-secret")
	if out, _ := json.Marshal(s); strings.Contains(string(out), "very-secret") {
		t.Errorf("secrets marshal in the clear: %s", out)
	}
}

func TestRateLimit_HonoursRetryAfter(t *testing.T) {
	f := newFake(t, 5)
	f.Throttle, f.RetryAfter = 2, "2"
	s, slept := newSource(t, baseSpec(f, "offset"), bearerSecrets())
	res, err := s.Discover(context.Background())
	if err != nil || len(res.Accounts) != 5 {
		t.Fatalf("%v", err)
	}
	var waited time.Duration
	for _, d := range *slept {
		waited += d
	}
	if waited < 4*time.Second {
		t.Errorf("waited %v, want at least 2 x Retry-After", waited)
	}
	st := s.Stats()
	if st.Throttled != 2 || st.Retries != 2 || st.RetryAfterSeconds != 2 {
		t.Errorf("stats %+v", st)
	}
}

func TestRateLimit_TooLongRetryAfterIsNotWaitedFor(t *testing.T) {
	f := newFake(t, 5)
	f.Throttle, f.RetryAfter = 5, "3600"
	s, slept := newSource(t, baseSpec(f, "offset"), bearerSecrets())
	_, err := s.Discover(context.Background())
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 429 || se.RetryAfter != time.Hour {
		t.Fatalf("err = %v", err)
	}
	for _, d := range *slept {
		if d > time.Second {
			t.Errorf("waited %v for a 3600s Retry-After", d)
		}
	}
	if n := len(f.APIRequests()); n != 1 {
		t.Errorf("%d requests: retried against a long Retry-After", n)
	}
}

func TestRetries_AreBounded(t *testing.T) {
	f := newFake(t, 5)
	f.Fail, f.FailStatus = 1000, 503
	spec := baseSpec(f, "offset")
	spec.Limits.MaxAttempts = 3
	s, _ := newSource(t, spec, bearerSecrets())
	_, err := s.Discover(context.Background())
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 503 {
		t.Fatalf("err = %v", err)
	}
	if n := len(f.APIRequests()); n != 3 {
		t.Errorf("%d attempts, want 3", n)
	}
	// a client error is not retried
	f2 := newFake(t, 5)
	f2.Fail, f2.FailStatus = 1000, 400
	s2, _ := newSource(t, baseSpec(f2, "offset"), bearerSecrets())
	if _, err := s2.Discover(context.Background()); err == nil || len(f2.APIRequests()) != 1 {
		t.Errorf("a 400 was retried: %d requests", len(f2.APIRequests()))
	}
}

func TestTokenBucket(t *testing.T) {
	now := time.Unix(1000, 0)
	b := newBucket(2, 2, func() time.Time { return now })
	if w := b.reserve(); w != 0 {
		t.Errorf("first: %v", w)
	}
	if w := b.reserve(); w != 0 {
		t.Errorf("second (burst): %v", w)
	}
	if w := b.reserve(); w != 500*time.Millisecond {
		t.Errorf("third waits %v, want 500ms", w)
	}
	now = now.Add(time.Second)
	if w := b.reserve(); w != 0 {
		t.Errorf("after refill: %v", w)
	}
	b.penalize(10 * time.Second)
	if w := b.reserve(); w < 9*time.Second {
		t.Errorf("after a 429 the bucket waits %v", w)
	}
}

func TestResponseSizeCap(t *testing.T) {
	f := newFake(t, 1)
	f.Huge = 200000
	spec := baseSpec(f, "offset")
	spec.Users.Path = "/huge/users"
	spec.Users.ItemsPath = "$.items"
	spec.Users.Pagination = Pagination{}
	spec.Limits.MaxResponseBytes = 100000
	s, _ := newSource(t, spec, bearerSecrets())
	_, err := s.Discover(context.Background())
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
	if n := len(f.APIRequests()); n != 1 {
		t.Errorf("%d requests: an oversize response was retried", n)
	}
}

func TestPagination_Guards(t *testing.T) {
	t.Run("a cursor that does not advance", func(t *testing.T) {
		f := newFake(t, 30)
		f.StuckCursor = true
		s, _ := newSource(t, baseSpec(f, "cursor"), bearerSecrets())
		_, err := s.Discover(context.Background())
		if err == nil || !strings.Contains(err.Error(), "not advancing") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("max pages marks the result partial", func(t *testing.T) {
		f := newFake(t, 50)
		spec := baseSpec(f, "offset")
		spec.Limits.MaxPages = 2
		s, _ := newSource(t, spec, bearerSecrets())
		res, err := s.Discover(context.Background())
		if err != nil || !strings.Contains(res.Partial, "stopped at a configured limit") || len(res.Accounts) != 20 {
			t.Fatalf("%v partial=%q accounts=%d", err, res.Partial, len(res.Accounts))
		}
	})
	t.Run("max records marks the result partial", func(t *testing.T) {
		f := newFake(t, 50)
		spec := baseSpec(f, "offset")
		spec.Limits.MaxRecords = 15
		s, _ := newSource(t, spec, bearerSecrets())
		res, err := s.Discover(context.Background())
		if err != nil || res.Partial == "" || len(res.Accounts) != 15 {
			t.Fatalf("%v partial=%q accounts=%d", err, res.Partial, len(res.Accounts))
		}
	})
	for _, style := range []string{"link", "nexturl"} {
		t.Run("next link to another host, "+style, func(t *testing.T) {
			var hits atomic.Int32
			evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`[]`))
			}))
			defer evil.Close()
			f := newFake(t, 30)
			f.EvilNext = evil.URL + "/steal"
			s, _ := newSource(t, baseSpec(f, style), bearerSecrets())
			_, err := s.Discover(context.Background())
			if err == nil || !strings.Contains(err.Error(), "another host") {
				t.Fatalf("err = %v", err)
			}
			if hits.Load() != 0 {
				t.Errorf("the credential was sent to another host %d times", hits.Load())
			}
		})
	}
}

func TestDiscover_RecordsWithoutIDAreSkipped(t *testing.T) {
	f := newFake(t, 5)
	spec := baseSpec(f, "offset")
	spec.Users.Fields = map[string]string{"id": "$.nope", "username": "$.login"}
	s, _ := newSource(t, spec, bearerSecrets())
	res, err := s.Discover(context.Background())
	if err != nil || len(res.Accounts) != 0 {
		t.Fatalf("%v %d", err, len(res.Accounts))
	}
}

func writeSpec(f *fakerest.Fake) *Spec {
	spec := baseSpec(f, "offset")
	spec.Groups = &Resource{Path: "/groups", ItemsPath: "$.groups", Fields: map[string]string{"id": "$.id", "name": "$.name"}}
	spec.Writes = &Writes{
		Lookup:       &Operation{Method: "GET", Path: "/users/{username}", RecordPath: "$.user"},
		Create:       &Operation{Method: "POST", Path: "/users", Body: json.RawMessage(`{"login":"${username}","email":"${email}","name":"${display_name}"}`), Expect: []int{201}},
		Update:       &Operation{Method: "PATCH", Path: "/users/{external_id}", Body: json.RawMessage(`{"email":"${attr.email}","dept":"${attr.department}"}`)},
		Disable:      &Operation{Method: "PATCH", Path: "/users/{external_id}", Body: json.RawMessage(`{"state":"suspended"}`)},
		Delete:       &Operation{Method: "DELETE", Path: "/users/{external_id}"},
		AddMember:    &Operation{Method: "PUT", Path: "/groups/{group_id}/members/{external_id}"},
		RemoveMember: &Operation{Method: "DELETE", Path: "/groups/{group_id}/members/{external_id}"},
		IsMember:     &Operation{Method: "GET", Path: "/groups/{group_id}/members/{external_id}"},
	}
	return spec
}

func newTarget(t *testing.T, spec *Spec) (*Target, *[]time.Duration) {
	t.Helper()
	tg, err := NewTarget(spec, bearerSecrets(), devRT, httpClient(t))
	if err != nil {
		t.Fatal(err)
	}
	return tg, noSleep(tg.c)
}

func writes(f *fakerest.Fake) int {
	n := 0
	for _, r := range f.APIRequests() {
		if r.Method != "GET" {
			n++
		}
	}
	return n
}

func TestTarget_ApplyAndVerify(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name  string
		req   target.Request
		setup func(f *fakerest.Fake)
		check func(t *testing.T, f *fakerest.Fake)
	}{
		{"create", target.Request{Kind: target.CreateAccount, Key: "k1", Account: target.Account{Username: "zed", Email: "zed@example.com", DisplayName: "Zed"}}, nil,
			func(t *testing.T, f *fakerest.Fake) {
				if u := f.Users["u004"]; u == nil || u.Login != "zed" || u.Email != "zed@example.com" || u.Name != "Zed" {
					t.Errorf("created: %+v", f.Users)
				}
			}},
		{"update", target.Request{Kind: target.UpdateAccount, Account: target.Account{Username: "user001", Attrs: map[string]string{"email": "new@example.com", "department": "ops"}}}, nil,
			func(t *testing.T, f *fakerest.Fake) {
				if u := f.Users["u001"]; u.Email != "new@example.com" || u.Dept != "ops" {
					t.Errorf("updated: %+v", u)
				}
			}},
		{"disable", target.Request{Kind: target.DisableAccount, Account: target.Account{Username: "user001"}}, nil,
			func(t *testing.T, f *fakerest.Fake) {
				if f.Users["u001"].State != "suspended" {
					t.Error("not disabled")
				}
			}},
		{"delete", target.Request{Kind: target.DeleteAccount, Account: target.Account{Username: "user002"}}, nil,
			func(t *testing.T, f *fakerest.Fake) {
				if f.Users["u002"] != nil {
					t.Error("not deleted")
				}
			}},
		{"add member", target.Request{Kind: target.AddEntitlement, Account: target.Account{Username: "user002"}, Group: target.Group{ExternalID: "g2"}}, nil,
			func(t *testing.T, f *fakerest.Fake) {
				if m := f.Groups["g2"].Members; len(m) != 2 || m[1] != "u002" {
					t.Errorf("members: %v", m)
				}
			}},
		{"remove member", target.Request{Kind: target.RemoveEntitlement, Account: target.Account{Username: "user001"}, Group: target.Group{ExternalID: "g1"}}, nil,
			func(t *testing.T, f *fakerest.Fake) {
				if m := f.Groups["g1"].Members; len(m) != 2 {
					t.Errorf("members: %v", m)
				}
			}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t, 3)
			tg, _ := newTarget(t, writeSpec(f))
			if v, err := tg.Verify(ctx, tc.req); err != nil || v.OK {
				t.Fatalf("verify before the change: %+v %v", v, err)
			}
			if err := tg.Apply(ctx, tc.req); err != nil {
				t.Fatal(err)
			}
			tc.check(t, f)
			if v, err := tg.Verify(ctx, tc.req); err != nil || !v.OK {
				t.Fatalf("verify after: %+v %v", v, err)
			}
			// a repeated request converges without another write
			before := writes(f)
			if err := tg.Apply(ctx, tc.req); err != nil {
				t.Fatalf("repeat: %v", err)
			}
			if writes(f) != before {
				t.Errorf("a repeated %s wrote again", tc.name)
			}
			tc.check(t, f)
		})
	}
}

func TestTarget_IdempotencyKeyAndAuthOnWrites(t *testing.T) {
	f := newFake(t, 3)
	tg, _ := newTarget(t, writeSpec(f))
	if err := tg.Apply(context.Background(), target.Request{Kind: target.CreateAccount, Key: "op-123", Account: target.Account{Username: "zed"}}); err != nil {
		t.Fatal(err)
	}
	var post *fakerest.Req
	for _, r := range f.APIRequests() {
		if r.Method == "POST" {
			r := r
			post = &r
		}
	}
	if post == nil || post.Header.Get("Idempotency-Key") != "op-123" || post.Header.Get("Authorization") != "Bearer "+fakerest.Bearer ||
		post.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("write request: %+v", post)
	}
}

func TestTarget_PathParametersAreEscaped(t *testing.T) {
	f := newFake(t, 3)
	tg, _ := newTarget(t, writeSpec(f))
	// a username that tries to reach another endpoint
	err := tg.Apply(context.Background(), target.Request{Kind: target.DeleteAccount, Account: target.Account{Username: "../groups/g1"}})
	if err != nil {
		t.Fatal(err) // not found: the delete converges
	}
	for _, r := range f.APIRequests() {
		if r.Path != "/users/..%2Fgroups%2Fg1" {
			t.Errorf("the username was not one escaped segment: %q", r.Path)
		}
	}
	if err := tg.Apply(context.Background(), target.Request{Kind: target.DeleteAccount, Account: target.Account{Username: ".."}}); err == nil || target.Retryable(err) {
		t.Errorf("a .. segment: %v", err)
	}
}

func TestTarget_Errors(t *testing.T) {
	ctx := context.Background()
	f := newFake(t, 3)
	spec := writeSpec(f)
	spec.Writes.Disable = nil
	tg, _ := newTarget(t, spec)
	if err := tg.Apply(ctx, target.Request{Kind: target.DisableAccount, Account: target.Account{Username: "user001"}}); err == nil || target.Retryable(err) {
		t.Errorf("unconfigured operation: %v", err)
	}
	if err := tg.Apply(ctx, target.Request{Kind: target.UpdateAccount, Account: target.Account{Username: "nobody"}}); err == nil || target.Retryable(err) {
		t.Errorf("update of a missing account: %v", err)
	}
	f.Fail, f.FailStatus = 1000, 500
	err := tg.Apply(ctx, target.Request{Kind: target.CreateAccount, Account: target.Account{Username: "zed"}})
	var te *target.Error
	if !errors.As(err, &te) || !te.Retryable || te.Status != 500 {
		t.Errorf("5xx: %v", err)
	}
	f.Fail = 0
	f.Auth = "basic" // the credential is now refused
	err = tg.Apply(ctx, target.Request{Kind: target.CreateAccount, Account: target.Account{Username: "zed"}})
	if !errors.As(err, &te) || te.Retryable || te.Status != 401 || strings.Contains(err.Error(), fakerest.Bearer) {
		t.Errorf("401: %v", err)
	}
}

func TestTarget_PlanShowsExactRequestsWithoutSending(t *testing.T) {
	f := newFake(t, 3)
	f.Auth = "oauth2"
	spec := writeSpec(f)
	spec.Auth = Auth{Type: AuthOAuth2, ClientID: fakerest.ClientID, TokenURL: f.URL + "/oauth/token"}
	sec, _ := ParseSecrets(AuthOAuth2, fakerest.ClientSecret)
	tg, err := NewTarget(spec, sec, devRT, httpClient(t))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := tg.Plan(target.Request{Kind: target.CreateAccount, Account: target.Account{Username: "a/b", Email: "a@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 2 || plan[0].Step != "lookup" || plan[0].Write || plan[1].Step != "create" || !plan[1].Write || !plan[1].Conditional {
		t.Fatalf("plan: %+v", plan)
	}
	if plan[0].URL != f.URL+"/users/a%2Fb" || plan[1].Method != "POST" || plan[1].URL != f.URL+"/users" ||
		plan[1].Body != `{"email":"a@example.com","login":"a/b"}` {
		t.Errorf("plan: %+v", plan)
	}
	if !strings.Contains(plan[1].Auth, "oauth2") || strings.Contains(plan[1].Auth, fakerest.ClientSecret) {
		t.Errorf("auth note: %q", plan[1].Auth)
	}
	if n := len(f.Requests()); n != 0 || f.TokenCalls != 0 {
		t.Errorf("a plan sent %d requests (%d token calls)", n, f.TokenCalls)
	}
	// a template that needs a value the change does not have is named
	if _, err := tg.Plan(target.Request{Kind: target.AddEntitlement, Account: target.Account{Username: "x"}, Group: target.Group{ExternalID: "g1"}}); err == nil || !strings.Contains(err.Error(), "external_id") {
		t.Errorf("missing variable: %v", err)
	}
	// an API key in a query is shown masked
	spec.Auth = Auth{Type: AuthAPIKey, In: "query", Name: "api_key"}
	ks, _ := ParseSecrets(AuthAPIKey, fakerest.APIKey)
	tk, err := NewTarget(spec, ks, devRT, httpClient(t))
	if err != nil {
		t.Fatal(err)
	}
	plan, err = tk.Plan(target.Request{Kind: target.DeleteAccount, Account: target.Account{Username: "x", ExternalID: "u1"}})
	if err != nil || strings.Contains(plan[0].URL, fakerest.APIKey) || !strings.Contains(plan[0].URL, "api_key=%2A%2A%2A") {
		t.Errorf("api key in plan: %+v %v", plan, err)
	}
}

func TestProber(t *testing.T) {
	ctx := context.Background()
	f := newFake(t, 25)
	spec := baseSpec(f, "cursor")
	p, err := NewProber(spec, bearerSecrets(), devRT, httpClient(t))
	if err != nil {
		t.Fatal(err)
	}
	noSleep(p.c)
	if ci, err := p.Connect(ctx); err != nil || !ci.Reachable {
		t.Fatalf("connect: %+v %v", ci, err)
	}
	if ai, err := p.Authenticate(ctx); err != nil || !ai.OK || ai.Mode != "bearer_token" {
		t.Fatalf("authenticate: %+v %v", ai, err)
	}
	st, err := p.Sample(ctx, connectors.SampleQuery{Op: "mapping"})
	if err != nil {
		t.Fatal(err)
	}
	if st.Objects != 25 || st.Pages != 3 || len(st.Missing) != 0 || len(st.Findings) != 0 || st.AttrFill["email"] != 25 {
		t.Errorf("sample: %+v", st)
	}
	if st, _ := p.Sample(ctx, connectors.SampleQuery{Op: "mapping", Limit: 5}); st.Objects != 5 {
		t.Errorf("limited sample read %d", st.Objects)
	}
	if ri, err := p.RateLimits(ctx); err != nil || ri.Limit != 1000 || ri.Remaining != 990 || ri.Throttled != 0 {
		t.Errorf("rate limits: %+v %v", ri, err)
	}
	if _, err := p.Time(ctx); !errors.Is(err, connectors.ErrUnsupported) {
		t.Errorf("time: %v", err)
	}
	// a mapped field no record carries is reported missing
	spec.Users.Fields = map[string]string{"id": "$.id", "username": "$.login", "title": "$.title"}
	p2, _ := NewProber(spec, bearerSecrets(), devRT, httpClient(t))
	if st, _ := p2.Sample(ctx, connectors.SampleQuery{Op: "mapping"}); len(st.Missing) != 1 || st.Missing[0] != "title" {
		t.Errorf("missing: %+v", st)
	}
	// a wrong credential is a failed authentication, not an error
	f.Auth = "basic"
	if ai, err := p.Authenticate(ctx); err != nil || ai.OK {
		t.Errorf("wrong credential: %+v %v", ai, err)
	}
}

func TestProber_BadOAuthClientIsNotAuthenticated(t *testing.T) {
	f := newFake(t, 3)
	f.Auth = "oauth2"
	spec := baseSpec(f, "offset")
	spec.Auth = Auth{Type: AuthOAuth2, ClientID: fakerest.ClientID, TokenURL: f.URL + "/oauth/token"}
	sec, _ := ParseSecrets(AuthOAuth2, "nope-nope-nope")
	p, err := NewProber(spec, sec, devRT, httpClient(t))
	if err != nil {
		t.Fatal(err)
	}
	if ai, err := p.Authenticate(context.Background()); err != nil || ai.OK || ai.Mode != "client_secret" {
		t.Errorf("%+v %v", ai, err)
	}
}

func TestSource_IsAConnector(t *testing.T) {
	f := newFake(t, 3)
	s, _ := newSource(t, baseSpec(f, "offset"), bearerSecrets())
	var c connectors.Connector = s
	if c.System() != "rest" || c.TypeName() != "rest" || c.DisplayName() == "" {
		t.Errorf("%s %s %s", c.System(), c.TypeName(), c.DisplayName())
	}
	if err := c.StreamEvents(context.Background(), nil, func(connectors.Event) error { return errors.New("no events expected") }); err != nil {
		t.Error(err)
	}
	spec := baseSpec(f, "offset")
	spec.System = "acme-hr"
	s2, _ := newSource(t, spec, bearerSecrets())
	res, _ := s2.Discover(context.Background())
	if res.System != "acme-hr" || res.Accounts[0].System != "acme-hr" {
		t.Errorf("system: %q", res.System)
	}
	if _, err := New(&Spec{BaseURL: "ftp://x"}, bearerSecrets(), devRT, httpClient(t)); err == nil {
		t.Error("an invalid spec built a connector")
	}
}

func TestNewClient_RefusesHTTPInProd(t *testing.T) {
	f := newFake(t, 1)
	_, err := New(baseSpec(f, "offset"), bearerSecrets(), connsync.Runtime{Env: config.Prod}, httpClient(t))
	if err == nil {
		t.Fatal("plain http to loopback in prod")
	}
}

func TestSafehttpGuardsTheConnector(t *testing.T) {
	// the spec is accepted (dev runtime), but a production outbound client refuses a loopback target
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Prod})
	if err != nil {
		t.Fatal(err)
	}
	f := newFake(t, 2)
	s, err := New(baseSpec(f, "offset"), bearerSecrets(), devRT, hc)
	if err != nil {
		t.Fatal(err)
	}
	noSleep(s.c)
	if _, err := s.Discover(context.Background()); err == nil {
		t.Error("a loopback target was reached with the production client")
	}
	if n := len(f.Requests()); n != 0 {
		t.Errorf("%d requests reached the loopback server", n)
	}
}
