package loaders_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/loaders"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// scimFake is an in-process SCIM 2.0 service provider: Users and Groups with
// startIndex/count paging, a small filter language (displayName, userName sw
// or eq, active eq true), a bearer token, an OAuth client-credentials token
// endpoint, and the switch of a provider that lists groups without members.
type scimFake struct {
	srv           *httptest.Server
	token         string // the bearer token it accepts
	clientID      string
	clientSecret  string
	users         []map[string]any
	groups        []map[string]any
	membersInList bool
	mu            sync.Mutex
	requests      []string // "path?query" of every SCIM request
	auths         []string
	tokenCalls    int
}

func newSCIMFake(t *testing.T) *scimFake {
	f := &scimFake{token: "scim-token-secret", membersInList: true}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.tokenCalls++
		f.mu.Unlock()
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_id") != f.clientID || r.Form.Get("client_secret") != f.clientSecret {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at-" + f.token, "token_type": "Bearer", "expires_in": 60})
	})
	mux.HandleFunc("/scim/v2/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, strings.TrimPrefix(r.URL.RequestURI(), "/scim/v2"))
		f.auths = append(f.auths, r.Header.Get("Authorization"))
		f.mu.Unlock()
		if a := r.Header.Get("Authorization"); a != "Bearer "+f.token && a != "Bearer at-"+f.token {
			http.Error(w, "unauthorized: "+a, http.StatusUnauthorized) // an echo, which the run must not repeat
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/scim/v2/")
		switch {
		case path == "Users":
			f.list(w, r, f.users, "userName")
		case path == "Groups":
			f.list(w, r, f.groups, "displayName")
		case strings.HasPrefix(path, "Groups/"):
			for _, g := range f.groups {
				if g["id"] == strings.TrimPrefix(path, "Groups/") {
					_ = json.NewEncoder(w).Encode(g)
					return
				}
			}
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *scimFake) list(w http.ResponseWriter, r *http.Request, all []map[string]any, nameKey string) {
	q := r.URL.Query()
	var rows []map[string]any
	for _, x := range all {
		if scimMatches(q.Get("filter"), x, nameKey) {
			rows = append(rows, x)
		}
	}
	start, _ := strconv.Atoi(q.Get("startIndex"))
	count, _ := strconv.Atoi(q.Get("count"))
	if start < 1 {
		start = 1
	}
	if count < 1 || count > 3 { // the provider's own page cap
		count = 3
	}
	end := min(len(rows), start-1+count)
	page := []map[string]any{}
	if start-1 < len(rows) {
		for _, x := range rows[start-1 : end] {
			if nameKey == "displayName" && !f.membersInList {
				c := map[string]any{}
				for k, v := range x {
					if k != "members" {
						c[k] = v
					}
				}
				x = c
			}
			page = append(page, x)
		}
	}
	w.Header().Set("Content-Type", "application/scim+json")
	_ = json.NewEncoder(w).Encode(map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": len(rows), "startIndex": start, "itemsPerPage": len(page), "Resources": page})
}

// scimMatches: "<attr> sw|eq \"v\"" and "active eq true" (an empty filter matches).
func scimMatches(filter string, x map[string]any, nameKey string) bool {
	if filter == "" {
		return true
	}
	if filter == "active eq true" {
		return x["active"] != false
	}
	parts := strings.SplitN(filter, " ", 3)
	if len(parts) != 3 {
		return false
	}
	v, _ := x[parts[0]].(string)
	want := strings.Trim(parts[2], `"`)
	switch parts[1] {
	case "sw":
		return strings.HasPrefix(v, want)
	case "eq":
		return v == want
	}
	return false
}

func scimUser(i int, active bool) map[string]any {
	return map[string]any{"id": fmt.Sprintf("sid-%d", i), "userName": fmt.Sprintf("u%d", i), "externalId": fmt.Sprintf("ext-u%d", i), "active": active,
		"emails": []map[string]any{{"value": fmt.Sprintf("old%d@example.edu", i), "type": "home"}, {"value": fmt.Sprintf("u%d@example.edu", i), "primary": true}}}
}

func scimGroup(id, name string, members ...string) map[string]any {
	ms := []map[string]any{}
	for _, m := range members {
		t := "User"
		if strings.HasPrefix(m, "grp-") {
			t = "Group"
		}
		ms = append(ms, map[string]any{"value": m, "type": t, "display": m})
	}
	return map[string]any{"id": id, "displayName": name, "members": ms}
}

func (f *scimFake) seed() {
	for i := 0; i < 8; i++ {
		f.users = append(f.users, scimUser(i, i != 6)) // u6 is deactivated
	}
	f.groups = []map[string]any{
		scimGroup("grp-eng", "Engineering Team", "sid-0", "sid-1", "sid-2", "sid-6", "grp-ops"),
		scimGroup("grp-ops", "Ops", "sid-3", "sid-4"),
		scimGroup("grp-empty", "Nobody"),
	}
}

func (f *scimFake) reqs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

func (h *harness) scimHTTP() {
	h.t.Helper()
	hc, err := safehttp.NewForTest(h.t, safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		h.t.Fatal(err)
	}
	h.svc.HTTP = hc
}

func (h *harness) scimSpec(f *scimFake, name, cfg string) loaders.Spec {
	return loaders.Spec{Name: name, Type: loaders.TypeSCIM, TargetFolder: string(h.ref), Schedule: "@daily",
		Config: []byte(fmt.Sprintf(`{"base_url":%q,%s}`, f.srv.URL+"/scim/v2", cfg))}
}

func TestSCIM_GroupsPagedMembersMappedByUserName(t *testing.T) {
	h := newHarness(t)
	f := newSCIMFake(t)
	f.seed()
	h.scimHTTP()
	l := h.create(h.scimSpec(f, "idp", `"subject_attr":"userName","page_size":2`), f.token)
	r := h.run(l, store.RunFull)
	if r.Status != store.RunApplied {
		t.Fatalf("run = %s (%v)", r.Status, deref(r.Error))
	}
	// the deactivated user and the nested group are not members; names are made valid
	wantMembers(t, h, "ref:Engineering_Team", []string{"u0", "u1", "u2"})
	wantMembers(t, h, "ref:Ops", []string{"u3", "u4"})
	wantMembers(t, h, "ref:Nobody", nil)
	// paging by startIndex and count: the provider caps a page at 3, the loader asked for 2
	reqs := f.reqs()
	var pages []string
	for _, q := range reqs {
		if strings.HasPrefix(q, "/Users") {
			_, raw, _ := strings.Cut(q, "?")
			v, _ := url.ParseQuery(raw)
			pages = append(pages, v.Get("startIndex")+"/"+v.Get("count"))
		}
	}
	if strings.Join(pages, " ") != "1/2 3/2 5/2 7/2" {
		t.Errorf("user pages = %v, want 1/2 3/2 5/2 7/2 (8 users, pages of 2)", pages)
	}
	// every request carried the sealed token, and the token is stored sealed
	for _, a := range f.auths {
		if a != "Bearer "+f.token {
			t.Errorf("Authorization = %q", a)
		}
	}
	if stored := h.loader(l.ID); len(stored.SecretEnc) == 0 || strings.Contains(string(stored.SecretEnc), "scim-token") {
		t.Errorf("secret stored as %q", stored.SecretEnc)
	}
	// a second run changes nothing
	if r2 := h.run(l, store.RunFull); r2.Status != store.RunApplied || *r2.Adds != 0 || *r2.Removes != 0 {
		t.Errorf("second run = %+v", r2)
	}
}

func TestSCIM_MapsByEmailAndExternalIDAndKeepsInactive(t *testing.T) {
	h := newHarness(t)
	f := newSCIMFake(t)
	f.seed()
	h.scimHTTP()
	byEmail := h.create(h.scimSpec(f, "by-email", `"subject_attr":"email","name_prefix":"e_"`), f.token)
	if r := h.run(byEmail, store.RunFull); r.Status != store.RunApplied {
		t.Fatalf("run = %s (%v)", r.Status, deref(r.Error))
	}
	wantMembers(t, h, "ref:e_Engineering_Team", []string{"u0", "u1", "u2"}) // the primary address, not the home one
	// external ids that match no identity are listed, never dropped
	byExt := h.create(h.scimSpec(f, "by-ext", `"subject_attr":"externalId","name_prefix":"x_"`), f.token)
	r := h.run(byExt, store.RunFull)
	if r.Status != store.RunHeld && r.Status != store.RunApplied {
		t.Fatalf("run = %s (%v)", r.Status, deref(r.Error))
	}
	if un := h.unresolved(byExt.ID); len(un) == 0 || !strings.HasPrefix(un[0].Identifier, "ext-u") {
		t.Errorf("unresolved = %+v, want the external ids", un)
	}
	// only_active=false keeps the deactivated user
	all := h.create(h.scimSpec(f, "all", `"subject_attr":"userName","only_active":false,"name_prefix":"a_"`), f.token)
	if r := h.run(all, store.RunFull); r.Status != store.RunApplied {
		t.Fatalf("run = %s (%v)", r.Status, deref(r.Error))
	}
	wantMembers(t, h, "ref:a_Engineering_Team", []string{"u0", "u1", "u2", "u6"})
}

func TestSCIM_FiltersAndGroupsListedWithoutMembers(t *testing.T) {
	h := newHarness(t)
	f := newSCIMFake(t)
	f.seed()
	f.membersInList = false
	h.scimHTTP()
	l := h.create(h.scimSpec(f, "filtered", `"subject_attr":"userName","group_filter":"displayName sw \"Eng\"","user_filter":"userName sw \"u\""`), f.token)
	if r := h.run(l, store.RunFull); r.Status != store.RunApplied {
		t.Fatalf("run = %s (%v)", r.Status, deref(r.Error))
	}
	wantMembers(t, h, "ref:Engineering_Team", []string{"u0", "u1", "u2"})
	var sawFilter, sawGroupFetch bool
	for _, q := range f.reqs() {
		sawFilter = sawFilter || strings.HasPrefix(q, "/Groups?") && strings.Contains(q, "filter=displayName+sw")
		sawGroupFetch = sawGroupFetch || q == "/Groups/grp-eng"
		if q == "/Groups/grp-ops" {
			t.Error("a group the filter excludes was fetched")
		}
	}
	if !sawFilter || !sawGroupFetch {
		t.Errorf("filter sent = %v, members fetched one by one = %v (%v)", sawFilter, sawGroupFetch, f.reqs())
	}
}

func TestSCIM_ClientCredentials(t *testing.T) {
	h := newHarness(t)
	f := newSCIMFake(t)
	f.seed()
	f.clientID, f.clientSecret = "tessera", "cc-secret-value"
	h.scimHTTP()
	cfg := fmt.Sprintf(`"subject_attr":"userName","auth":"client_credentials","token_url":%q,"client_id":"tessera","scope":"scim"`, f.srv.URL+"/oauth/token")
	l := h.create(h.scimSpec(f, "oauth", cfg), "cc-secret-value")
	if r := h.run(l, store.RunFull); r.Status != store.RunApplied {
		t.Fatalf("run = %s (%v)", r.Status, deref(r.Error))
	}
	if f.tokenCalls != 1 {
		t.Errorf("token calls = %d", f.tokenCalls)
	}
	for _, a := range f.auths {
		if a != "Bearer at-"+f.token {
			t.Errorf("Authorization = %q: the client secret must not be the bearer", a)
		}
	}
	wrong := h.create(h.scimSpec(f, "oauth-wrong", cfg), "not-the-secret")
	r := h.run(wrong, store.RunFull)
	if r.Status != store.RunFailed || !strings.Contains(deref(r.Error), "token endpoint") || strings.Contains(deref(r.Error), "not-the-secret") {
		t.Errorf("wrong secret: %s %q", r.Status, deref(r.Error))
	}
}

func TestSCIM_RefusedCredentialAndSecretNeverInErrorsOrAudit(t *testing.T) {
	h := newHarness(t)
	f := newSCIMFake(t)
	f.seed()
	h.scimHTTP()
	l := h.create(h.scimSpec(f, "badtoken", `"subject_attr":"userName"`), "wrong-token-value")
	r := h.run(l, store.RunFull)
	if r.Status != store.RunFailed || !strings.Contains(deref(r.Error), "refused the credential") {
		t.Fatalf("run = %s %q", r.Status, deref(r.Error))
	}
	if strings.Contains(deref(r.Error), "wrong-token-value") {
		t.Errorf("the error carries the token: %q", deref(r.Error))
	}
	h.read(func(tx *store.TenantTx) error {
		log, err := tx.AuditLog(-1)
		for _, e := range log {
			if b, _ := json.Marshal(e); strings.Contains(string(b), "wrong-token-value") {
				t.Errorf("audit event %s holds the token", e.Action)
			}
		}
		return err
	})
}

func TestSCIM_SSRFGuardAndConfig(t *testing.T) {
	h := newHarness(t)
	f := newSCIMFake(t)
	f.seed()
	// the guarded client of production refuses a loopback provider
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Prod})
	if err != nil {
		t.Fatal(err)
	}
	h.svc.HTTP = hc
	l := h.create(h.scimSpec(f, "ssrf", `"subject_attr":"userName"`), f.token)
	if r := h.run(l, store.RunFull); r.Status != store.RunFailed {
		t.Errorf("a loopback provider was read: %s", r.Status)
	}
	if n := len(f.reqs()); n != 0 {
		t.Errorf("the provider saw %d requests", n)
	}
	for name, cfg := range map[string]string{
		"no subject_attr":      `"base_url":"https://x.example/scim/v2"`,
		"bad subject_attr":     `"base_url":"https://x.example/scim/v2","subject_attr":"password"`,
		"url with credentials": `"base_url":"https://u:p@x.example/scim/v2","subject_attr":"id"`,
		"ftp":                  `"base_url":"ftp://x.example","subject_attr":"id"`,
		"cc without token_url": `"base_url":"https://x.example","subject_attr":"id","auth":"client_credentials","client_id":"a"`,
		"token_url on bearer":  `"base_url":"https://x.example","subject_attr":"id","token_url":"https://x.example/t"`,
		"page too big":         `"base_url":"https://x.example","subject_attr":"id","page_size":5000`,
		"filter control char":  `"base_url":"https://x.example","subject_attr":"id","user_filter":"a\u0000b"`,
		"unknown field":        `"base_url":"https://x.example","subject_attr":"id","script":"x"`,
	} {
		if _, err := loaders.ValidateConfig(loaders.TypeSCIM, json.RawMessage("{"+cfg+"}"), false); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	ok := `{"base_url":"https://x.example/scim/v2","subject_attr":"email","auth":"client_credentials","token_url":"https://x.example/t","client_id":"a","group_filter":"displayName sw \"a\""}`
	if _, err := loaders.ValidateConfig(loaders.TypeSCIM, json.RawMessage(ok), false); err != nil {
		t.Errorf("valid config: %v", err)
	}
}

func TestSCIM_NeedsItsCredential(t *testing.T) {
	h := newHarness(t)
	f := newSCIMFake(t)
	err := h.db.InTenant(t.Context(), tid, func(tx *store.TenantTx) error {
		_, err := loaders.Create(loaders.SaveEnv{Tx: tx, Now: h.now, Sealer: h.sealer}, h.scimSpec(f, "nosecret", `"subject_attr":"id"`), "")
		return err
	})
	if errCode(err) != "secret_required" {
		t.Errorf("create without a secret: %v", err)
	}
}
