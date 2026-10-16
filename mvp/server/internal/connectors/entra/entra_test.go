package entra

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
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
	tenantGUID = "11111111-2222-3333-4444-555555555555"
	ada        = "aaaaaaaa-0000-4000-8000-000000000001"
	ben        = "aaaaaaaa-0000-4000-8000-000000000002"
	cy         = "aaaaaaaa-0000-4000-8000-000000000003"
	dee        = "aaaaaaaa-0000-4000-8000-000000000004"
	g1         = "bbbbbbbb-0000-4000-8000-000000000001"
	g2         = "bbbbbbbb-0000-4000-8000-000000000002"
	g3         = "bbbbbbbb-0000-4000-8000-000000000003"
	spBilling  = "cccccccc-0000-4000-8000-000000000001"
	spSaaS     = "cccccccc-0000-4000-8000-000000000002"
	spPlatform = "cccccccc-0000-4000-8000-000000000003"
	roleAdmin  = "62e90394-69f5-4237-9190-012177145e10"
	roleReader = "f2ef992c-3afb-46b9-b7cf-a126ee74c451"
	saasAppID  = "22220000-0000-4000-8000-000000000002"
)

// fake replays the recorded fixtures as a Graph tenant.
type fake struct {
	t   *testing.T
	srv *connsynctest.Server

	mu         sync.Mutex
	changed    bool              // serve the delta fixtures for the stored delta links
	status     map[string]int    // path prefix -> forced status
	statusBody map[string]string // path prefix -> body for a forced status
	body       map[string]string // path -> override body
	retry429   map[string]int    // path -> number of 429s to answer first
	tokenForms []url.Values
	override   http.HandlerFunc

	signInStatus int // forced status for the signInActivity list
	signInBody   string
}

func newFake(t *testing.T) *fake {
	f := &fake{t: t, status: map[string]int{}, statusBody: map[string]string{}, body: map[string]string{}, retry429: map[string]int{}}
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
	for p, s := range f.status {
		if strings.HasPrefix(r.URL.Path, p) {
			w.WriteHeader(s)
			b := f.statusBody[p]
			if b == "" {
				b = `{"error":{"code":"Authorization_RequestDenied","message":"leaky-body-should-never-surface"}}`
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
	if b, ok := f.body[r.URL.Path]; ok {
		fmt.Fprint(w, b)
		return
	}
	out := func(name string) { _, _ = w.Write(connsynctest.Fixture(f.t, name, f.srv.URL)) }
	q := r.URL.Query()
	p := strings.TrimPrefix(r.URL.Path, "/v1.0")
	switch {
	case r.URL.Path == "/"+tenantGUID+"/oauth2/v2.0/token":
		_ = r.ParseForm()
		f.tokenForms = append(f.tokenForms, r.PostForm)
		fmt.Fprint(w, `{"token_type":"Bearer","expires_in":3599,"access_token":"graph-token-1"}`)
	case p == "/users/delta":
		switch q.Get("$deltatoken") {
		case "dt-users-1":
			if f.changed {
				out("users_delta_inc.json")
			} else {
				fmt.Fprintf(w, `{"value":[],"@odata.deltaLink":"%s/v1.0/users/delta?$deltatoken=dt-users-1"}`, f.srv.URL)
			}
		case "dt-users-2":
			fmt.Fprintf(w, `{"value":[],"@odata.deltaLink":"%s/v1.0/users/delta?$deltatoken=dt-users-2"}`, f.srv.URL)
		case "dt-users-expired":
			w.WriteHeader(http.StatusGone)
			fmt.Fprint(w, `{"error":{"code":"resyncRequired"}}`)
		case "dt-users-bad":
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":{"code":"syncStateNotFound"}}`)
		default:
			if q.Get("$skiptoken") == "p2" {
				out("users_delta_p2.json")
			} else {
				out("users_delta_p1.json")
			}
		}
	case p == "/groups/delta":
		switch q.Get("$deltatoken") {
		case "dt-groups-1":
			if f.changed {
				out("groups_delta_inc.json")
			} else {
				fmt.Fprintf(w, `{"value":[],"@odata.deltaLink":"%s/v1.0/groups/delta?$deltatoken=dt-groups-1"}`, f.srv.URL)
			}
		case "dt-groups-2":
			fmt.Fprintf(w, `{"value":[],"@odata.deltaLink":"%s/v1.0/groups/delta?$deltatoken=dt-groups-2"}`, f.srv.URL)
		default:
			out("groups_delta.json")
		}
	case p == "/groups/"+g1+"/members":
		switch {
		case f.changed:
			out("members_g1_inc.json")
		case q.Get("$skiptoken") == "m2":
			out("members_g1_p2.json")
		default:
			out("members_g1_p1.json")
		}
	case p == "/groups/"+g2+"/members":
		out("members_g2.json")
	case p == "/groups/"+g3+"/members":
		out("members_g3.json")
	case p == "/users":
		if q.Get("$select") != "id,signInActivity" {
			f.t.Errorf("unexpected users list %s", r.URL.RawQuery)
		}
		if f.signInStatus != 0 {
			w.WriteHeader(f.signInStatus)
			fmt.Fprint(w, f.signInBody)
			return
		}
		out("signins_users.json")
	case p == "/servicePrincipals":
		out("serviceprincipals.json")
	case p == "/servicePrincipals/"+spBilling+"/appRoleAssignedTo":
		out("assigned_billing.json")
	case p == "/servicePrincipals/"+spSaaS+"/appRoleAssignedTo":
		out("assigned_saas.json")
	case p == "/roleManagement/directory/roleDefinitions":
		out("roledefinitions.json")
	case p == "/roleManagement/directory/roleAssignments":
		out("roleassignments.json")
	case p == "/auditLogs/signIns":
		out("signinlog.json")
	default:
		f.t.Errorf("unexpected request %s %s", r.Method, r.URL.String())
		http.NotFound(w, r)
	}
}

func baseCfg() Config {
	return Config{TenantID: tenantGUID, ClientID: "00000000-aaaa-4bbb-8ccc-000000000001", ClientSecret: connsync.NewSecret("client-secret-xyz"),
		EmitIdentities: true, SignInActivity: true}
}

func (f *fake) connector(cfg Config) *Connector {
	f.t.Helper()
	cfg.GraphURL, cfg.AuthorityURL = f.srv.URL, f.srv.URL
	c, err := New(cfg, connsynctest.Runtime, f.srv.Client(f.t, 0), func() time.Time { return now0 })
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
	res, err := f.connector(baseCfg()).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	accts := acctMap(res)
	if len(accts) != 4 { // three users (the malformed id is dropped) and the tenant-owned service principal
		t.Fatalf("accounts = %d: %v", len(accts), accts)
	}
	a := accts[ada]
	if a.Username != "ada.fixture@fixture.onmicrosoft.com" || a.Kind != "user" || a.Status != "active" || a.Identity.ExternalID != "EMP-2001" ||
		a.Identity.Email != "ada.fixture@example.com" || a.LastLoginAt == nil || !a.LastLoginAt.Equal(time.Date(2026, 10, 7, 9, 15, 0, 0, time.UTC)) {
		t.Errorf("ada = %+v", a)
	}
	if b := accts[ben]; b.Identity.ExternalID != "entra:"+ben || b.Identity.Email != "ben.sample@fixture.onmicrosoft.com" || b.LastLoginAt != nil {
		t.Errorf("ben = %+v (no employeeId: entra:<id>; no mail: the UPN; signInActivity null: no last login)", b)
	}
	if c := accts[cy]; c.Status != "disabled" || c.Identity.Email != "cy@guest.example.net" || c.LastLoginAt == nil || c.LastLoginAt.Year() != 2025 {
		t.Errorf("cy = %+v (disabled guest with only lastSignInDateTime)", c)
	}
	sp := accts[spBilling]
	if sp.Kind != "service" || sp.Username != "Fixture Billing Service" || sp.Identity.ExternalID != "entra-sp:"+spBilling {
		t.Errorf("service principal account = %+v", sp)
	}
	if _, ok := accts[spSaaS]; ok {
		t.Error("a third-party service principal became an account")
	}
	if _, ok := accts[spPlatform]; ok {
		t.Error("another tenant's service principal became an account")
	}
	ids := map[string]connectors.IdentityRecord{}
	for _, i := range res.Identities {
		ids[i.ExternalID] = i
	}
	if len(ids) != 4 || ids["EMP-2001"].Type != "human" || ids["entra-sp:"+spBilling].Type != "service" || *ids["EMP-2001"].Department != "Engineering" {
		t.Errorf("identities = %+v", ids)
	}
	groups := groupMap(res)
	if len(groups) != 5 {
		t.Errorf("groups = %v", groups)
	}
	if groups[g1].Kind != "security_group" || groups[g3].Kind != "m365_group" || groups[g1].Privileged || !groups[g2].Privileged {
		t.Errorf("group kinds/privilege: %+v", groups)
	}
	if r := groups["role:"+roleAdmin]; r.Kind != "role" || r.Name != "Global Administrator" || !r.Privileged {
		t.Errorf("Global Administrator = %+v", r)
	}
	if r := groups["role:"+roleReader]; r.Kind != "role" || r.Privileged {
		t.Errorf("Global Reader = %+v (reader roles are not privileged)", r)
	}
	if _, ok := groups["role:88d8e3e3-8f55-4a1e-953a-9b9898b8876b"]; ok {
		t.Error("a role whose only assignee is unknown was emitted")
	}
	if len(res.Resources) != 2 || len(res.Permissions) != 5 {
		t.Fatalf("resources = %d, permissions = %d; want 2 and 5 (the Microsoft-owned app is skipped, a disabled app role too)", len(res.Resources), len(res.Permissions))
	}
	perms := map[string]string{}
	for _, p := range res.Permissions {
		perms[p.ExternalID] = p.Action
	}
	if perms["app:"+spBilling+":access"] != "access" || perms["app:"+spBilling+":dd000000-0000-4000-8000-000000000002"] != "Invoice.Write" ||
		perms["app:"+spSaaS+":ee000000-0000-4000-8000-000000000001"] != "Admin" {
		t.Errorf("permissions = %v", perms)
	}
	want := []string{
		// group membership, with a nested group (g1 is a member of g2)
		"account:" + ada + "->group:" + g1 + " member_of",
		"account:" + ben + "->group:" + g1 + " member_of",
		"group:" + g1 + "->group:" + g2 + " member_of",
		"account:" + cy + "->group:" + g2 + " member_of",
		"account:" + spBilling + "->group:" + g3 + " member_of",
		// directory roles, to a user, a group and a service principal
		"account:" + ada + "->group:role:" + roleAdmin + " member_of",
		"group:" + g2 + "->group:role:" + roleAdmin + " member_of",
		"account:" + spBilling + "->group:role:" + roleReader + " member_of",
		// app role assignments
		"account:" + ada + "->perm:app:" + spBilling + ":dd000000-0000-4000-8000-000000000002 direct_grant",
		"account:" + ada + "->perm:app:" + spSaaS + ":access direct_grant",
		"group:" + g1 + "->perm:app:" + spSaaS + ":access grants",
		"account:" + ben + "->perm:app:" + spSaaS + ":ee000000-0000-4000-8000-000000000001 direct_grant",
	}
	got := edgeSet(res)
	for _, e := range want {
		if !got[e] {
			t.Errorf("missing edge %s", e)
		}
	}
	if len(got) != len(want) {
		t.Errorf("edges = %d, want %d: %v", len(got), len(want), got)
	}
}

func TestRequestsAreReadOnlyAuthorizedAndStayOnTheTenant(t *testing.T) {
	f := newFake(t)
	c := f.connector(baseCfg())
	ms := &connsync.MemoryStore{}
	ctx := connsync.WithStore(context.Background(), ms)
	if _, err := c.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.StreamEvents(ctx, nil, func(connectors.Event) error { return nil }); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	forms := f.tokenForms
	f.mu.Unlock()
	if len(forms) != 1 {
		t.Fatalf("token requests = %d, want 1 (cached)", len(forms))
	}
	tf := forms[0]
	if tf.Get("grant_type") != "client_credentials" || tf.Get("client_id") != baseCfg().ClientID || tf.Get("client_secret") != "client-secret-xyz" ||
		tf.Get("scope") != f.srv.URL+"/.default" {
		t.Errorf("token form = %v", tf)
	}
	for _, r := range f.srv.Requests() {
		if strings.Contains(r.Path, "oauth2") {
			if r.Method != http.MethodPost || r.Authorization != "" {
				t.Errorf("token request = %+v", r)
			}
			continue
		}
		if r.Method != http.MethodGet || r.Authorization != "Bearer graph-token-1" {
			t.Errorf("%s %s: method/Authorization = %q", r.Method, r.Path, r.Authorization)
		}
		if !strings.HasPrefix(r.Path, "/v1.0/") {
			t.Errorf("request outside Graph v1.0: %s", r.Path)
		}
	}
	if n := f.srv.Count("/v1.0/servicePrincipals/" + spPlatform); n != 0 {
		t.Errorf("app assignments were read for a Microsoft-owned app (%d calls)", n)
	}
}

func TestSignInActivityMissingDegradesGracefully(t *testing.T) {
	for name, setup := range map[string]func(f *fake){
		"forbidden (AuditLog.Read.All not granted)": func(f *fake) {
			f.signInStatus = 403
			f.signInBody = `{"error":{"code":"Authorization_RequestDenied"}}`
		},
		"tenant without P1/P2 (403 with its own code)": func(f *fake) {
			f.signInStatus = 403
			f.signInBody = `{"error":{"code":"Authentication_RequestFromNonPremiumTenantOrB2CTenant"}}`
		},
		"property absent from the response": func(f *fake) {
			f.body["/v1.0/users"] = `{"value":[{"id":"` + ada + `"},{"id":"` + ben + `"}]}`
		},
		"switched off by configuration": func(f *fake) {},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			setup(f)
			cfg := baseCfg()
			cfg.SignInActivity = !strings.HasPrefix(name, "switched off")
			res, err := f.connector(cfg).Discover(context.Background())
			if err != nil {
				t.Fatalf("Discover failed: %v", err)
			}
			if len(res.Accounts) != 4 || len(res.Groups) != 5 {
				t.Errorf("accounts/groups = %d/%d", len(res.Accounts), len(res.Groups))
			}
			for _, a := range res.Accounts {
				if a.LastLoginAt != nil {
					t.Errorf("%s has a last login without sign-in data", a.ExternalID)
				}
			}
			if strings.HasPrefix(name, "switched off") {
				for _, r := range f.srv.Requests() {
					if strings.Contains(r.Query, "signInActivity") {
						t.Error("signInActivity was requested although it is switched off")
					}
				}
			}
		})
	}
}

func TestDirectoryRolesForbiddenDegrades(t *testing.T) {
	f := newFake(t)
	f.status["/v1.0/roleManagement"] = 403
	res, err := f.connector(baseCfg()).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range res.Groups {
		if g.Kind == "role" {
			t.Errorf("role %s present although role management was forbidden", g.ExternalID)
		}
	}
	if len(res.Groups) != 3 || len(res.Accounts) != 4 {
		t.Errorf("groups/accounts = %d/%d", len(res.Groups), len(res.Accounts))
	}
}

func TestThrottlingWithRetryAfter(t *testing.T) {
	f := newFake(t)
	f.retry429["/v1.0/users/delta"] = 2
	f.retry429["/v1.0/groups/"+g2+"/members"] = 1
	c := f.connector(baseCfg())
	ns := &connsynctest.NoSleep{}
	c.api.Backoff = connsync.Backoff{Base: time.Millisecond, Max: 10 * time.Second, Sleep: ns.Sleep}
	res, err := c.Discover(context.Background())
	if err != nil || len(res.Accounts) != 4 {
		t.Fatalf("Discover = %v, %v", res, err)
	}
	if len(ns.Waits) != 3 {
		t.Fatalf("waits = %v, want 3", ns.Waits)
	}
	for _, w := range ns.Waits {
		if w != 4*time.Second {
			t.Errorf("wait %v, want the Retry-After of 4s", w)
		}
	}
	// a permanent 429 fails, naming nothing from the body
	f2 := newFake(t)
	f2.status["/v1.0/users/delta"] = 429
	_, err = f2.connector(baseCfg()).Discover(context.Background())
	if !errors.Is(err, connsync.ErrRateLimited) || strings.Contains(err.Error(), "leaky-body") {
		t.Errorf("err = %v", err)
	}
}

func TestMalformedAndOversizedPages(t *testing.T) {
	for name, body := range map[string]string{
		"array instead of object": `[]`,
		"truncated":               `{"value":[{"id":`,
		"value of the wrong type": `{"value":"nope"}`,
		"trailing garbage":        `{"value":[]} {}`,
		"empty":                   ``,
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			f.body["/v1.0/users/delta"] = body
			if _, err := f.connector(baseCfg()).Discover(context.Background()); !errors.Is(err, connsync.ErrMalformed) {
				t.Errorf("err = %v, want ErrMalformed", err)
			}
		})
	}
	t.Run("delta query without a delta link", func(t *testing.T) {
		f := newFake(t)
		f.body["/v1.0/users/delta"] = `{"value":[]}`
		if _, err := f.connector(baseCfg()).Discover(context.Background()); !errors.Is(err, connsync.ErrMalformed) {
			t.Errorf("err = %v, want ErrMalformed", err)
		}
	})
	t.Run("oversized", func(t *testing.T) {
		f := newFake(t)
		f.body["/v1.0/users/delta"] = `{"value":[{"id":"` + ada + `","displayName":"` + strings.Repeat("x", 8192) + `"}]}`
		cfg := baseCfg()
		cfg.GraphURL, cfg.AuthorityURL = f.srv.URL, f.srv.URL
		c, err := New(cfg, connsynctest.Runtime, f.srv.Client(t, 2048), func() time.Time { return now0 })
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
	f.override = func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "oauth2") {
			fmt.Fprint(w, `{"token_type":"Bearer","expires_in":3599,"access_token":"graph-token-1"}`)
			return
		}
		fmt.Fprint(w, `{"value":[],"@odata.nextLink":"https://evil.example.net/v1.0/users/delta?$skiptoken=x"}`)
	}
	_, err := f.connector(baseCfg()).Discover(context.Background())
	if err == nil || !strings.Contains(err.Error(), "leaves the configured host") {
		t.Fatalf("err = %v", err)
	}
}

// ---------------------------------------------------------------- incremental

func TestIncrementalDeltaSync(t *testing.T) {
	f := newFake(t)
	ms := &connsync.MemoryStore{}
	ctx := connsync.WithStore(context.Background(), ms)
	if _, err := f.connector(baseCfg()).Discover(ctx); err != nil {
		t.Fatal(err)
	}
	cp, _ := ms.Load(ctx, System, checkpointName)
	if cp == nil || cp.FullSyncAt == nil || len(cp.State) == 0 {
		t.Fatalf("checkpoint = %+v", cp)
	}
	var cur cursor
	if err := json.Unmarshal([]byte(cp.Cursor), &cur); err != nil ||
		cur.Users != f.srv.URL+"/v1.0/users/delta?$deltatoken=dt-users-1" || cur.Groups != f.srv.URL+"/v1.0/groups/delta?$deltatoken=dt-groups-1" {
		t.Fatalf("cursor = %q (%v), want the two delta links", cp.Cursor, err)
	}

	f.changed = true
	before := len(f.srv.Requests())
	res, err := f.connector(baseCfg()).Discover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, r := range f.srv.Requests()[before:] {
		paths = append(paths, r.Path+"?"+r.Query)
	}
	joined := strings.Join(paths, "\n")
	if !strings.Contains(joined, "/v1.0/users/delta?$deltatoken=dt-users-1") || !strings.Contains(joined, "/v1.0/groups/delta?$deltatoken=dt-groups-1") {
		t.Errorf("the stored delta links were not used:\n%s", joined)
	}
	if strings.Contains(joined, "/users/delta?$select") || strings.Contains(joined, "/members?$select=id&$top=999\n/v1.0/groups/"+g2) {
		t.Errorf("a full enumeration ran:\n%s", joined)
	}
	if f.srv.Count("/v1.0/groups/"+g2+"/members") != 1 || f.srv.Count("/v1.0/groups/"+g3+"/members") != 1 {
		t.Errorf("unchanged groups' members were re-read:\n%s", joined)
	}
	accts := acctMap(res)
	// ada: a delta item that carries only displayName must not blank the other properties
	if a := accts[ada]; a.Username != "ada.fixture@fixture.onmicrosoft.com" || a.Identity.ExternalID != "EMP-2001" || a.Identity.Email != "ada.fixture@example.com" {
		t.Errorf("partial update lost properties: %+v", a)
	}
	for _, i := range res.Identities {
		if i.ExternalID == "EMP-2001" && i.Name != "Ada Fixture-Lovelace" {
			t.Errorf("ada's name = %q, want the delta's", i.Name)
		}
	}
	if _, ok := accts[cy]; ok {
		t.Error("a user the delta reported as removed is still an account")
	}
	if _, ok := accts[dee]; !ok || len(accts) != 4 { // ada, ben, dee, the service principal
		t.Errorf("accounts = %v", accts)
	}
	groups := groupMap(res)
	if _, ok := groups[g3]; ok {
		t.Error("a group the delta reported as removed is still present")
	}
	got := edgeSet(res)
	if got["account:"+ben+"->group:"+g1+" member_of"] || !got["account:"+dee+"->group:"+g1+" member_of"] || !got["account:"+ada+"->group:"+g1+" member_of"] {
		t.Errorf("Engineering membership not refreshed: %v", got)
	}
	if got["account:"+cy+"->group:"+g2+" member_of"] {
		t.Error("the removed user still has a membership edge")
	}
	if !got["group:"+g1+"->group:"+g2+" member_of"] {
		t.Error("an unchanged group lost its nested member")
	}
	cp2, _ := ms.Load(ctx, System, checkpointName)
	if !strings.Contains(cp2.Cursor, "dt-users-2") || !strings.Contains(cp2.Cursor, "dt-groups-2") {
		t.Errorf("cursor not advanced: %s", cp2.Cursor)
	}
	if cp2.FullSyncAt == nil || !cp2.FullSyncAt.Equal(*cp.FullSyncAt) {
		t.Errorf("FullSyncAt moved on an incremental sync")
	}
}

func TestExpiredDeltaTokenFallsBackToFullRead(t *testing.T) {
	for name, token := range map[string]string{"410 Gone": "dt-users-expired", "400 syncStateNotFound": "dt-users-bad"} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			ms := &connsync.MemoryStore{}
			ctx := connsync.WithStore(context.Background(), ms)
			if _, err := f.connector(baseCfg()).Discover(ctx); err != nil {
				t.Fatal(err)
			}
			cp, _ := ms.Load(ctx, System, checkpointName)
			cp.Cursor = fmt.Sprintf(`{"users":"%s/v1.0/users/delta?$deltatoken=%s","groups":"%s/v1.0/groups/delta?$deltatoken=dt-groups-1"}`,
				f.srv.URL, token, f.srv.URL)
			_ = ms.Save(ctx, System, checkpointName, cp)
			before := len(f.srv.Requests())
			res, err := f.connector(baseCfg()).Discover(ctx)
			if err != nil || len(res.Accounts) != 4 {
				t.Fatalf("Discover = %v, %v", res, err)
			}
			var sawStale, sawFull bool
			for _, r := range f.srv.Requests()[before:] {
				if r.Path == "/v1.0/users/delta" && strings.Contains(r.Query, token) {
					sawStale = true
				}
				if r.Path == "/v1.0/users/delta" && strings.Contains(r.Query, "select") {
					sawFull = true
				}
			}
			if !sawStale || !sawFull {
				t.Errorf("stale=%v full=%v: want the stale link tried once, then a full enumeration", sawStale, sawFull)
			}
			cp2, _ := ms.Load(ctx, System, checkpointName)
			if !strings.Contains(cp2.Cursor, "dt-users-1") || cp2.FullSyncAt == nil || !cp2.FullSyncAt.Equal(now0) {
				t.Errorf("checkpoint after fallback = %+v", cp2)
			}
		})
	}
}

func TestStoredDeltaLinkForAnotherHostIsNeverUsed(t *testing.T) {
	f := newFake(t)
	ms := &connsync.MemoryStore{}
	ctx := connsync.WithStore(context.Background(), ms)
	if _, err := f.connector(baseCfg()).Discover(ctx); err != nil {
		t.Fatal(err)
	}
	cp, _ := ms.Load(ctx, System, checkpointName)
	cp.Cursor = `{"users":"https://evil.example.net/v1.0/users/delta?$deltatoken=x","groups":"https://evil.example.net/v1.0/groups/delta?$deltatoken=y"}`
	_ = ms.Save(ctx, System, checkpointName, cp)
	res, err := f.connector(baseCfg()).Discover(ctx)
	if err != nil || len(res.Accounts) != 4 {
		t.Fatalf("Discover = %v, %v", res, err)
	}
	for _, r := range f.srv.Requests() {
		if strings.Contains(r.Query, "deltatoken=x") {
			t.Error("a delta link from another host was requested")
		}
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
	full := func() int {
		n := 0
		for _, r := range f.srv.Requests() {
			if r.Path == "/v1.0/users/delta" && strings.Contains(r.Query, "select") {
				n++
			}
		}
		return n
	}
	if _, err := c.Discover(ctx); err != nil || full() != 1 {
		t.Fatalf("a second sync re-enumerated users (%d, %v)", full(), err)
	}
	if _, err := c.Discover(connsync.WithMode(ctx, connsync.Full)); err != nil || full() != 2 {
		t.Fatalf("on-demand full sync did not re-enumerate users (%d, %v)", full(), err)
	}
	// MaxIncrementalAge forces a full read once the last one is old enough
	cfg := baseCfg()
	cfg.MaxIncrementalAge = time.Hour
	c2 := f.connector(cfg)
	c2.now = func() time.Time { return now0.Add(2 * time.Hour) }
	if _, err := c2.Discover(ctx); err != nil || full() != 3 {
		t.Fatalf("a stale chain was not repaired (%d, %v)", full(), err)
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
	n := 0
	for _, r := range f.srv.Requests() {
		if r.Path == "/v1.0/users/delta" && strings.Contains(r.Query, "select") {
			n++
		}
	}
	if n != 2 {
		t.Errorf("full enumerations = %d, want 2", n)
	}
}

func TestMergeInto(t *testing.T) {
	u := &eUser{ID: ada, DisplayName: "Ada", Mail: "ada@example.com", Department: "Eng"}
	if err := mergeInto(u, json.RawMessage(`{"id":"`+ada+`","displayName":"Ada L","department":null,"@odata.type":"#microsoft.graph.user","members@delta":[1]}`)); err != nil {
		t.Fatal(err)
	}
	if u.DisplayName != "Ada L" || u.Mail != "ada@example.com" || u.Department != "" {
		t.Errorf("merged = %+v (present properties overwrite, absent ones stay, null clears)", u)
	}
	if err := mergeInto(u, json.RawMessage(`{"displayName":["x"]}`)); err == nil {
		t.Error("a wrongly typed property was accepted")
	}
	if err := mergeInto(u, json.RawMessage(`not json`)); err == nil {
		t.Error("garbage was accepted")
	}
}

// ---------------------------------------------------------------- events

func TestStreamEventsFromSignInLog(t *testing.T) {
	f := newFake(t)
	ms := &connsync.MemoryStore{}
	ctx := connsync.WithStore(context.Background(), ms)
	c := f.connector(baseCfg())
	// without a discovery there are no apps to attribute usage to
	n := 0
	if err := c.StreamEvents(ctx, nil, func(connectors.Event) error { n++; return nil }); err != nil || n != 0 {
		t.Fatalf("before discovery: %v, %d events", err, n)
	}
	if _, err := c.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	var got []*connectors.UsageRecord
	if err := c.StreamEvents(ctx, nil, func(e connectors.Event) error { got = append(got, e.(*connectors.UsageRecord)); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("events = %d, want 2 (a failed sign-in and an unknown app are dropped)", len(got))
	}
	a, b := got[0], got[1]
	if a.Identity.ExternalID != "EMP-2001" || a.Count != 2 || !a.Day.Equal(time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)) ||
		a.Permission.ExternalID != "app:"+spSaaS+":access" || a.Account.ExternalID != ada {
		t.Errorf("ada usage = %+v", a)
	}
	if b.Identity.ExternalID != "entra:"+ben || b.Count != 1 {
		t.Errorf("ben usage = %+v", b)
	}
	var q string
	for _, r := range f.srv.Requests() {
		if r.Path == "/v1.0/auditLogs/signIns" {
			q = r.Query
			break
		}
	}
	dec, _ := url.QueryUnescape(q)
	if !strings.Contains(dec, "createdDateTime ge "+now0.Add(-30*24*time.Hour).Format(time.RFC3339)) || !strings.Contains(dec, "status/errorCode eq 0") {
		t.Errorf("sign-in query = %q", dec)
	}
	f.status["/v1.0/auditLogs"] = 403
	n = 0
	if err := c.StreamEvents(ctx, nil, func(connectors.Event) error { n++; return nil }); err != nil || n != 0 {
		t.Fatalf("without AuditLog.Read.All: %v, %d events", err, n)
	}
}

func TestStreamEventsStopsWhenYieldFails(t *testing.T) {
	f := newFake(t)
	ms := &connsync.MemoryStore{}
	ctx := connsync.WithStore(context.Background(), ms)
	c := f.connector(baseCfg())
	if _, err := c.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	stop := errors.New("stop")
	if err := c.StreamEvents(ctx, nil, func(connectors.Event) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("err = %v", err)
	}
}

// ---------------------------------------------------------------- configuration

func TestTokenFailureDoesNotLeakTheSecret(t *testing.T) {
	f := newFake(t)
	f.status["/"+tenantGUID] = 401
	f.statusBody["/"+tenantGUID] = `{"error":"invalid_client","error_description":"client-secret-xyz is wrong"}`
	_, err := f.connector(baseCfg()).Discover(context.Background())
	if connsync.Status(err) != 401 {
		t.Fatalf("err = %v", err)
	}
	for _, leak := range []string{"client-secret-xyz", "is wrong"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error %q leaks %q", err, leak)
		}
	}
	if !strings.Contains(err.Error(), "invalid_client") {
		t.Errorf("error %q lacks the OAuth error code", err)
	}
}

func TestNewValidatesConfiguration(t *testing.T) {
	prod := connsync.Runtime{Env: "prod"}
	hc, err := connsync.NewHTTPClient(prod, safehttp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ok := baseCfg()
	with := func(mod func(*Config)) Config { c := ok; mod(&c); return c }
	tests := []struct {
		name string
		cfg  Config
		good bool
	}{
		{"defaults", ok, true},
		{"national cloud", with(func(c *Config) {
			c.GraphURL = "https://graph.microsoft.us"
			c.AuthorityURL = "https://login.microsoftonline.us"
		}), true},
		{"tenant is a domain", with(func(c *Config) { c.TenantID = "contoso.onmicrosoft.com" }), false},
		{"empty tenant", with(func(c *Config) { c.TenantID = "" }), false},
		{"no client id", with(func(c *Config) { c.ClientID = "" }), false},
		{"no secret", with(func(c *Config) { c.ClientSecret = connsync.Secret{} }), false},
		{"http graph", with(func(c *Config) { c.GraphURL = "http://graph.microsoft.com" }), false},
		{"http authority", with(func(c *Config) { c.AuthorityURL = "http://login.microsoftonline.com" }), false},
		{"private graph", with(func(c *Config) { c.GraphURL = "https://10.0.0.5" }), false},
		{"loopback authority in prod", with(func(c *Config) { c.AuthorityURL = "https://127.0.0.1:9" }), false},
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
	good := map[string]string{"TESSERA_ENV": "prod", "TESSERA_ENTRA_TENANT_ID": tenantGUID, "TESSERA_ENTRA_CLIENT_ID": "cid",
		"TESSERA_ENTRA_CLIENT_SECRET": "env:ENTRA_SECRET", "ENTRA_SECRET": "s3cret"}
	c, err := FromEnv(env(good), now0)
	if err != nil || c.System() != "entra" || c.TypeName() != "EntraConnector" || c.DisplayName() != "Microsoft Entra ID" {
		t.Fatalf("FromEnv = %v, %v", c, err)
	}
	cfg := c.(*Connector).cfg
	if !cfg.EmitIdentities || !cfg.SignInActivity || cfg.GraphURL != DefaultGraphURL || cfg.AuthorityURL != DefaultAuthorityURL {
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
		"literal secret":   mod("TESSERA_ENTRA_CLIENT_SECRET", "literal-secret"),
		"unset secret":     mod("TESSERA_ENTRA_CLIENT_SECRET", ""),
		"missing env":      mod("TESSERA_ENTRA_CLIENT_SECRET", "env:NOPE"),
		"bad tenant":       mod("TESSERA_ENTRA_TENANT_ID", "contoso"),
		"bad bool":         mod("TESSERA_ENTRA_SIGNIN_ACTIVITY", "sometimes"),
		"bad age":          mod("TESSERA_ENTRA_MAX_INCREMENTAL_AGE", "1s"),
		"http graph":       mod("TESSERA_ENTRA_GRAPH_URL", "http://graph.microsoft.com"),
		"loopback in prod": mod("TESSERA_OUTBOUND_ALLOW_LOOPBACK", "true"),
	} {
		_, err := FromEnv(env(m), now0)
		if name == "loopback in prod" {
			if err != nil {
				t.Errorf("%s: %v (the flag is ignored in prod, the defaults are valid)", name, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: FromEnv succeeded", name)
		} else if strings.Contains(err.Error(), "literal-secret") {
			t.Errorf("%s: error echoes the credential: %v", name, err)
		}
	}
	off := mod("TESSERA_ENTRA_SIGNIN_ACTIVITY", "false")
	off["TESSERA_ENTRA_EMIT_IDENTITIES"] = "false"
	off["TESSERA_ENTRA_MAX_INCREMENTAL_AGE"] = "12h"
	c, err = FromEnv(env(off), now0)
	if err != nil || c.(*Connector).cfg.SignInActivity || c.(*Connector).cfg.EmitIdentities || c.(*Connector).cfg.MaxIncrementalAge != 12*time.Hour {
		t.Fatalf("FromEnv(off) = %+v, %v", c, err)
	}
}

func TestReaderRole(t *testing.T) {
	for n, want := range map[string]bool{"Global Reader": true, "Directory Readers": true, "Security Reader": true,
		"Global Administrator": false, "Reader Of Things Administrator": false, "": false} {
		if readerRole(n) != want {
			t.Errorf("readerRole(%q) = %v", n, !want)
		}
	}
}
