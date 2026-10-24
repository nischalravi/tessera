package atlassian_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/atlassian"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/atlassian/atfake"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

var t0 = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)

const (
	email    = "tessera@acme.example"
	token    = "ATATT-api-token-secret"
	orgID    = "org-1234"
	adminKey = "admin-key-secret"

	uAda = "5b10ac8d82e05b22cc7d4ef5"
	uBo  = "5b10ac8d82e05b22cc7d4ef6"
	uApp = "5b10ac8d82e05b22cc7d4ef7"
	uOld = "5b10ac8d82e05b22cc7d4ef8"

	gDev   = "276f955c-63d7-42c8-9520-92d01dca0625"
	gAdmin = "6e87dc72-4f1f-421f-9382-2fee8b652487"
	gSite  = "6e87dc72-4f1f-421f-9382-2fee8b652488"
)

type rig struct {
	fake *atfake.Fake
	srv  *connsynctest.Server
	cfg  atlassian.Config
	open func(atlassian.Config) (*atlassian.Client, error)
}

func newRig(t *testing.T, withAdmin bool, projects ...string) *rig {
	t.Helper()
	fk := atfake.New(email, token, orgID, adminKey)
	fk.Users = []atfake.User{
		{AccountID: uAda, Type: "atlassian", Email: "Ada@Acme.example", Name: "Ada A", Active: true},
		{AccountID: uBo, Type: "atlassian", Name: "Bo B (email hidden)", Active: true},
		{AccountID: uApp, Type: "app", Name: "Bot", Active: true},
		{AccountID: uOld, Type: "atlassian", Email: "old@acme.example", Name: "Old", Active: false},
	}
	fk.Groups = []atfake.Group{{ID: gDev, Name: "developers"}, {ID: gAdmin, Name: "org-admins"}, {ID: gSite, Name: "site-admins"}}
	fk.Members = map[string][]string{gDev: {uAda, uBo}, gAdmin: {uAda}, gSite: {uOld, "5b10ac8d82e05b22cc7d4eff"}}
	fk.Access = map[string]string{gAdmin: "admin", gSite: "site-admin"}
	fk.Projects = map[string]map[string]*atfake.Role{"PROJ": {
		"10002": {Name: "Administrators", Admin: true, Users: []string{uBo}},
		"10003": {Name: "Developers", Users: []string{uAda}, Groups: []string{gDev}},
	}}
	fk.AdminUsers = []atfake.AdminUser{
		{AccountID: uAda, Email: "ada@acme.example", Status: "active", Products: []atfake.Product{{Key: "jira-software", Name: "Jira"}, {Key: "confluence", Name: "Confluence"}}},
		{AccountID: uBo, Email: "bo@acme.example", Status: "active", Products: []atfake.Product{{Key: "jira-software", Name: "Jira"}}},
		{AccountID: uOld, Status: "inactive"},
		{AccountID: "5b10ac8d82e05b22cc7d4e00", Status: "active", Products: []atfake.Product{{Key: "bitbucket", Name: "Bitbucket"}}}, // not on the site
	}
	srv := connsynctest.New(t, fk)
	hc, err := safehttp.NewForTest(t, srv.Options(0))
	if err != nil {
		t.Fatal(err)
	}
	cfg := atlassian.Config{BaseURL: srv.URL, Email: email, Token: connsync.NewSecret(token), ProjectKeys: projects}
	if withAdmin {
		cfg.OrgID, cfg.AdminKey, cfg.AdminURL = orgID, connsync.NewSecret(adminKey), srv.URL
	}
	return &rig{fk, srv, cfg, func(c atlassian.Config) (*atlassian.Client, error) {
		return atlassian.Open(c, connsynctest.Runtime, hc, func() time.Time { return t0 })
	}}
}

func (r *rig) client(t *testing.T) *atlassian.Client {
	t.Helper()
	c, err := r.open(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func edgeSet(res *connectors.DiscoveryResult) map[string]bool {
	out := map[string]bool{}
	for _, e := range res.Edges {
		out[e.Src.Kind+":"+e.Src.ExternalID+" -> "+e.Dst.ExternalID] = true
	}
	return out
}

func TestDiscover_SiteOnly(t *testing.T) {
	r := newRig(t, false, "PROJ")
	res, err := atlassian.NewConnector(r.client(t)).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	kind, priv, req := map[string]string{}, map[string]bool{}, map[string]bool{}
	for _, g := range res.Groups {
		kind[g.ExternalID], priv[g.ExternalID], req[g.ExternalID] = g.Kind, g.Privileged, g.Requestable
	}
	if len(kind) != 5 || kind[gDev] != atlassian.KindGroup || kind["PROJ/10002"] != atlassian.KindProjectRole {
		t.Errorf("groups = %v", kind)
	}
	if !priv[gAdmin] || !priv[gSite] || priv[gDev] || !priv["PROJ/10002"] || priv["PROJ/10003"] {
		t.Errorf("privileged = %v (groups the site lists as admin or site-admin, and a project's admin role)", priv)
	}
	if !req[gDev] || !req["PROJ/10003"] {
		t.Errorf("requestable = %v", req)
	}
	status, akind, user := map[string]string{}, map[string]string{}, map[string]string{}
	for _, a := range res.Accounts {
		status[a.ExternalID], akind[a.ExternalID], user[a.ExternalID] = a.Status, a.Kind, a.Username
		if a.ExternalID == uAda && (a.Identity == nil || a.Identity.Email != "ada@acme.example") {
			t.Errorf("ada identity = %+v", a.Identity)
		}
		if a.ExternalID == uBo && a.Identity != nil {
			t.Errorf("an account with a hidden e-mail has an identity: %+v", a.Identity)
		}
	}
	if status[uAda] != "active" || status[uOld] != "disabled" || akind[uApp] != "service" || akind[uAda] != "user" || user[uBo] != uBo || len(status) != 4 {
		t.Errorf("accounts = %v %v %v", status, akind, user)
	}
	edges := edgeSet(res)
	for _, want := range []string{
		"account:" + uAda + " -> " + gDev, "account:" + uBo + " -> " + gDev, "account:" + uAda + " -> " + gAdmin, "account:" + uOld + " -> " + gSite,
		"account:" + uBo + " -> PROJ/10002", "account:" + uAda + " -> PROJ/10003", "group:" + gDev + " -> PROJ/10003"} {
		if !edges[want] {
			t.Errorf("missing edge %s in %v", want, edges)
		}
	}
	if len(edges) != 7 {
		t.Errorf("edges = %v (an unknown member is not an edge)", edges)
	}
	if _, writes, admin := r.fake.Counts(); writes != 0 || admin != 0 {
		t.Errorf("writes %d admin reads %d", writes, admin)
	}
}

func TestDiscover_WithOrganizationAdminAPI(t *testing.T) {
	r := newRig(t, true)
	res, err := atlassian.NewConnector(r.client(t)).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	prod := map[string]string{}
	for _, g := range res.Groups {
		if g.Kind == atlassian.KindProduct {
			prod[g.ExternalID] = g.Name
			if g.Requestable {
				t.Errorf("product %s is requestable: access is granted through groups", g.ExternalID)
			}
		}
	}
	if len(prod) != 2 || prod["product:jira-software"] != "Jira" || prod["product:confluence"] != "Confluence" {
		t.Errorf("products = %v (a user the site does not list adds none)", prod)
	}
	edges := edgeSet(res)
	for _, want := range []string{"account:" + uAda + " -> product:jira-software", "account:" + uAda + " -> product:confluence", "account:" + uBo + " -> product:jira-software"} {
		if !edges[want] {
			t.Errorf("missing %s", want)
		}
	}
	for _, a := range res.Accounts {
		switch a.ExternalID {
		case uBo: // the profile hides it; the organization shows it
			if a.Identity == nil || a.Identity.Email != "bo@acme.example" {
				t.Errorf("bo identity = %+v", a.Identity)
			}
		case uOld:
			if a.Status != "disabled" {
				t.Errorf("old status = %s", a.Status)
			}
		}
	}
	if _, _, admin := r.fake.Counts(); admin == 0 {
		t.Error("the admin API was not read")
	}
}

func TestDiscover_Paging(t *testing.T) {
	for name, f := range map[string]atfake.Faults{"all pages": {}, "bad next link": {BadNext: true}} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, true)
			r.fake.PageSize = 1
			r.fake.SetFaults(f)
			res, err := atlassian.NewConnector(r.client(t)).Discover(context.Background())
			if f.BadNext {
				if err == nil || !strings.Contains(err.Error(), "leaves the organization users API") {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Accounts) != 4 || len(res.Groups) != 5 || !edgeSet(res)["account:"+uAda+" -> "+gDev] || !edgeSet(res)["account:"+uBo+" -> product:jira-software"] {
				t.Errorf("accounts %d groups %d edges %v", len(res.Accounts), len(res.Groups), edgeSet(res))
			}
		})
	}
}

func TestAuth(t *testing.T) {
	r := newRig(t, true)
	if _, err := atlassian.NewConnector(r.client(t)).Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, q := range r.srv.Requests() {
		want := "Basic "
		if strings.HasPrefix(q.Path, "/admin/") {
			want = "Bearer "
		}
		if !strings.HasPrefix(q.Authorization, want) {
			t.Errorf("%s carried %q", q.Path, q.Authorization)
		}
	}
	bad := r.cfg
	bad.Token = connsync.NewSecret("wrong-token-xyz")
	c, err := r.open(bad)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Probe(context.Background())
	if connsync.Status(err) != 401 || strings.Contains(err.Error(), "wrong-token-xyz") || strings.Contains(err.Error(), token) {
		t.Errorf("wrong token: %v", err)
	}
	if got := fmt.Sprintf("%v %+v", bad.Token, bad); strings.Contains(got, "wrong-token-xyz") {
		t.Errorf("the token prints: %s", got)
	}
	bad = r.cfg
	bad.AdminKey = connsync.NewSecret("wrong-admin-key")
	if c, err = r.open(bad); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Probe(context.Background()); connsync.Status(err) != 401 || strings.Contains(err.Error(), "wrong-admin-key") {
		t.Errorf("wrong admin key: %v", err)
	}
}

func TestFaults(t *testing.T) {
	for name, f := range map[string]atfake.Faults{"server error": {ReadStatus: 500}, "malformed": {Malformed: true}, "admin refused": {AdminStatus: 403}} {
		r := newRig(t, true)
		r.fake.SetFaults(f)
		if _, err := atlassian.NewConnector(r.client(t)).Discover(context.Background()); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	r := newRig(t, false)
	r.fake.SetFaults(atfake.Faults{Throttle: 1})
	if _, err := r.client(t).Probe(context.Background()); err != nil {
		t.Errorf("a 429 is retried: %v", err)
	}
	r = newRig(t, false, "NOPE")
	if _, err := atlassian.NewConnector(r.client(t)).Discover(context.Background()); err == nil || !strings.Contains(err.Error(), "NOPE") {
		t.Errorf("a project that does not exist: %v", err)
	}
}

func TestProbe(t *testing.T) {
	r := newRig(t, true)
	p, err := r.client(t).Probe(context.Background())
	if err != nil || p.Users != 4 || p.Groups != 3 || p.AdminUsers != 4 {
		t.Errorf("probe = %+v, %v", p, err)
	}
	c := r.client(t)
	if c.Mode() != "api_token" || c.Identity() != email || !c.HasAdmin() {
		t.Error("mode, identity or admin flag")
	}
	if p, err = newRig(t, false).client(t).Probe(context.Background()); err != nil || p.AdminUsers != 0 {
		t.Errorf("site-only probe = %+v, %v", p, err)
	}
}

func TestCheckURLs(t *testing.T) {
	prod := connsync.Runtime{Env: config.Prod}
	dev := connsync.Runtime{Env: config.Dev, AllowLoopback: true}
	for _, c := range []struct {
		raw string
		rt  connsync.Runtime
		ok  bool
	}{
		{"https://acme.atlassian.net", prod, true},
		{"https://acme.atlassian.net/", prod, true},
		{"https://ACME.ATLASSIAN.NET", prod, true},
		{"https://atlassian.net", prod, false},
		{"https://evil-atlassian.net", prod, false},
		{"https://acme.atlassian.net.evil.example", prod, false},
		{"https://acme.atlassian.com", prod, false},
		{"https://api.atlassian.com", prod, false}, // the admin API is not a site
		{"http://acme.atlassian.net", prod, false},
		{"https://u:p@acme.atlassian.net", prod, false},
		{"https://acme.atlassian.net#x", prod, false},
		{"https://127.0.0.1:9", prod, false},
		{"https://127.0.0.1:9", dev, true},
		{"https://127.0.0.1:9", connsync.Runtime{Env: config.Prod, AllowLoopback: true}, false},
		{"https://192.168.1.1", dev, false},
		{"https://example.com", dev, false},
	} {
		if _, err := atlassian.CheckSiteURL(c.raw, c.rt); (err == nil) != c.ok {
			t.Errorf("CheckSiteURL(%q, %v) = %v, want ok=%v", c.raw, c.rt, err, c.ok)
		}
	}
	for _, c := range []struct {
		raw string
		rt  connsync.Runtime
		ok  bool
	}{
		{"https://api.atlassian.com", prod, true},
		{"https://API.ATLASSIAN.COM", prod, true},
		{"https://api.atlassian.com/admin", prod, false},
		{"https://api.atlassian.com.evil.example", prod, false},
		{"https://acme.atlassian.net", prod, false},
		{"https://auth.atlassian.com", prod, false},
		{"http://api.atlassian.com", prod, false},
		{"https://127.0.0.1:9", prod, false},
		{"https://127.0.0.1:9", dev, true},
		{"https://127.0.0.1:9", connsync.Runtime{Env: config.Prod, AllowLoopback: true}, false},
	} {
		if _, err := atlassian.CheckAdminURL(c.raw, c.rt); (err == nil) != c.ok {
			t.Errorf("CheckAdminURL(%q, %v) = %v, want ok=%v", c.raw, c.rt, err, c.ok)
		}
	}
}

func TestOpenValidation(t *testing.T) {
	prod := connsync.Runtime{Env: config.Prod}
	hc, _ := safehttp.NewForTest(t, connsynctest.New(t, atfake.New("a@b.c", "t", "", "")).Options(0))
	good := atlassian.Config{BaseURL: "https://acme.atlassian.net", Email: email, Token: connsync.NewSecret(token)}
	if _, err := atlassian.Open(good, prod, nil, nil); err == nil {
		t.Error("a nil safehttp client was accepted")
	}
	for name, mut := range map[string]func(*atlassian.Config){
		"no token":        func(c *atlassian.Config) { c.Token = connsync.NewSecret("") },
		"no email":        func(c *atlassian.Config) { c.Email = "" },
		"not an email":    func(c *atlassian.Config) { c.Email = "tessera" },
		"a path":          func(c *atlassian.Config) { c.BaseURL = "https://acme.atlassian.net/wiki" },
		"other host":      func(c *atlassian.Config) { c.BaseURL = "https://acme.example.com" },
		"org without key": func(c *atlassian.Config) { c.OrgID = orgID },
		"key without org": func(c *atlassian.Config) { c.AdminKey = connsync.NewSecret("k") },
		"bad org id":      func(c *atlassian.Config) { c.OrgID, c.AdminKey = "a/b", connsync.NewSecret("k") },
		"other admin host": func(c *atlassian.Config) {
			c.OrgID, c.AdminKey, c.AdminURL = orgID, connsync.NewSecret("k"), "https://evil.example.com"
		},
		"bad project key":   func(c *atlassian.Config) { c.ProjectKeys = []string{"A/../B"} },
		"too many projects": func(c *atlassian.Config) { c.ProjectKeys = make([]string, atlassian.MaxProjects+1) },
	} {
		c := good
		mut(&c)
		if _, err := atlassian.Open(c, prod, hc, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	withAdmin := good
	withAdmin.OrgID, withAdmin.AdminKey, withAdmin.ProjectKeys = orgID, connsync.NewSecret("k"), []string{"PROJ", "OPS_1"}
	if _, err := atlassian.Open(withAdmin, prod, hc, nil); err != nil {
		t.Errorf("good config: %v", err)
	}
	if !atlassian.IsProjectKey("PROJ") || atlassian.IsProjectKey("a b") || !atlassian.IsOrgID("abc-123") || atlassian.IsOrgID("a b") {
		t.Error("setting predicates")
	}
}

func TestParseCredential(t *testing.T) {
	if tok, adm, err := atlassian.ParseCredential("  ATATTplain  "); err != nil || tok != "ATATTplain" || adm != "" {
		t.Errorf("plain = %q %q %v", tok, adm, err)
	}
	if tok, adm, err := atlassian.ParseCredential(`{"api_token":"t","admin_api_key":"k"}`); err != nil || tok != "t" || adm != "k" {
		t.Errorf("json = %q %q %v", tok, adm, err)
	}
	if tok, adm, err := atlassian.ParseCredential(`{"api_token":"t"}`); err != nil || tok != "t" || adm != "" {
		t.Errorf("json without admin = %q %q %v", tok, adm, err)
	}
	for _, b := range []string{"", "a b", "a\nb", `{"admin_api_key":"k"}`, `{"api_token":"t","extra":1}`, `{"api_token":"a b"}`, `{`, strings.Repeat("x", 9000)} {
		if _, _, err := atlassian.ParseCredential(b); err == nil {
			t.Errorf("%.40q accepted", b)
		} else if strings.Contains(err.Error(), "admin_api_key\":\"k") {
			t.Errorf("the error repeats the credential: %v", err)
		}
	}
	for _, b := range []string{"", "not json", `{"email":"a@b.c"}`, `{"email":"nope","api_token":"t"}`, `{"email":"a@b.c","api_token":"t x"}`, `{"email":"a@b.c","api_token":"t","extra":1}`} {
		if _, err := atlassian.ParseTargetCredential(b); err == nil {
			t.Errorf("target credential %q accepted", b)
		}
	}
	if c, err := atlassian.ParseTargetCredential(`{"email":"a@b.c","api_token":"t"}`); err != nil || c.Email != "a@b.c" {
		t.Errorf("target credential: %v", err)
	}
}

func TestConfigFromEnv(t *testing.T) {
	env := map[string]string{"TESSERA_ATLASSIAN_BASE_URL": "https://acme.atlassian.net", "TESSERA_ATLASSIAN_EMAIL": email, "TESSERA_ATLASSIAN_CREDENTIAL": "env:AT_CRED",
		"AT_CRED": `{"api_token":"tok","admin_api_key":"adm"}`, "TESSERA_ATLASSIAN_ORG_ID": orgID, "TESSERA_ATLASSIAN_PROJECTS": "PROJ, OPS"}
	get := func(k string) string { return env[k] }
	cfg, err := atlassian.ConfigFromEnv(get)
	if err != nil || cfg.Token.Reveal() != "tok" || cfg.AdminKey.Reveal() != "adm" || cfg.OrgID != orgID || len(cfg.ProjectKeys) != 2 || cfg.ProjectKeys[1] != "OPS" {
		t.Errorf("cfg = %+v %v", cfg, err)
	}
	env["TESSERA_ATLASSIAN_CREDENTIAL"] = "literal-token"
	if _, err = atlassian.ConfigFromEnv(get); err == nil || strings.Contains(err.Error(), "literal-token") {
		t.Errorf("literal credential: %v", err)
	}
	env["TESSERA_ATLASSIAN_CREDENTIAL"], env["AT_CRED"] = "env:AT_CRED", "a b"
	if _, err = atlassian.ConfigFromEnv(get); err == nil {
		t.Error("a malformed credential was accepted")
	}
	env["AT_CRED"] = "tok"
	hc, _ := safehttp.NewForTest(t, connsynctest.New(t, atfake.New("a@b.c", "t", "", "")).Options(0))
	env["TESSERA_ATLASSIAN_ORG_ID"] = ""
	if c, err := atlassian.FromEnv(get, connsync.Runtime{Env: config.Prod}, hc, nil); err != nil || c.System() != "atlassian" || c.DisplayName() == "" || c.TypeName() == "" {
		t.Errorf("FromEnv = %v %v", c, err)
	}
	env["TESSERA_ATLASSIAN_BASE_URL"] = "https://evil.example.com"
	if _, err := atlassian.FromEnv(get, connsync.Runtime{Env: config.Prod}, hc, nil); err == nil {
		t.Error("a host outside the allow-list was accepted")
	}
	// the dev override of the admin API is refused outside the dev loopback exception
	env["TESSERA_ATLASSIAN_BASE_URL"], env["TESSERA_ATLASSIAN_ORG_ID"] = "https://acme.atlassian.net", orgID
	env["AT_CRED"], env["TESSERA_ATLASSIAN_ADMIN_URL"] = `{"api_token":"t","admin_api_key":"k"}`, "https://127.0.0.1:9"
	if _, err := atlassian.FromEnv(get, connsync.Runtime{Env: config.Prod, AllowLoopback: true}, hc, nil); err == nil {
		t.Error("prod accepted the admin API override")
	}
}

// ---------------------------------------------------------------- the provisioning target

func newTarget(t *testing.T) (*atlassian.Target, *rig) {
	t.Helper()
	r := newRig(t, false, "PROJ")
	return &atlassian.Target{C: r.client(t)}, r
}

func byID(id string) target.Account { return target.Account{ExternalID: id, Username: "ignored"} }

func apply(t *testing.T, tg *atlassian.Target, req target.Request) target.Verdict {
	t.Helper()
	if err := tg.Apply(context.Background(), req); err != nil {
		t.Fatalf("apply %s: %v", req.Kind, err)
	}
	v, err := tg.Verify(context.Background(), req)
	if err != nil {
		t.Fatalf("verify %s: %v", req.Kind, err)
	}
	return v
}

func TestTarget_GroupMembership(t *testing.T) {
	tg, r := newTarget(t)
	ctx := context.Background()
	add := target.Request{Kind: target.AddEntitlement, Key: "a1", Account: byID(uOld + ""), Group: target.Group{ExternalID: gDev}}
	// uOld is inactive: Atlassian refuses it
	if err := tg.Apply(ctx, add); err == nil {
		t.Error("an inactive user was added")
	}
	add.Account = byID(uApp)
	if v := apply(t, tg, add); !v.OK || len(r.fake.MembersOf(gDev)) != 3 {
		t.Fatalf("add: %+v %v", v, r.fake.MembersOf(gDev))
	}
	_, _, _ = r.fake.Counts()
	if err := tg.Apply(ctx, add); err != nil || len(r.fake.MembersOf(gDev)) != 3 {
		t.Errorf("a repeated add: %v %v", err, r.fake.MembersOf(gDev))
	}
	rm := target.Request{Kind: target.RemoveEntitlement, Key: "a2", Account: byID(uApp), Group: target.Group{ExternalID: gDev}}
	if v := apply(t, tg, rm); !v.OK || len(r.fake.MembersOf(gDev)) != 2 {
		t.Fatalf("remove: %+v %v", v, r.fake.MembersOf(gDev))
	}
	_, w0, _ := r.fake.Counts()
	if err := tg.Apply(ctx, rm); err != nil {
		t.Fatal(err)
	}
	if _, w1, _ := r.fake.Counts(); w1 != w0 {
		t.Errorf("a repeated removal wrote again")
	}
	// by e-mail: an exact match of the e-mail the profile shows
	byMail := target.Request{Kind: target.AddEntitlement, Account: target.Account{Username: "ada@acme.example"}, Group: target.Group{ExternalID: gSite}}
	if v := apply(t, tg, byMail); !v.OK {
		t.Errorf("by e-mail: %+v", v)
	}
	// a user whose e-mail the profile hides cannot be found by it
	err := tg.Apply(ctx, target.Request{Kind: target.AddEntitlement, Account: target.Account{Username: "bo@acme.example"}, Group: target.Group{ExternalID: gDev}})
	var te *target.Error
	if !errors.As(err, &te) || te.Retryable {
		t.Errorf("a hidden e-mail: %v", err)
	}
	if err := tg.Apply(ctx, target.Request{Kind: target.RemoveEntitlement, Account: target.Account{Username: "ghost@acme.example"}, Group: target.Group{ExternalID: gDev}}); err != nil {
		t.Errorf("remove from a missing user: %v", err)
	}
	// a group that does not exist
	err = tg.Apply(ctx, target.Request{Kind: target.AddEntitlement, Account: byID(uAda), Group: target.Group{ExternalID: "00000000-0000-0000-0000-000000000000"}})
	if err == nil {
		t.Error("a missing group")
	}
}

func TestTarget_ProjectRoles(t *testing.T) {
	tg, r := newTarget(t)
	add := target.Request{Kind: target.AddEntitlement, Key: "r1", Account: byID(uApp), Group: target.Group{ExternalID: "PROJ/10003"}}
	if v := apply(t, tg, add); !v.OK || len(r.fake.RoleOf("PROJ", "10003").Users) != 2 {
		t.Fatalf("add role: %+v %+v", v, r.fake.RoleOf("PROJ", "10003"))
	}
	if err := tg.Apply(context.Background(), add); err != nil || len(r.fake.RoleOf("PROJ", "10003").Users) != 2 {
		t.Errorf("a repeated add: %v", err)
	}
	rm := target.Request{Kind: target.RemoveEntitlement, Key: "r2", Account: byID(uApp), Group: target.Group{ExternalID: "PROJ/10003"}}
	if v := apply(t, tg, rm); !v.OK || len(r.fake.RoleOf("PROJ", "10003").Users) != 1 {
		t.Fatalf("remove role: %+v %+v", v, r.fake.RoleOf("PROJ", "10003"))
	}
	err := tg.Apply(context.Background(), target.Request{Kind: target.AddEntitlement, Account: byID(uApp), Group: target.Group{ExternalID: "PROJ/99999"}})
	var te *target.Error
	if !errors.As(err, &te) || te.Retryable {
		t.Errorf("a missing role: %v", err)
	}
}

func TestTarget_AccountLifecycleIsSCIM(t *testing.T) {
	tg, r := newTarget(t)
	before := len(r.srv.Requests())
	for _, k := range []string{target.CreateAccount, target.UpdateAccount, target.DisableAccount, target.DeleteAccount, "nuke"} {
		req := target.Request{Kind: k, Account: byID(uAda)}
		err := tg.Apply(context.Background(), req)
		var te *target.Error
		if !errors.As(err, &te) || te.Retryable {
			t.Errorf("%s: %v", k, err)
		} else if k != "nuke" && !strings.Contains(te.Msg, "SCIM") {
			t.Errorf("%s: the error does not point at the SCIM target: %v", k, te.Msg)
		}
		if _, err := tg.Verify(context.Background(), req); err == nil {
			t.Errorf("verify %s: no error", k)
		}
	}
	if len(r.srv.Requests()) != before {
		t.Error("an account lifecycle operation reached the site")
	}
}

func TestTarget_RefusesUnsafeReferences(t *testing.T) {
	tg, r := newTarget(t)
	before := len(r.srv.Requests())
	for _, g := range []string{"", "a/b/c", "../x", "PROJ/12a", "PROJ/", "/10003", "1PROJ/10003", "a b", "g?x=1", "g&groupId=other", strings.Repeat("a", 65), "PROJ/../10003"} {
		for _, k := range []string{target.AddEntitlement, target.RemoveEntitlement} {
			req := target.Request{Kind: k, Account: byID(uAda), Group: target.Group{ExternalID: g}}
			err := tg.Apply(context.Background(), req)
			var te *target.Error
			if !errors.As(err, &te) || te.Retryable {
				t.Errorf("%s %q: %v", k, g, err)
			}
			if _, err := tg.Verify(context.Background(), req); err == nil {
				t.Errorf("verify %q: no error", g)
			}
		}
	}
	for _, a := range []target.Account{{Username: "no-at-sign"}, {Username: ""}, {Username: "a b@c"}, {ExternalID: "bad id", Username: "x"}} {
		if err := tg.Apply(context.Background(), target.Request{Kind: target.AddEntitlement, Account: a, Group: target.Group{ExternalID: gDev}}); err == nil {
			t.Errorf("account %+v accepted", a)
		}
	}
	if len(r.srv.Requests()) != before {
		t.Errorf("a refused reference reached the site: %v", r.srv.Requests()[before:])
	}
}

func TestTarget_DroppedAndRefusedWrites(t *testing.T) {
	tg, r := newTarget(t)
	r.fake.SetFaults(atfake.Faults{DropWrites: true})
	if v := apply(t, tg, target.Request{Kind: target.AddEntitlement, Account: byID(uApp), Group: target.Group{ExternalID: gDev}}); v.OK {
		t.Errorf("a dropped write was verified: %+v", v)
	}
	r.fake.SetFaults(atfake.Faults{WriteStatus: 403})
	err := tg.Apply(context.Background(), target.Request{Kind: target.AddEntitlement, Account: byID(uApp), Group: target.Group{ExternalID: gAdmin}})
	var te *target.Error
	if !errors.As(err, &te) || te.Status != 403 || strings.Contains(te.Msg, token) {
		t.Errorf("a refused write: %v", err)
	}
	r.fake.SetFaults(atfake.Faults{WriteStatus: 500})
	if err := tg.Apply(context.Background(), target.Request{Kind: target.AddEntitlement, Account: byID(uApp), Group: target.Group{ExternalID: gAdmin}}); err == nil || !target.Retryable(err) {
		t.Errorf("a 500 is retryable: %v", err)
	}
}

func TestTarget_OpenTarget(t *testing.T) {
	r := newRig(t, false)
	hc, _ := safehttp.NewForTest(t, r.srv.Options(0))
	cred, err := atlassian.ParseTargetCredential(`{"email":"` + email + `","api_token":"` + token + `"}`)
	if err != nil {
		t.Fatal(err)
	}
	tg, err := atlassian.OpenTarget(r.srv.URL, cred, connsynctest.Runtime, hc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if v := apply(t, tg, target.Request{Kind: target.AddEntitlement, Account: byID(uApp), Group: target.Group{ExternalID: gDev}}); !v.OK {
		t.Errorf("%+v", v)
	}
	if _, err := atlassian.OpenTarget("https://evil.example.com", cred, connsync.Runtime{Env: config.Prod}, hc, nil); err == nil {
		t.Error("a host outside the allow-list was opened")
	}
}
