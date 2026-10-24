package servicenow_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/servicenow"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/servicenow/snfake"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

var t0 = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)

const (
	apiUser = "tessera.integration"
	apiPass = "pw-basic-secret-1"
	cliID   = "client-id-1"
	cliSec  = "client-secret-1"

	uAda   = "6816f79cc0a8016401c5a33be04be441"
	uBo    = "6816f79cc0a8016401c5a33be04be442"
	uSvc   = "6816f79cc0a8016401c5a33be04be443"
	gNet   = "0000000000000000000000000000a001"
	gApps  = "0000000000000000000000000000a002"
	rItil  = "0000000000000000000000000000b001"
	rAdmin = "0000000000000000000000000000b002"
	rSec   = "0000000000000000000000000000b003"
	rElev  = "0000000000000000000000000000b004"
)

type rig struct {
	fake *snfake.Fake
	srv  *connsynctest.Server
	hc   func() (*servicenow.Client, error)
	cfg  servicenow.Config
}

func newRig(t *testing.T, mode string) *rig {
	t.Helper()
	fk := snfake.New(apiUser, apiPass, cliID, cliSec)
	fk.Set("sys_user",
		snfake.Row{"sys_id": uAda, "user_name": "ada@acme.example", "email": "Ada@Acme.example", "name": "Ada A", "active": "true", "locked_out": "false", "employee_number": "E1", "title": "SRE", "last_login_time": "2026-10-01 08:00:00", "sys_created_on": "2025-01-02 03:04:05", "web_service_access_only": "false"},
		snfake.Row{"sys_id": uBo, "user_name": "bo", "email": "bo@acme.example", "active": "true", "locked_out": "true", "web_service_access_only": "false"},
		snfake.Row{"sys_id": uSvc, "user_name": "svc.integration", "active": "false", "web_service_access_only": "true"})
	fk.Set("sys_user_group", snfake.Row{"sys_id": gNet, "name": "Network", "description": "net team", "active": "true"}, snfake.Row{"sys_id": gApps, "name": "Apps", "active": "true"})
	fk.Set("sys_user_role",
		snfake.Row{"sys_id": rItil, "name": "itil", "elevated_privilege": "false"},
		snfake.Row{"sys_id": rAdmin, "name": "admin"},
		snfake.Row{"sys_id": rSec, "name": "security_admin"},
		snfake.Row{"sys_id": rElev, "name": "approver_user", "elevated_privilege": "true"})
	fk.Set("sys_user_grmember",
		snfake.Row{"sys_id": "m1", "user": uAda, "group": gNet}, snfake.Row{"sys_id": "m2", "user": uBo, "group": gApps},
		snfake.Row{"sys_id": "m3", "user": "ffffffffffffffffffffffffffffffff", "group": gApps}) // a user the read did not return
	fk.Set("sys_user_has_role",
		snfake.Row{"sys_id": "h1", "user": uAda, "role": rItil, "inherited": "false", "state": "active"},
		snfake.Row{"sys_id": "h2", "user": uBo, "role": rAdmin, "inherited": "true", "state": "active"},
		snfake.Row{"sys_id": "h3", "user": uBo, "role": rSec, "inherited": "false", "state": "inactive"},
		snfake.Row{"sys_id": "h4", "user": uAda, "role": rElev, "inherited": "false", "expires": "2026-09-01 00:00:00"}, // expired
		snfake.Row{"sys_id": "h5", "user": uAda, "role": rElev, "inherited": "false", "state": "active", "expires": "2027-01-01 00:00:00"})
	srv := connsynctest.New(t, fk)
	hc, err := safehttp.NewForTest(t, srv.Options(0))
	if err != nil {
		t.Fatal(err)
	}
	cfg := servicenow.Config{BaseURL: srv.URL, AuthMode: mode, Username: apiUser, Secret: connsync.NewSecret(apiPass)}
	if mode == servicenow.AuthOAuth {
		cfg.Username, cfg.Secret = cliID, connsync.NewSecret(cliSec)
	}
	return &rig{fk, srv, func() (*servicenow.Client, error) {
		return servicenow.Open(cfg, connsynctest.Runtime, hc, func() time.Time { return t0 })
	}, cfg}
}

func (r *rig) client(t *testing.T) *servicenow.Client {
	t.Helper()
	c, err := r.hc()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func edgeSet(res *connectors.DiscoveryResult) map[string]bool {
	out := map[string]bool{}
	for _, e := range res.Edges {
		out[e.Src.ExternalID+" -> "+e.Dst.ExternalID] = true
	}
	return out
}

func TestDiscover(t *testing.T) {
	for _, mode := range []string{servicenow.AuthBasic, servicenow.AuthOAuth} {
		t.Run(mode, func(t *testing.T) {
			r := newRig(t, mode)
			res, err := servicenow.NewConnector(r.client(t), func() time.Time { return t0 }).Discover(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			kind, priv := map[string]string{}, map[string]bool{}
			for _, g := range res.Groups {
				kind[g.ExternalID], priv[g.ExternalID] = g.Kind, g.Privileged
			}
			if len(kind) != 6 || kind[gNet] != servicenow.KindGroup || kind[rItil] != servicenow.KindRole {
				t.Errorf("groups = %v", kind)
			}
			if !priv[rAdmin] || !priv[rSec] || !priv[rElev] || priv[rItil] || priv[gNet] {
				t.Errorf("privileged = %v (admin, security_admin and an elevated-privilege role are privileged)", priv)
			}
			status, akind := map[string]string{}, map[string]string{}
			for _, a := range res.Accounts {
				status[a.ExternalID], akind[a.ExternalID] = a.Status, a.Kind
			}
			if status[uAda] != "active" || status[uBo] != "disabled" || status[uSvc] != "disabled" || akind[uSvc] != "service" || akind[uAda] != "user" {
				t.Errorf("accounts = %v %v", status, akind)
			}
			for _, a := range res.Accounts {
				if a.ExternalID == uAda {
					if a.Identity == nil || a.Identity.Email != "ada@acme.example" || a.LastLoginAt == nil || !a.LastLoginAt.Equal(time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)) || a.Attributes["employee_number"] != "E1" {
						t.Errorf("ada = %+v", a)
					}
				}
			}
			edges := edgeSet(res)
			for _, want := range []string{uAda + " -> " + gNet, uBo + " -> " + gApps, uAda + " -> " + rItil, uBo + " -> " + rAdmin, uAda + " -> " + rElev} {
				if !edges[want] {
					t.Errorf("missing edge %s in %v", want, edges)
				}
			}
			if len(edges) != 5 {
				t.Errorf("edges = %v (an inactive role, an expired one and a member the read did not return are not edges)", edges)
			}
			_, reads, writes := r.fake.Counts()
			if reads == 0 || writes != 0 {
				t.Errorf("reads %d writes %d", reads, writes)
			}
			if mode == servicenow.AuthOAuth {
				if tokens, _, _ := r.fake.Counts(); tokens != 1 {
					t.Errorf("token requests = %d, want one for the whole read", tokens)
				}
			}
		})
	}
}

func TestAuthHeaders(t *testing.T) {
	r := newRig(t, servicenow.AuthBasic)
	if _, err := servicenow.NewConnector(r.client(t), nil).Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, q := range r.srv.Requests() {
		if !strings.HasPrefix(q.Authorization, "Basic ") {
			t.Fatalf("request %s %s carried %q", q.Method, q.Path, q.Authorization)
		}
	}
	o := newRig(t, servicenow.AuthOAuth)
	if _, err := servicenow.NewConnector(o.client(t), nil).Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, q := range o.srv.Requests() {
		if q.Path != "/oauth_token.do" && q.Authorization != "Bearer tok-sn-fake" {
			t.Fatalf("request %s %s carried %q", q.Method, q.Path, q.Authorization)
		}
	}
}

func TestOAuthTokenExpiryAndRefusal(t *testing.T) {
	r := newRig(t, servicenow.AuthOAuth)
	r.fake.SetFaults(snfake.Faults{Unauthorized: 1}) // an expired session: the token is dropped and fetched again
	if _, err := r.client(t).Probe(context.Background()); err != nil {
		t.Fatalf("probe after a 401: %v", err)
	}
	if tokens, _, _ := r.fake.Counts(); tokens != 2 {
		t.Errorf("token requests = %d, want 2 (one dropped by the 401)", tokens)
	}
	r.fake.SetFaults(snfake.Faults{TokenStatus: 401})
	_, err := r.client(t).Probe(context.Background())
	if err == nil {
		t.Fatal("a refused token was accepted")
	}
	if strings.Contains(err.Error(), cliSec) || strings.Contains(err.Error(), cliID) {
		t.Errorf("the error repeats a credential: %v", err)
	}
	// a wrong secret
	cfg := r.cfg
	cfg.Secret = connsync.NewSecret("wrong-secret-xyz")
	hc, _ := safehttp.NewForTest(t, r.srv.Options(0))
	r.fake.SetFaults(snfake.Faults{})
	c, err := servicenow.Open(cfg, connsynctest.Runtime, hc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Probe(context.Background()); err == nil || strings.Contains(err.Error(), "wrong-secret-xyz") {
		t.Errorf("wrong secret: %v", err)
	}
	if got := fmt.Sprintf("%v %+v %#v", cfg.Secret, cfg, cfg.Secret); strings.Contains(got, "wrong-secret-xyz") {
		t.Errorf("the secret prints: %s", got)
	}
}

func TestBasicRefused(t *testing.T) {
	r := newRig(t, servicenow.AuthBasic)
	cfg := r.cfg
	cfg.Secret = connsync.NewSecret("nope")
	hc, _ := safehttp.NewForTest(t, r.srv.Options(0))
	c, err := servicenow.Open(cfg, connsynctest.Runtime, hc, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Probe(context.Background())
	if connsync.Status(err) != 401 {
		t.Errorf("err = %v", err)
	}
}

func TestPaging(t *testing.T) {
	many := make([]snfake.Row, 0, 1250)
	for i := 0; i < 1250; i++ {
		many = append(many, snfake.Row{"sys_id": fmt.Sprintf("%032x", i+1), "user_name": fmt.Sprintf("u%d", i), "active": "true"})
	}
	for name, f := range map[string]struct {
		faults     snfake.Faults
		short      int
		pageSize   int
		wantErr    bool
		wantAtLeas int
	}{
		"link header":                   {pageSize: 500},
		"offset paging without a link":  {faults: snfake.Faults{NoLink: true}, pageSize: 500},
		"short pages while more remain": {short: 100, pageSize: 500},
		"short pages, no link":          {faults: snfake.Faults{NoLink: true}, short: 100, pageSize: 500},
		"link to another host":          {faults: snfake.Faults{BadLink: true}, pageSize: 500, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, servicenow.AuthBasic)
			r.fake.Set("sys_user", many...)
			r.fake.PageSize, r.fake.ShortPage = f.pageSize, f.short
			r.fake.SetFaults(f.faults)
			res, err := servicenow.NewConnector(r.client(t), nil).Discover(context.Background())
			if f.wantErr {
				if err == nil || !strings.Contains(err.Error(), "leaves the Table API") {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Accounts) != 1250 {
				t.Errorf("accounts = %d, want 1250", len(res.Accounts))
			}
		})
	}
}

func TestReadFaults(t *testing.T) {
	for name, f := range map[string]snfake.Faults{"server error": {ReadStatus: 500}, "malformed": {Malformed: true}} {
		r := newRig(t, servicenow.AuthBasic)
		r.fake.SetFaults(f)
		if _, err := servicenow.NewConnector(r.client(t), nil).Discover(context.Background()); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	r := newRig(t, servicenow.AuthBasic)
	r.fake.SetFaults(snfake.Faults{Throttle: 1})
	if _, err := r.client(t).Probe(context.Background()); err != nil {
		t.Errorf("a 429 is retried: %v", err)
	}
}

func TestProbe(t *testing.T) {
	r := newRig(t, servicenow.AuthBasic)
	p, err := r.client(t).Probe(context.Background())
	if err != nil || p.Users != 3 || p.Groups != 2 || p.Roles != 4 || p.Assignments != 5 {
		t.Errorf("probe = %+v, %v", p, err)
	}
	if r.client(t).Mode() != "basic" || r.client(t).Identity() != apiUser {
		t.Error("mode or identity")
	}
}

func TestCheckURL(t *testing.T) {
	prod := connsync.Runtime{Env: config.Prod}
	dev := connsync.Runtime{Env: config.Dev, AllowLoopback: true}
	for _, c := range []struct {
		raw string
		rt  connsync.Runtime
		ok  bool
	}{
		{"https://acme.service-now.com", prod, true},
		{"https://acme-dev.service-now.com/", prod, true},
		{"https://agency.servicenowservices.com", prod, true},
		{"https://ACME.SERVICE-NOW.COM", prod, true},
		{"https://service-now.com", prod, false},
		{"https://evil-service-now.com", prod, false},
		{"https://acme.service-now.com.evil.example", prod, false},
		{"https://service-now.com.evil.example", prod, false},
		{"https://acme.servicenow.com", prod, false},
		{"https://acme.example.com", prod, false},
		{"http://acme.service-now.com", prod, false},
		{"https://user:pw@acme.service-now.com", prod, false},
		{"https://acme.service-now.com?x=1", prod, false},
		{"https://127.0.0.1:8443", prod, false},
		{"https://127.0.0.1:8443", dev, true},
		{"http://127.0.0.1:8443", dev, true},
		{"https://127.0.0.1:8443", connsync.Runtime{Env: config.Prod, AllowLoopback: true}, false}, // prod refuses the override even when set
		{"https://10.0.0.5", dev, false},
		{"https://evil.example.com", dev, false},
		{"", prod, false},
	} {
		_, err := servicenow.CheckURL(c.raw, c.rt)
		if (err == nil) != c.ok {
			t.Errorf("CheckURL(%q, %v) = %v, want ok=%v", c.raw, c.rt, err, c.ok)
		}
	}
	hc, _ := safehttp.NewForTest(t, connsynctest.New(t, snfake.New("a", "b", "", "")).Options(0))
	if _, err := servicenow.Open(servicenow.Config{BaseURL: "https://acme.service-now.com/path", Username: "u", Secret: connsync.NewSecret("s")}, connsync.Runtime{Env: config.Prod}, hc, nil); err == nil {
		t.Error("a base URL with a path was accepted")
	}
}

func TestOpenValidation(t *testing.T) {
	prod := connsync.Runtime{Env: config.Prod}
	hc, _ := safehttp.NewForTest(t, connsynctest.New(t, snfake.New("a", "b", "", "")).Options(0))
	good := servicenow.Config{BaseURL: "https://acme.service-now.com", Username: "svc", Secret: connsync.NewSecret("s")}
	if _, err := servicenow.Open(good, prod, nil, nil); err == nil {
		t.Error("a nil safehttp client was accepted")
	}
	for name, mut := range map[string]func(*servicenow.Config){
		"no secret":   func(c *servicenow.Config) { c.Secret = connsync.NewSecret("") },
		"no user":     func(c *servicenow.Config) { c.Username = "" },
		"space user":  func(c *servicenow.Config) { c.Username = "a b" },
		"unknown way": func(c *servicenow.Config) { c.AuthMode = "saml" },
	} {
		c := good
		mut(&c)
		if _, err := servicenow.Open(c, prod, hc, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := servicenow.Open(good, prod, hc, nil); err != nil {
		t.Errorf("good config: %v", err)
	}
}

func TestValueAllowList(t *testing.T) {
	for _, v := range []string{"ada", "ada@acme.example", "o'brien", "first last", "a_b-c+d.e", "ünal", "user1"} {
		if _, err := servicenow.Value(v); err != nil {
			t.Errorf("Value(%q) refused: %v", v, err)
		}
	}
	for _, v := range []string{"", "a^b", "a^ORactive=true", "x^NQy", "javascript:gs.getUserID()", "dynamic:abc", "a=b", "a\nb", "a\x00", "(a)", "ab^", "^", strings.Repeat("a", 201), " lead", "x y"} {
		if _, err := servicenow.Value(v); err == nil {
			t.Errorf("Value(%q) accepted", v)
		} else if strings.Contains(err.Error(), "javascript") {
			t.Errorf("the error quotes the value: %v", err)
		}
	}
	if _, err := servicenow.SysID(uAda); err != nil {
		t.Error(err)
	}
	for _, v := range []string{"", "xyz", strings.ToUpper(uAda), uAda + "^", uAda[:31]} {
		if _, err := servicenow.SysID(v); err == nil {
			t.Errorf("SysID(%q) accepted", v)
		}
	}
}

func TestParseCredential(t *testing.T) {
	good := []string{
		`{"auth":"basic","username":"svc","password":"pw"}`,
		`{"auth":"oauth","client_id":"id","client_secret":"sec"}`,
		`{"auth":"basic","username":"svc","password":"pw","mode":"ticket","assignment_group":"` + gNet + `"}`,
		`{"auth":"oauth","client_id":"id","client_secret":"sec","mode":"direct"}`,
	}
	for _, g := range good {
		if _, err := servicenow.ParseCredential(g); err != nil {
			t.Errorf("%s: %v", g, err)
		}
	}
	for _, b := range []string{"", "not json", `{"auth":"basic"}`, `{"auth":"basic","username":"svc"}`, `{"auth":"basic","username":"svc","password":"pw","client_id":"x"}`,
		`{"auth":"oauth","client_id":"id"}`, `{"auth":"oauth","client_id":"id","client_secret":"s","username":"u"}`, `{"auth":"saml"}`,
		`{"auth":"basic","username":"svc","password":"pw","mode":"weird"}`, `{"auth":"basic","username":"svc","password":"pw","mode":"ticket","assignment_group":"not-an-id"}`,
		`{"auth":"basic","username":"svc","password":"pw","assignment_group":"` + gNet + `"}`, `{"auth":"basic","username":"svc","password":"pw","extra":1}`,
		`{"auth":"basic","username":"a b","password":"pw"}`, `{"auth":"basic","username":"svc","password":"` + strings.Repeat("p", 9000) + `"}`} {
		_, err := servicenow.ParseCredential(b)
		if err == nil {
			t.Errorf("%.60s accepted", b)
		} else if strings.Contains(err.Error(), "pw") && !strings.Contains(err.Error(), "password") {
			t.Errorf("the error repeats the secret: %v", err)
		}
	}
}

func TestConfigFromEnv(t *testing.T) {
	env := map[string]string{"TESSERA_SERVICENOW_BASE_URL": "https://acme.service-now.com", "TESSERA_SERVICENOW_USERNAME": "svc", "TESSERA_SERVICENOW_CLIENT_ID": "cid",
		"TESSERA_SERVICENOW_SECRET": "env:SN_PW", "SN_PW": "hunter2"}
	get := func(k string) string { return env[k] }
	cfg, err := servicenow.ConfigFromEnv(get)
	if err != nil || cfg.AuthMode != "" || cfg.Username != "svc" || cfg.Secret.Reveal() != "hunter2" || cfg.BaseURL != "https://acme.service-now.com" {
		t.Errorf("basic = %+v %v", cfg, err)
	}
	env["TESSERA_SERVICENOW_AUTH"] = "oauth"
	if cfg, err = servicenow.ConfigFromEnv(get); err != nil || cfg.AuthMode != "oauth" || cfg.Username != "cid" {
		t.Errorf("oauth = %+v %v", cfg, err)
	}
	env["TESSERA_SERVICENOW_SECRET"] = "hunter2" // a literal is not a reference
	if _, err = servicenow.ConfigFromEnv(get); err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("literal secret: %v", err)
	}
	hc, _ := safehttp.NewForTest(t, connsynctest.New(t, snfake.New("a", "b", "", "")).Options(0))
	env["TESSERA_SERVICENOW_SECRET"] = "env:SN_PW"
	if c, err := servicenow.FromEnv(get, connsync.Runtime{Env: config.Prod}, hc, nil); err != nil || c.System() != "servicenow" || c.DisplayName() == "" || c.TypeName() == "" {
		t.Errorf("FromEnv = %v %v", c, err)
	}
	env["TESSERA_SERVICENOW_BASE_URL"] = "https://evil.example.com"
	if _, err := servicenow.FromEnv(get, connsync.Runtime{Env: config.Prod}, hc, nil); err == nil {
		t.Error("a host outside the allow-list was accepted")
	}
}

// ---------------------------------------------------------------- the provisioning target

func newTarget(t *testing.T, ticket bool) (*servicenow.Target, *rig) {
	t.Helper()
	r := newRig(t, servicenow.AuthBasic)
	return &servicenow.Target{C: r.client(t), Ticket: ticket}, r
}

func acct(name string) target.Account { return target.Account{Username: name} }

func apply(t *testing.T, tg *servicenow.Target, req target.Request) target.Verdict {
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

func TestTarget_AccountLifecycle(t *testing.T) {
	tg, r := newTarget(t, false)
	ctx := context.Background()
	create := target.Request{Kind: target.CreateAccount, Key: "k1", Account: target.Account{Username: "new.user@acme.example", Email: "new.user@acme.example", DisplayName: "New User"}}
	if v := apply(t, tg, create); !v.OK {
		t.Fatalf("create: %+v", v)
	}
	rows := r.fake.Rows("sys_user", "user_name", "new.user@acme.example")
	if len(rows) != 1 || rows[0]["first_name"] != "New" || rows[0]["last_name"] != "User" || rows[0]["active"] != "true" || rows[0]["email"] != "new.user@acme.example" {
		t.Fatalf("created = %v", rows)
	}
	if err := tg.Apply(ctx, create); err != nil || len(r.fake.Rows("sys_user", "user_name", "new.user@acme.example")) != 1 {
		t.Errorf("a repeated create made another user or failed: %v", err)
	}

	upd := target.Request{Kind: target.UpdateAccount, Key: "k2", Account: target.Account{Username: "new.user@acme.example", Attrs: map[string]string{"title": "Lead", "phone": "555"}}}
	if v := apply(t, tg, upd); !v.OK {
		t.Fatalf("update: %+v", v)
	}
	_, _, w := r.fake.Counts()
	if err := tg.Apply(ctx, upd); err != nil {
		t.Fatal(err)
	}
	if _, _, w2 := r.fake.Counts(); w2 != w {
		t.Errorf("a repeated update wrote again (%d -> %d)", w, w2)
	}
	for _, bad := range []map[string]string{{"sys_id": "x"}, {"active": "true"}, {"user_name": "x"}, {"title": "a\nb"}, {"title": strings.Repeat("x", 300)}} {
		err := tg.Apply(ctx, target.Request{Kind: target.UpdateAccount, Account: target.Account{Username: "bo", Attrs: bad}})
		var te *target.Error
		if !errors.As(err, &te) || te.Retryable {
			t.Errorf("attrs %v: %v", bad, err)
		}
	}

	dis := target.Request{Kind: target.DisableAccount, Key: "k3", Account: acct("ada@acme.example")}
	if v := apply(t, tg, dis); !v.OK {
		t.Fatalf("disable: %+v", v)
	}
	if got := r.fake.Rows("sys_user", "user_name", "ada@acme.example")[0]["active"]; got != "false" {
		t.Errorf("active = %v", got)
	}
	del := target.Request{Kind: target.DeleteAccount, Key: "k4", Account: acct("bo")}
	if v := apply(t, tg, del); !v.OK || len(r.fake.Rows("sys_user", "user_name", "bo")) != 1 {
		t.Errorf("delete deactivates and keeps the row: %+v", v)
	}
	if err := tg.Apply(ctx, target.Request{Kind: target.DisableAccount, Account: acct("ghost")}); err != nil {
		t.Errorf("disabling a user that does not exist: %v", err)
	}
	if err := tg.Apply(ctx, target.Request{Kind: target.UpdateAccount, Account: target.Account{Username: "ghost", Attrs: map[string]string{"title": "x"}}}); err == nil {
		t.Error("updating a user that does not exist succeeded")
	}
	// a lookup by sys_id
	if v := apply(t, tg, target.Request{Kind: target.DisableAccount, Account: target.Account{ExternalID: uSvc}}); !v.OK {
		t.Errorf("by sys_id: %+v", v)
	}
}

func TestTarget_Entitlements(t *testing.T) {
	tg, r := newTarget(t, false)
	ctx := context.Background()
	addG := target.Request{Kind: target.AddEntitlement, Key: "g1", Account: acct("bo"), Group: target.Group{ExternalID: gNet}}
	if v := apply(t, tg, addG); !v.OK || len(r.fake.Rows("sys_user_grmember", "user", uBo, "group", gNet)) != 1 {
		t.Fatalf("add group: %+v", v)
	}
	if err := tg.Apply(ctx, addG); err != nil || len(r.fake.Rows("sys_user_grmember", "user", uBo, "group", gNet)) != 1 {
		t.Errorf("a repeated add made another membership: %v", err)
	}
	rmG := target.Request{Kind: target.RemoveEntitlement, Key: "g2", Account: acct("bo"), Group: target.Group{ExternalID: gNet}}
	if v := apply(t, tg, rmG); !v.OK || len(r.fake.Rows("sys_user_grmember", "user", uBo, "group", gNet)) != 0 {
		t.Fatalf("remove group: %+v", v)
	}

	addR := target.Request{Kind: target.AddEntitlement, Key: "r1", Account: acct("ada@acme.example"), Group: target.Group{ExternalID: rSec}}
	if v := apply(t, tg, addR); !v.OK || len(r.fake.Rows("sys_user_has_role", "user", uAda, "role", rSec)) != 1 {
		t.Fatalf("add role: %+v", v)
	}
	// bo holds admin only through a group (an inherited row): that already is holding it, so an add writes nothing,
	// and a removal acts on direct rows only: the inherited one goes with the group membership, not with this call
	_, _, w := r.fake.Counts()
	if err := tg.Apply(ctx, target.Request{Kind: target.AddEntitlement, Account: acct("bo"), Group: target.Group{ExternalID: rAdmin}}); err != nil {
		t.Fatal(err)
	}
	if _, _, w2 := r.fake.Counts(); w2 != w {
		t.Errorf("an add of a role already held through a group wrote")
	}
	rmR := target.Request{Kind: target.RemoveEntitlement, Key: "r2", Account: acct("bo"), Group: target.Group{ExternalID: rAdmin}}
	if err := tg.Apply(ctx, rmR); err != nil {
		t.Fatal(err)
	}
	if left := r.fake.Rows("sys_user_has_role", "user", uBo, "role", rAdmin); len(left) != 1 || left[0]["inherited"] != "true" {
		t.Errorf("the inherited row stays: %v", left)
	}
	r.fake.Set("sys_group_has_role", snfake.Row{"group": gApps, "role": rAdmin})
	v, err := tg.Verify(context.Background(), rmR)
	if err != nil || v.OK || !strings.Contains(v.Observed, "still holds the role through the group Apps") {
		t.Errorf("a role still held through a group: %+v %v", v, err)
	}
	if err := tg.Apply(ctx, target.Request{Kind: target.RemoveEntitlement, Account: acct("ada@acme.example"), Group: target.Group{ExternalID: rSec}}); err != nil ||
		len(r.fake.Rows("sys_user_has_role", "user", uAda, "role", rSec)) != 0 {
		t.Errorf("removing a directly granted role: %v", err)
	}
	// removing what a user does not hold, and from a user that does not exist
	if err := tg.Apply(ctx, target.Request{Kind: target.RemoveEntitlement, Account: acct("ghost"), Group: target.Group{ExternalID: gNet}}); err != nil {
		t.Errorf("remove from a missing user: %v", err)
	}
	for _, c := range []target.Request{
		{Kind: target.AddEntitlement, Account: acct("ghost"), Group: target.Group{ExternalID: gNet}},
		{Kind: target.AddEntitlement, Account: acct("bo"), Group: target.Group{ExternalID: "ffffffffffffffffffffffffffffffff"}},
		{Kind: target.AddEntitlement, Account: acct("bo"), Group: target.Group{ExternalID: "not-a-sys-id"}},
		{Kind: target.AddEntitlement, Account: acct("bo"), Group: target.Group{Name: "Network"}},
		{Kind: "nuke", Account: acct("bo")},
		{Kind: target.AddEntitlement, Group: target.Group{ExternalID: gNet}},
	} {
		err := tg.Apply(ctx, c)
		var te *target.Error
		if !errors.As(err, &te) || te.Retryable {
			t.Errorf("%+v: err = %v", c, err)
		}
	}
}

func TestTarget_DroppedWriteIsNotDone(t *testing.T) {
	tg, r := newTarget(t, false)
	r.fake.SetFaults(snfake.Faults{DropWrites: true})
	for _, req := range []target.Request{
		{Kind: target.AddEntitlement, Account: acct("bo"), Group: target.Group{ExternalID: gNet}},
		{Kind: target.DisableAccount, Account: acct("ada@acme.example")},
		{Kind: target.CreateAccount, Account: acct("fresh@acme.example")},
	} {
		if v := apply(t, tg, req); v.OK {
			t.Errorf("%s: a dropped write was verified: %+v", req.Kind, v)
		}
	}
	r.fake.SetFaults(snfake.Faults{WriteStatus: 403})
	err := tg.Apply(context.Background(), target.Request{Kind: target.AddEntitlement, Account: acct("bo"), Group: target.Group{ExternalID: gNet}})
	var te *target.Error
	if !errors.As(err, &te) || te.Status != 403 {
		t.Errorf("a refused write: %v", err)
	}
	r.fake.SetFaults(snfake.Faults{WriteStatus: 500})
	if err := tg.Apply(context.Background(), target.Request{Kind: target.AddEntitlement, Account: acct("bo"), Group: target.Group{ExternalID: gNet}}); err == nil || !target.Retryable(err) {
		t.Errorf("a 500 is retryable: %v", err)
	}
}

// A value that is not on the allow-list never reaches the instance: no query is sent.
func TestTarget_QueryInjectionIsRefused(t *testing.T) {
	tg, r := newTarget(t, false)
	for _, name := range []string{"x^active=false", "x^ORuser_name!=", "javascript:gs.getUserID()", "a^NQb", "dynamic:abc", "x\ny"} {
		before := len(r.srv.Requests())
		for _, k := range []string{target.DisableAccount, target.AddEntitlement, target.UpdateAccount} {
			req := target.Request{Kind: k, Account: target.Account{Username: name, Attrs: map[string]string{"title": "t"}}, Group: target.Group{ExternalID: gNet}}
			err := tg.Apply(context.Background(), req)
			var te *target.Error
			if !errors.As(err, &te) || te.Retryable {
				t.Errorf("%s %q: err = %v", k, name, err)
			} else if strings.Contains(te.Msg, name) {
				t.Errorf("%s: the error quotes the value: %v", k, te.Msg)
			}
			if _, err := tg.Verify(context.Background(), req); err == nil {
				t.Errorf("verify %s %q: no error", k, name)
			}
		}
		for _, q := range r.srv.Requests()[before:] {
			if strings.Contains(q.Query, "%5E") && strings.Contains(q.Query, url.QueryEscape(name)) {
				t.Errorf("a refused value reached the instance: %s", q.Query)
			}
		}
	}
	// the queries that are sent escape the caret of their own conditions and carry no free text
	if _, err := tg.Verify(context.Background(), target.Request{Kind: target.AddEntitlement, Account: acct("bo"), Group: target.Group{ExternalID: gNet}}); err != nil {
		t.Fatal(err)
	}
	for _, q := range r.srv.Requests() {
		if strings.Contains(q.Query, "sysparm_query=") && strings.Contains(q.Query, "^") {
			t.Errorf("a raw caret in a query string: %s", q.Query)
		}
	}
}

func TestTarget_TicketMode(t *testing.T) {
	tg, r := newTarget(t, true)
	tg.AssignmentGroup = gNet
	ctx := context.Background()
	req := target.Request{Kind: target.AddEntitlement, Key: "jml:joiner:42|x", Account: acct("bo"), Group: target.Group{ExternalID: gNet, Name: "Network"}}
	if err := tg.Apply(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := tg.Apply(ctx, req); err != nil {
		t.Fatal(err)
	}
	inc := r.fake.Rows("incident")
	if len(inc) != 1 {
		t.Fatalf("incidents = %d, want one for a repeated request", len(inc))
	}
	if strings.Contains(fmt.Sprint(inc[0]), "jml:joiner") {
		t.Errorf("the operation key was copied into the instance: %v", inc[0])
	}
	if !strings.HasPrefix(fmt.Sprint(inc[0]["correlation_id"]), "tessera-") || inc[0]["assignment_group"] != gNet ||
		!strings.Contains(fmt.Sprint(inc[0]["description"]), "Network") || !strings.Contains(fmt.Sprint(inc[0]["short_description"]), "add entitlement") {
		t.Errorf("incident = %v", inc[0])
	}
	if len(r.fake.Rows("sys_user_grmember", "user", uBo, "group", gNet)) != 0 || len(r.fake.Created) != 1 || r.fake.Created[0] != "incident" {
		t.Errorf("ticket mode wrote something else: %v", r.fake.Created)
	}
	v, err := tg.Verify(ctx, req)
	if err != nil || v.OK || !v.Waiting || !strings.Contains(v.Observed, "open") || !strings.Contains(v.Observed, "INC") {
		t.Errorf("open ticket: %+v %v", v, err)
	}
	// resolved or closed is a person's statement: the change must also be in the instance's tables
	for state, word := range map[string]string{"6": "resolved", "7": "closed"} {
		inc[0]["state"] = state
		r.fake.Set("incident", inc[0])
		r.fake.Set("sys_user_grmember")
		v, err := tg.Verify(ctx, req)
		if err != nil || v.OK || v.Waiting || !strings.Contains(v.Observed, "change not observed") {
			t.Errorf("state %s without the change: %+v %v", state, v, err)
		}
		r.fake.Set("sys_user_grmember", snfake.Row{"sys_id": "m9", "user": uBo, "group": gNet})
		if v, err := tg.Verify(ctx, req); err != nil || !v.OK || !strings.Contains(v.Observed, "change is observed") {
			t.Errorf("state %s with the change (%s): %+v %v", state, word, v, err)
		}
	}
	// canceled: a permanent failure
	inc[0]["state"] = "8"
	r.fake.Set("incident", inc[0])
	if _, err := tg.Verify(ctx, req); err == nil || target.Retryable(err) {
		t.Errorf("a canceled ticket: %v", err)
	}
	// an incident someone else made with a guessable id (a hash of the key, no secret) is not Tessera's
	sum := sha256.Sum256([]byte("guess-key"))
	r.fake.Set("incident", snfake.Row{"sys_id": "x1", "number": "INC0000001", "state": "7", "correlation_id": "tessera-" + hex.EncodeToString(sum[:])[:32]},
		snfake.Row{"sys_id": "x2", "number": "INC0000002", "state": "7", "correlation_id": "tessera-" + hex.EncodeToString(sum[:])[:40]})
	if v, err := tg.Verify(ctx, target.Request{Kind: target.AddEntitlement, Key: "guess-key", Account: acct("bo"), Group: target.Group{ExternalID: gNet}}); err != nil || v.OK || !strings.Contains(v.Observed, "no ticket") {
		t.Errorf("a pre-made incident stood in for the ticket: %+v %v", v, err)
	}
	// a revocation whose ticket was resolved while access remains is not done
	r.fake.Set("sys_user_has_role", snfake.Row{"sys_id": "h9", "user": uBo, "role": rAdmin, "inherited": "true", "state": "active"})
	r.fake.Set("sys_group_has_role", snfake.Row{"group": gApps, "role": rAdmin})
	r.fake.Set("sys_user_grmember", snfake.Row{"sys_id": "m10", "user": uBo, "group": gApps})
	rev := target.Request{Kind: target.RemoveEntitlement, Key: "rev1", Account: acct("bo"), Group: target.Group{ExternalID: rAdmin}}
	if err := tg.Apply(ctx, rev); err != nil {
		t.Fatal(err)
	}
	corr, _ := tg.CorrelationForTest("rev1")
	r.fake.Set("incident", snfake.Row{"sys_id": "x3", "number": "INC0000003", "state": "6", "correlation_id": corr})
	if v, err := tg.Verify(ctx, rev); err != nil || v.OK || !strings.Contains(v.Observed, "change not observed") || !strings.Contains(v.Observed, "the group Apps") {
		t.Errorf("a revocation resolved while access remains: %+v %v", v, err)
	}
	if v, err := tg.Verify(ctx, target.Request{Kind: target.AddEntitlement, Key: "other", Account: acct("bo"), Group: target.Group{ExternalID: gNet}}); err != nil || v.OK || !strings.Contains(v.Observed, "no ticket") {
		t.Errorf("no ticket: %+v %v", v, err)
	}
	if err := tg.Apply(ctx, target.Request{Kind: target.DisableAccount, Account: acct("bo")}); err == nil {
		t.Error("a ticket without the operation's key was raised")
	}
	// a name with control characters is flattened in the ticket text
	if err := tg.Apply(ctx, target.Request{Kind: target.DisableAccount, Key: "k9", Account: acct("evil\nInjected: line")}); err != nil {
		t.Fatal(err)
	}
	for _, row := range r.fake.Rows("incident") {
		if strings.Contains(fmt.Sprint(row["description"]), "\nInjected") {
			t.Errorf("a line break in a name reached the ticket: %q", row["description"])
		}
	}
}

func TestTarget_OpenTarget(t *testing.T) {
	r := newRig(t, servicenow.AuthBasic)
	hc, _ := safehttp.NewForTest(t, r.srv.Options(0))
	cred, err := servicenow.ParseCredential(`{"auth":"oauth","client_id":"` + cliID + `","client_secret":"` + cliSec + `","mode":"ticket","assignment_group":"` + gNet + `"}`)
	if err != nil {
		t.Fatal(err)
	}
	tg, err := servicenow.OpenTarget(r.srv.URL, cred, connsynctest.Runtime, hc, func() time.Time { return t0 })
	if err != nil || !tg.Ticket || tg.AssignmentGroup != gNet {
		t.Fatalf("target = %+v %v", tg, err)
	}
	if err := tg.Apply(context.Background(), target.Request{Kind: target.DisableAccount, Key: "x", Account: acct("bo")}); err != nil || len(r.fake.Rows("incident")) != 1 {
		t.Errorf("oauth ticket: %v", err)
	}
	if _, err := servicenow.OpenTarget("https://evil.example.com", cred, connsync.Runtime{Env: config.Prod}, hc, nil); err == nil {
		t.Error("a host outside the allow-list was opened")
	}
}
