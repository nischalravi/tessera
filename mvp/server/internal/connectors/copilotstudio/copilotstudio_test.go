package copilotstudio_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/copilotstudio"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/copilotstudio/copilotfake"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

var t0 = time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)

const (
	tenant = "11111111-2222-3333-4444-555555555555"
	client = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	secret = "entra-client-secret-value"

	botA, botB, botC = "b0000000-0000-0000-0000-00000000000a", "b0000000-0000-0000-0000-00000000000b", "b0000000-0000-0000-0000-00000000000c"
	userPat, userOlu = "a0000000-0000-0000-0000-000000000001", "a0000000-0000-0000-0000-000000000002"
	team             = "a0000000-0000-0000-0000-0000000000ff"
)

func newFake() *copilotfake.Fake {
	f := copilotfake.New(tenant, client, secret,
		map[string]string{userPat: "Pat@acme.example", userOlu: "olu@acme.example"},
		[]copilotfake.Bot{
			{ID: botA, Name: "HR helper", Schema: "cr1_hr", State: 0, AuthMode: 2, Created: "2026-09-01T10:00:00Z", Owner: userPat, Creator: userOlu},
			{ID: botB, Name: "Public FAQ", Schema: "cr1_faq", State: 1, AuthMode: 1, Owner: team, Creator: userOlu},
			{ID: botC, Name: "Idle", Schema: "cr1_idle", State: 0, AuthMode: 3, Owner: userPat},
		},
		[]copilotfake.Component{
			{ID: "c0000000-0000-0000-0000-000000000001", Name: "Send mail", Schema: "cr1_hr.action.SendMail", Bot: botA},
			{ID: "c0000000-0000-0000-0000-000000000002", Name: "Policies", Schema: "cr1_hr.knowledge.Policies", Bot: botA},
			{ID: "c0000000-0000-0000-0000-000000000003", Name: "Greeting", Schema: "cr1_hr.topic.Greeting", Bot: botA},
			{ID: "c0000000-0000-0000-0000-000000000004", Name: "FAQ site", Schema: "cr1_faq.knowledge.Site", Bot: botB},
			{ID: "c0000000-0000-0000-0000-000000000005", Name: "Orphan", Schema: "cr9.action.X", Bot: "b0000000-0000-0000-0000-0000000000ee"},
		})
	f.Description = "free text the connector must not keep"
	return f
}

type rig struct {
	fake *copilotfake.Fake
	srv  *connsynctest.Server
	cfg  copilotstudio.Config
	open func(copilotstudio.Config) (*copilotstudio.Client, error)
}

func newRig(t *testing.T, mut func(*copilotfake.Fake)) *rig {
	t.Helper()
	fk := newFake()
	if mut != nil {
		mut(fk)
	}
	srv := connsynctest.New(t, fk)
	fk.Base = srv.URL
	hc, err := safehttp.NewForTest(t, srv.Options(0))
	if err != nil {
		t.Fatal(err)
	}
	return &rig{fake: fk, srv: srv, cfg: copilotstudio.Config{BaseURL: srv.URL, TenantID: tenant, ClientID: client, Credential: connsync.NewSecret(secret), AuthorityURL: srv.URL},
		open: func(c copilotstudio.Config) (*copilotstudio.Client, error) {
			return copilotstudio.Open(c, connsynctest.Runtime, hc, func() time.Time { return t0 })
		}}
}

func (r *rig) discover(t *testing.T) (*connectors.DiscoveryResult, error) {
	t.Helper()
	c, err := r.open(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return copilotstudio.NewConnector(c).Discover(context.Background())
}

func TestDiscoverMapsAgentsToolsAndOwners(t *testing.T) {
	for _, page := range []int{0, 1} {
		t.Run(fmt.Sprintf("page %d", page), func(t *testing.T) {
			r := newRig(t, func(f *copilotfake.Fake) { f.PageSize = page })
			res, err := r.discover(t)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Identities) != 3 || len(res.Agents) != 3 {
				t.Fatalf("identities %d agents %d", len(res.Identities), len(res.Agents))
			}
			hr, faq := res.Identities[0], res.Identities[1]
			if hr.ExternalID != "copilot:"+botA || hr.Type != "ai_agent" || hr.Name != "HR helper" || hr.Status != "active" || hr.Owner == nil || hr.Owner.Email != "pat@acme.example" {
				t.Errorf("identity = %+v", hr)
			}
			if a := res.Agents[0]; a.Kind != "copilot_studio_agent" || a.Creator == nil || a.Creator.Email != "olu@acme.example" {
				t.Errorf("agent record = %+v", a)
			}
			// a team owner has no e-mail address: kept as text, no owner identity, and the bot is inactive
			if faq.Owner != nil || faq.Status != "disabled" || res.Agents[1].SponsorRef != team {
				t.Errorf("team-owned bot = %+v, %+v", faq, res.Agents[1])
			}
			if res.Accounts[1].Attributes["auth_mode"] != "none" || res.Accounts[0].Attributes["auth_mode"] != "integrated" || res.Accounts[2].Attributes["auth_mode"] != "custom_aad" {
				t.Errorf("auth modes = %v %v %v", res.Accounts[0].Attributes, res.Accounts[1].Attributes, res.Accounts[2].Attributes)
			}
			perms := map[string]bool{}
			for _, p := range res.Permissions {
				perms[p.ExternalID] = p.Privileged
			}
			want := []string{
				"copilot-tool:" + botA + "/c0000000-0000-0000-0000-000000000001#invoke",
				"copilot-knowledge:" + botA + "/c0000000-0000-0000-0000-000000000002#retrieve",
				"copilot-knowledge:" + botB + "/c0000000-0000-0000-0000-000000000004#retrieve",
			}
			if len(perms) != len(want) {
				t.Errorf("%d permissions, want %d: %v", len(perms), len(want), perms)
			}
			for _, k := range want {
				if _, ok := perms[k]; !ok {
					t.Errorf("missing %s", k)
				}
			}
			for _, rs := range res.Resources {
				anon := slices.Contains(rs.Tags, "anonymous_access")
				if anon != strings.Contains(rs.ExternalID, botB) {
					t.Errorf("%s anonymous_access = %v", rs.ExternalID, anon)
				}
			}
			if got := fmt.Sprintf("%+v", res); strings.Contains(got, "free text") {
				t.Error("a description or component data was kept")
			}
			for _, s := range r.fake.Selects() {
				if strings.Contains(s, "data") || strings.Contains(s, "description") {
					t.Errorf("selected %q", s)
				}
			}
			if r.fake.Writes() != 0 {
				t.Errorf("%d writes", r.fake.Writes())
			}
			if sc := r.fake.Scopes(); len(sc) != 1 || sc[0] != r.srv.URL+"/.default" {
				t.Errorf("scopes = %v", sc)
			}
		})
	}
}

func TestPageLinkCannotLeaveTheOrigin(t *testing.T) {
	r := newRig(t, func(f *copilotfake.Fake) { f.PageSize, f.LeakLink = 1, true })
	if _, err := r.discover(t); err == nil || !strings.Contains(err.Error(), "leaves the Web API") {
		t.Errorf("err = %v", err)
	}
	for _, q := range r.srv.Requests() {
		if q.Path == "/evil" {
			t.Error("followed the link")
		}
	}
}

func TestFaults(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*copilotfake.Fake)
		cfg  func(*copilotstudio.Config)
		is   error
		text string
	}{
		{name: "api denied", mut: func(f *copilotfake.Fake) { f.Deny = true }, text: "403"},
		{name: "wrong secret", cfg: func(c *copilotstudio.Config) { c.Credential = connsync.NewSecret("x" + secret) }, is: copilotstudio.ErrCredential},
		{name: "not json", mut: func(f *copilotfake.Fake) { f.NotJSON = true }, is: connsync.ErrMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, tc.mut)
			if tc.cfg != nil {
				tc.cfg(&r.cfg)
			}
			res, err := r.discover(t)
			if err == nil || res != nil {
				t.Fatalf("res %v, err %v", res, err)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Errorf("err = %v, want %v", err, tc.is)
			}
			if tc.text != "" && !strings.Contains(err.Error(), tc.text) {
				t.Errorf("err = %v, want text %q", err, tc.text)
			}
			if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), copilotfake.Token) {
				t.Errorf("error leaks a secret: %v", err)
			}
		})
	}
}

func TestProbe(t *testing.T) {
	r := newRig(t, nil)
	c, err := r.open(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.Probe(context.Background())
	if err != nil || p.Agents != 3 || c.Identity() != client || c.Mode() != "client_secret" {
		t.Errorf("probe = %+v, %v, %s, %s", p, err, c.Identity(), c.Mode())
	}
}

func TestEnvironmentURLIsChecked(t *testing.T) {
	prod := connsync.Runtime{Env: config.Prod}
	for u, ok := range map[string]bool{
		"https://acme.crm.dynamics.com":              true,
		"https://acme.crm4.dynamics.com/":            true,
		"https://acme.crm.microsoftdynamics.us":      true,
		"https://evil.example":                       false,
		"https://dynamics.com":                       false,
		"https://acme.crm.dynamics.com.evil.example": false,
		"https://acme.crm.dynamics.com:8443":         false,
		"https://acme.crm.dynamics.com/api":          false,
		"https://acme.crm.dynamics.com/?a=b":         false,
		"http://acme.crm.dynamics.com":               false,
		"https://127.0.0.1":                          false,
		"https://u:p@acme.crm.dynamics.com":          false,
	} {
		if _, err := copilotstudio.CheckURL(u, prod); (err == nil) != ok {
			t.Errorf("%s: err = %v, want ok %v", u, err, ok)
		}
	}
}

func TestOpenValidates(t *testing.T) {
	r := newRig(t, nil)
	for name, mut := range map[string]func(*copilotstudio.Config){
		"bad tenant": func(c *copilotstudio.Config) { c.TenantID = "x" },
		"bad client": func(c *copilotstudio.Config) { c.ClientID = "x" },
		"no secret":  func(c *copilotstudio.Config) { c.Credential = connsync.NewSecret("") },
		"bad host":   func(c *copilotstudio.Config) { c.BaseURL = "https://evil.example" },
	} {
		c := r.cfg
		mut(&c)
		if _, err := r.open(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	hc, _ := safehttp.NewForTest(t, r.srv.Options(0))
	c := r.cfg
	c.BaseURL = "https://acme.crm.dynamics.com"
	if _, err := copilotstudio.Open(c, connsync.Runtime{Env: config.Prod}, hc, nil); err == nil || !strings.Contains(err.Error(), "refused outside dev") {
		t.Errorf("authority override in prod: %v", err)
	}
	c.AuthorityURL = ""
	if _, err := copilotstudio.Open(c, connsync.Runtime{Env: config.Prod}, hc, nil); err != nil {
		t.Errorf("prod with public endpoints: %v", err)
	}
}

func TestSecretNeverPrinted(t *testing.T) {
	r := newRig(t, nil)
	c, err := r.open(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
		for _, x := range []any{c, copilotstudio.NewConnector(c), r.cfg} {
			if got := fmt.Sprintf(f, x); strings.Contains(got, secret) {
				t.Errorf("%s prints the secret", f)
			}
		}
	}
}

func TestFromEnv(t *testing.T) {
	r := newRig(t, nil)
	env := map[string]string{"TESSERA_COPILOT_CREDENTIAL": "env:K", "K": secret, "TESSERA_COPILOT_URL": r.srv.URL, "TESSERA_COPILOT_TENANT_ID": tenant,
		"TESSERA_COPILOT_CLIENT_ID": client, "TESSERA_COPILOT_AUTHORITY_URL": r.srv.URL}
	hc, _ := safehttp.NewForTest(t, r.srv.Options(0))
	cn, err := copilotstudio.FromEnv(func(k string) string { return env[k] }, connsynctest.Runtime, hc, func() time.Time { return t0 })
	if err != nil || cn.System() != "copilot-studio" {
		t.Fatalf("%v %v", cn, err)
	}
	if res, err := cn.Discover(context.Background()); err != nil || len(res.Agents) != 3 {
		t.Errorf("discover = %v, %v", res, err)
	}
	delete(env, "TESSERA_COPILOT_CREDENTIAL")
	if _, err := copilotstudio.FromEnv(func(k string) string { return env[k] }, connsynctest.Runtime, hc, nil); err == nil {
		t.Error("no credential accepted")
	}
}
