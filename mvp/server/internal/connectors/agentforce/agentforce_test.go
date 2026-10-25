package agentforce_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/agentforce"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/agentforce/agentforcefake"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

var t0 = time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)

const (
	consumer    = "3MVG9ExampleConsumerKey"
	integration = "integration@acme.example"

	botA, botB = "0Xx000000000001AAA", "0Xx000000000002AAA"
	uBot, uOwn = "005000000000001AAA", "005000000000002AAA"
	uCreator   = "005000000000003AAA"
)

func newFake() *agentforcefake.Fake {
	f := agentforcefake.New(consumer, integration,
		map[string]string{uBot: "agent.user@acme.example", uOwn: "Pat@acme.example", uCreator: "olu@acme.example"},
		[]agentforcefake.Bot{
			{ID: botA, Dev: "Service_Agent", Label: "Service agent", Type: "ExternalCopilot", User: uBot, Owner: uOwn, Creator: uCreator, Created: "2026-09-01T10:00:00.000+0000"},
			{ID: botB, Dev: "Employee_Agent", Label: "Employee agent", Type: "InternalCopilot", Owner: "00G000000000009AAA"},
		},
		map[string]string{"16j000000000001AAA": "Service_Agent", "16j000000000002AAA": "Other_Planner"},
		[]agentforcefake.Function{
			{ID: "1Tj000000000001AAA", Dev: "Create_Case", Target: "Create_Case_Flow", TargetType: "flow"},
			{ID: "1Tj000000000002AAA", Dev: "Run_Report", Target: "ReportRunner", TargetType: "apex"},
			{ID: "1Tj000000000003AAA", Dev: "Other_Action", Target: "Other", TargetType: "flow"},
		},
		[][2]string{{"16j000000000001AAA", "1Tj000000000001AAA"}, {"16j000000000001AAA", "1Tj000000000002AAA"}, {"16j000000000002AAA", "1Tj000000000003AAA"}})
	f.Description = "free text the connector must not keep"
	return f
}

type rig struct {
	fake *agentforcefake.Fake
	srv  *connsynctest.Server
	cfg  agentforce.Config
	cred string
	open func(agentforce.Config) (*agentforce.Client, error)
}

func newRig(t *testing.T, mut func(*agentforcefake.Fake)) *rig {
	t.Helper()
	fk := newFake()
	if mut != nil {
		mut(fk)
	}
	srv := connsynctest.New(t, fk)
	hc, err := safehttp.NewForTest(t, srv.Options(0))
	if err != nil {
		t.Fatal(err)
	}
	cred := agentforcefake.Credential(consumer, integration)
	return &rig{fake: fk, srv: srv, cred: cred, cfg: agentforce.Config{BaseURL: srv.URL, Credential: connsync.NewSecret(cred)},
		open: func(c agentforce.Config) (*agentforce.Client, error) {
			return agentforce.Open(c, connsynctest.Runtime, hc, func() time.Time { return t0 })
		}}
}

func (r *rig) discover(t *testing.T) (*connectors.DiscoveryResult, error) {
	t.Helper()
	c, err := r.open(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return agentforce.NewConnector(c).Discover(context.Background())
}

func TestDiscoverMapsAgentsActionsAndOwners(t *testing.T) {
	for _, page := range []int{0, 1} {
		t.Run(fmt.Sprintf("page %d", page), func(t *testing.T) {
			r := newRig(t, func(f *agentforcefake.Fake) { f.PageSize = page })
			res, err := r.discover(t)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Identities) != 2 || len(res.Agents) != 2 || len(res.Accounts) != 2 {
				t.Fatalf("identities %d agents %d accounts %d", len(res.Identities), len(res.Agents), len(res.Accounts))
			}
			svc, emp := res.Identities[0], res.Identities[1]
			if svc.ExternalID != "agentforce:"+botA || svc.Type != "ai_agent" || svc.Name != "Service agent" || svc.Owner == nil || svc.Owner.Email != "pat@acme.example" {
				t.Errorf("identity = %+v", svc)
			}
			if a := res.Agents[0]; a.Kind != "agentforce_agent" || a.Creator == nil || a.Creator.Email != "olu@acme.example" {
				t.Errorf("agent record = %+v", a)
			}
			// a queue owner is no person: kept as text only
			if emp.Owner != nil || res.Agents[1].SponsorRef != "00G000000000009AAA" {
				t.Errorf("queue-owned agent = %+v, %+v", emp, res.Agents[1])
			}
			if res.Accounts[0].CreatedAt == nil || !res.Accounts[0].CreatedAt.Equal(time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)) {
				t.Errorf("created = %v", res.Accounts[0].CreatedAt)
			}
			perms := map[string]bool{}
			for _, p := range res.Permissions {
				perms[p.ExternalID] = p.Privileged
			}
			for _, k := range []string{"sf-user:" + uBot + "#run_as", "sf-action:flow:Create_Case_Flow#invoke", "sf-action:apex:ReportRunner#invoke"} {
				if _, ok := perms[k]; !ok {
					t.Errorf("missing %s", k)
				}
			}
			if len(perms) != 3 {
				t.Errorf("%d permissions: %v", len(perms), perms)
			}
			if got := fmt.Sprintf("%+v", res); strings.Contains(got, "free text") || strings.Contains(got, "Other_Action") {
				t.Error("a description or another agent's action was kept")
			}
			if r.fake.Writes() != 0 {
				t.Errorf("%d writes", r.fake.Writes())
			}
			for _, q := range r.fake.Queries() {
				if !strings.HasPrefix(q, "SELECT ") || strings.Contains(strings.ToLower(q), "instruction") {
					t.Errorf("query %q", q)
				}
			}
		})
	}
}

func TestFaults(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*agentforcefake.Fake)
		cfg  func(*agentforce.Config)
		text string
	}{
		{name: "api denied", mut: func(f *agentforcefake.Fake) { f.Deny = true }, text: "403"},
		{name: "genai objects missing", mut: func(f *agentforcefake.Fake) { f.NoGenAi = true }, text: "400"},
		{name: "token refused", mut: func(f *agentforcefake.Fake) { f.RefuseToken = true }, text: "400"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, tc.mut)
			res, err := r.discover(t)
			if err == nil || res != nil || !strings.Contains(err.Error(), tc.text) {
				t.Fatalf("res %v, err %v", res, err)
			}
			if strings.Contains(err.Error(), agentforcefake.Token) || strings.Contains(err.Error(), "PRIVATE KEY") {
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
	if err != nil || p.Agents != 2 || c.Identity() != integration || c.Mode() != "jwt_bearer" {
		t.Errorf("probe = %+v, %v, %s, %s", p, err, c.Identity(), c.Mode())
	}
	r2 := newRig(t, func(f *agentforcefake.Fake) { f.RefuseToken = true })
	c2, _ := r2.open(r2.cfg)
	if _, err := c2.Probe(context.Background()); !errors.Is(err, agentforce.ErrCredential) {
		t.Errorf("a refused token: %v", err)
	}
}

func TestOpenValidates(t *testing.T) {
	r := newRig(t, nil)
	for name, mut := range map[string]func(*agentforce.Config){
		"no credential": func(c *agentforce.Config) { c.Credential = connsync.NewSecret("") },
		"not json":      func(c *agentforce.Config) { c.Credential = connsync.NewSecret("secret") },
		"bad key": func(c *agentforce.Config) {
			c.Credential = connsync.NewSecret(`{"client_id":"a","username":"b","private_key":"x"}`)
		},
		"foreign host":    func(c *agentforce.Config) { c.BaseURL = "https://evil.example" },
		"bad api version": func(c *agentforce.Config) { c.APIVersion = "61" },
	} {
		c := r.cfg
		mut(&c)
		if _, err := r.open(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	hc, _ := safehttp.NewForTest(t, r.srv.Options(0))
	if _, err := agentforce.Open(r.cfg, connsync.Runtime{Env: config.Prod}, hc, nil); err == nil {
		t.Error("a loopback host was accepted in prod")
	}
	c := r.cfg
	c.BaseURL = "https://acme.my.salesforce.com"
	if _, err := agentforce.Open(c, connsync.Runtime{Env: config.Prod}, hc, nil); err != nil {
		t.Errorf("a My Domain host in prod: %v", err)
	}
}

func TestSecretNeverPrinted(t *testing.T) {
	r := newRig(t, nil)
	c, err := r.open(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
		for _, x := range []any{c, agentforce.NewConnector(c), r.cfg} {
			if got := fmt.Sprintf(f, x); strings.Contains(got, "PRIVATE KEY") || strings.Contains(got, "private_key") {
				t.Errorf("%s prints the key", f)
			}
		}
	}
}

func TestFromEnv(t *testing.T) {
	r := newRig(t, nil)
	env := map[string]string{"TESSERA_AGENTFORCE_CREDENTIAL": "env:K", "K": r.cred, "TESSERA_AGENTFORCE_BASE_URL": r.srv.URL}
	hc, _ := safehttp.NewForTest(t, r.srv.Options(0))
	cn, err := agentforce.FromEnv(func(k string) string { return env[k] }, connsynctest.Runtime, hc, func() time.Time { return t0 })
	if err != nil || cn.System() != "salesforce-agentforce" {
		t.Fatalf("%v %v", cn, err)
	}
	if res, err := cn.Discover(context.Background()); err != nil || len(res.Agents) != 2 {
		t.Errorf("discover = %v, %v", res, err)
	}
	delete(env, "TESSERA_AGENTFORCE_CREDENTIAL")
	if _, err := agentforce.FromEnv(func(k string) string { return env[k] }, connsynctest.Runtime, hc, nil); err == nil {
		t.Error("no credential accepted")
	}
}
