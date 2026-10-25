package foundryagents_test

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
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/foundryagents"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/foundryagents/foundryfake"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

var t0 = time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)

const (
	tenant = "11111111-2222-3333-4444-555555555555"
	client = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	secret = "entra-client-secret-value"
)

func agents() []foundryfake.Agent {
	return []foundryfake.Agent{
		{ID: "asst_support", Name: "support", CreatedAt: 1760000000, Instructions: "free text the connector must not keep",
			Metadata: map[string]string{"Sponsor": "Pat@Acme.example", "creator": "olu@acme.example", "pii": "true"},
			Tools: []map[string]any{
				{"type": "function", "function": map[string]any{"name": "create_ticket", "description": "free text", "parameters": map[string]any{}}},
				{"type": "code_interpreter"}, {"type": "file_search"}, {"type": "azure_ai_search"},
				{"type": "openapi", "openapi": map[string]any{"name": "crm", "spec": map[string]any{"x": "spec text"}}},
				{"type": "connected_agent", "connected_agent": map[string]any{"id": "asst_billing", "name": "billing"}},
				{"type": "mcp", "mcp": map[string]any{"server_label": "docs", "server_url": "https://mcp.example/secret-path"}},
				{"type": "bing_grounding"}, {"type": "Bad Type!"}},
			Resources: map[string]any{"file_search": map[string]any{"vector_store_ids": []string{"vs_kb1", "bad id"}},
				"azure_ai_search": map[string]any{"indexes": []map[string]any{{"index_connection_id": "search-conn", "index_name": "tickets"}}}}},
		{ID: "asst_billing", Name: "billing", Metadata: map[string]string{"owner": "a-team"}},
		{ID: "asst_empty", Name: "empty"},
	}
}

type rig struct {
	fake *foundryfake.Fake
	srv  *connsynctest.Server
	cfg  foundryagents.Config
}

func newRig(t *testing.T, mut func(*foundryfake.Fake)) (*rig, func(foundryagents.Config) (*foundryagents.Client, error)) {
	t.Helper()
	fk := foundryfake.New(tenant, client, secret, agents()...)
	if mut != nil {
		mut(fk)
	}
	srv := connsynctest.New(t, fk)
	hc, err := safehttp.NewForTest(t, srv.Options(0))
	if err != nil {
		t.Fatal(err)
	}
	cfg := foundryagents.Config{BaseURL: srv.URL + "/api/projects/support", TenantID: tenant, ClientID: client, Credential: connsync.NewSecret(secret),
		Owner: "olu@acme.example", AuthorityURL: srv.URL}
	return &rig{fake: fk, srv: srv, cfg: cfg}, func(c foundryagents.Config) (*foundryagents.Client, error) {
		return foundryagents.Open(c, connsynctest.Runtime, hc, func() time.Time { return t0 })
	}
}

func discover(t *testing.T, r *rig, open func(foundryagents.Config) (*foundryagents.Client, error)) (*connectors.DiscoveryResult, error) {
	t.Helper()
	c, err := open(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return foundryagents.NewConnector(c).Discover(context.Background())
}

func TestDiscoverMapsAgentsToolsAndOwners(t *testing.T) {
	for _, page := range []int{0, 1} {
		t.Run(fmt.Sprintf("page %d", page), func(t *testing.T) {
			r, open := newRig(t, func(f *foundryfake.Fake) { f.PageSize = page })
			res, err := discover(t, r, open)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Identities) != 3 || len(res.Agents) != 3 {
				t.Fatalf("identities %d agents %d", len(res.Identities), len(res.Agents))
			}
			id := res.Identities[0]
			if id.ExternalID != "foundry:asst_support" || id.Type != "ai_agent" || id.Owner == nil || id.Owner.Email != "pat@acme.example" {
				t.Errorf("identity = %+v", id)
			}
			if a := res.Agents[0]; a.Kind != "foundry_agent" || a.Creator == nil || a.Creator.Email != "olu@acme.example" {
				t.Errorf("agent record = %+v", a)
			}
			// a sponsor that is not an e-mail address falls back to the connection's owner, and is kept as text
			if o := res.Identities[1].Owner; o == nil || o.Email != "olu@acme.example" || res.Accounts[1].Attributes["sponsor_text"] != "a-team" {
				t.Errorf("fallback owner = %+v, %+v", o, res.Accounts[1].Attributes)
			}
			perms := map[string]connectors.PermissionRecord{}
			for _, p := range res.Permissions {
				perms[p.ExternalID] = p
			}
			want := map[string]bool{
				"foundry-function:asst_support/create_ticket#invoke": false,
				"foundry-tool:code_interpreter#invoke":               true,
				"foundry-vector-store:vs_kb1#file_search":            false,
				"foundry-search-index:search-conn/tickets#search":    false,
				"foundry-openapi:asst_support/crm#invoke":            false,
				"foundry-agent:asst_billing#invoke_agent":            false,
				"foundry-mcp:docs#invoke":                            false,
				"foundry-tool:bing_grounding#invoke":                 false,
			}
			for k, priv := range want {
				if p, ok := perms[k]; !ok || p.Privileged != priv {
					t.Errorf("%s = %+v (present %v), want privileged %v", k, p, ok, priv)
				}
			}
			if len(perms) != len(want) {
				t.Errorf("%d permissions, want %d: %v", len(perms), len(want), perms)
			}
			for _, rs := range res.Resources {
				if rs.ExternalID == "foundry-tool:code_interpreter" && (!slices.Contains(rs.Tags, "code_execution") || !slices.Contains(rs.Tags, "pii")) {
					t.Errorf("code interpreter tags = %v", rs.Tags)
				}
			}
			got := fmt.Sprintf("%+v", res)
			for _, bad := range []string{"free text", "spec text", "secret-path", "bad id", "Bad Type"} {
				if strings.Contains(got, bad) {
					t.Errorf("the result keeps %q", bad)
				}
			}
			if r.fake.Writes() != 0 {
				t.Errorf("%d writes", r.fake.Writes())
			}
			if sc := r.fake.Scopes(); len(sc) != 1 || sc[0] != "https://ai.azure.com/.default" {
				t.Errorf("scopes = %v", sc)
			}
		})
	}
}

func TestFaults(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*foundryfake.Fake)
		cfg  func(*foundryagents.Config)
		is   error
		text string
	}{
		{name: "api denied", mut: func(f *foundryfake.Fake) { f.Deny = true }, text: "403"},
		{name: "wrong secret", cfg: func(c *foundryagents.Config) { c.Credential = connsync.NewSecret("x" + secret) }, is: foundryagents.ErrCredential},
		{name: "not json", mut: func(f *foundryfake.Fake) { f.NotJSON = true }, is: connsync.ErrMalformed},
		{name: "pages never end", mut: func(f *foundryfake.Fake) { f.Endless, f.PageSize = true, 1 }, text: "more"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, open := newRig(t, tc.mut)
			if tc.cfg != nil {
				tc.cfg(&r.cfg)
			}
			res, err := discover(t, r, open)
			if err == nil || res != nil {
				t.Fatalf("res %v, err %v", res, err)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Errorf("err = %v, want %v", err, tc.is)
			}
			if tc.text != "" && !strings.Contains(err.Error(), tc.text) {
				t.Errorf("err = %v, want text %q", err, tc.text)
			}
			if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), foundryfake.Token) {
				t.Errorf("error leaks a secret: %v", err)
			}
		})
	}
}

func TestProbe(t *testing.T) {
	r, open := newRig(t, nil)
	c, err := open(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.Probe(context.Background())
	if err != nil || p.Agents != 3 || c.Identity() != client || c.Mode() != "client_secret" {
		t.Errorf("probe = %+v, %v, %s, %s", p, err, c.Identity(), c.Mode())
	}
}

// The bearer token goes only to an Azure AI host: any other host, a port, a missing project path and a query are
// refused outside the dev loopback exception.
func TestEndpointIsChecked(t *testing.T) {
	prod := connsync.Runtime{Env: config.Prod}
	for u, ok := range map[string]bool{
		"https://acme.services.ai.azure.com/api/projects/support":        true,
		"https://acme.openai.azure.com/api/projects/support":             true,
		"https://evil.example/api/projects/support":                      false,
		"https://services.ai.azure.com/api/projects/support":             false,
		"https://acme.services.ai.azure.com.evil.example/api/projects/x": false,
		"https://acme.services.ai.azure.com:8443/api/projects/x":         false,
		"https://acme.services.ai.azure.com/api/projects/x?a=b":          false,
		"https://acme.services.ai.azure.com/":                            false,
		"https://acme.services.ai.azure.com/api/projects/../x":           false,
		"http://acme.services.ai.azure.com/api/projects/x":               false,
		"https://127.0.0.1/api/projects/support":                         false,
		"https://u:p@acme.services.ai.azure.com/api/projects/x":          false,
	} {
		if _, err := foundryagents.CheckURL(u, prod); (err == nil) != ok {
			t.Errorf("%s: err = %v, want ok %v", u, err, ok)
		}
	}
}

func TestOpenValidates(t *testing.T) {
	r, open := newRig(t, nil)
	for name, mut := range map[string]func(*foundryagents.Config){
		"bad tenant": func(c *foundryagents.Config) { c.TenantID = "x" },
		"bad client": func(c *foundryagents.Config) { c.ClientID = "x" },
		"bad owner":  func(c *foundryagents.Config) { c.Owner = "nope" },
		"no secret":  func(c *foundryagents.Config) { c.Credential = connsync.NewSecret("") },
		"bad host":   func(c *foundryagents.Config) { c.BaseURL = "https://evil.example/api/projects/support" },
	} {
		c := r.cfg
		mut(&c)
		if _, err := open(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	hc, _ := safehttp.NewForTest(t, r.srv.Options(0))
	c := r.cfg
	if _, err := foundryagents.Open(c, connsync.Runtime{Env: config.Prod}, hc, nil); err == nil {
		t.Error("a loopback endpoint and an authority override were accepted in prod")
	}
	c.BaseURL, c.AuthorityURL = "https://acme.services.ai.azure.com/api/projects/support", ""
	if _, err := foundryagents.Open(c, connsync.Runtime{Env: config.Prod}, hc, nil); err != nil {
		t.Errorf("prod with public endpoints: %v", err)
	}
	c.AuthorityURL = r.srv.URL
	if _, err := foundryagents.Open(c, connsync.Runtime{Env: config.Prod}, hc, nil); err == nil || !strings.Contains(err.Error(), "refused outside dev") {
		t.Errorf("authority override in prod: %v", err)
	}
}

func TestSecretNeverPrinted(t *testing.T) {
	r, open := newRig(t, nil)
	c, err := open(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
		for _, x := range []any{c, foundryagents.NewConnector(c), r.cfg} {
			if got := fmt.Sprintf(f, x); strings.Contains(got, secret) {
				t.Errorf("%s prints the secret", f)
			}
		}
	}
}

func TestFromEnv(t *testing.T) {
	r, open := newRig(t, nil)
	_ = open
	env := map[string]string{"TESSERA_FOUNDRY_CREDENTIAL": "env:K", "K": secret, "TESSERA_FOUNDRY_ENDPOINT": r.cfg.BaseURL, "TESSERA_FOUNDRY_TENANT_ID": tenant,
		"TESSERA_FOUNDRY_CLIENT_ID": client, "TESSERA_FOUNDRY_AUTHORITY_URL": r.srv.URL}
	hc, _ := safehttp.NewForTest(t, r.srv.Options(0))
	cn, err := foundryagents.FromEnv(func(k string) string { return env[k] }, connsynctest.Runtime, hc, func() time.Time { return t0 })
	if err != nil || cn.System() != "azure-foundry" {
		t.Fatalf("%v %v", cn, err)
	}
	if res, err := cn.Discover(context.Background()); err != nil || len(res.Agents) != 3 {
		t.Errorf("discover = %v, %v", res, err)
	}
	delete(env, "TESSERA_FOUNDRY_CREDENTIAL")
	if _, err := foundryagents.FromEnv(func(k string) string { return env[k] }, connsynctest.Runtime, hc, nil); err == nil {
		t.Error("no credential accepted")
	}
}
