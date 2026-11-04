package readiness

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// A live MCP, Bedrock, Vertex, Foundry, Copilot Studio, Agentforce or AgentCore connection's connector is
// opened from its stored config (issue #814): its base_url and settings reach the builder (with the opened
// credential, except AgentCore, which reads a recorded snapshot), and a connection that does not open
// fails closed, naming the system its connector reports, so the env-configured connector is not read in
// its place.
func TestAgentPlatformsAreOpenedFromTheStoredConfig(t *testing.T) {
	for _, tc := range []struct {
		typ, system, base, setting, want string
	}{
		{"mcp", "mcp", "https://tools.acme.example/mcp", "owner", "olu@acme.example"},
		{"bedrock", "aws-bedrock", "", "region", "us-east-1"},
		{"vertex", "gcp-vertex", "", "project_id", "acme-agents-prod"},
		{"foundry", "azure-foundry", "https://acme.services.ai.azure.com/api/projects/support", "client_id", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
		{"copilot", "copilot-studio", "https://acme.crm.dynamics.com", "tenant_id", "11111111-2222-3333-4444-555555555555"},
		{"agentforce", "salesforce-agentforce", "https://acme.my.salesforce.com", "", ""},
		{"agentcore", "aws-agentcore", "", "snapshot", "agentcore.json"},
	} {
		t.Run(tc.typ, func(t *testing.T) {
			var opened []governed.Params
			s := govSvc(t, &opened, stubProber{})
			passingEvidence(s, t0.Add(48*time.Hour))
			var built []governed.Params
			s.Runner.Gov.Connector = func(p governed.Params, _ governed.Net) (connectors.Connector, error) {
				built = append(built, p)
				return fakeConnector{tc.system}, nil
			}
			st := newStore(t)
			activateGov(t, s, st, tc.typ)
			cns, failed, err := s.GovernedConnectors(context.Background(), st.DB, st.Tenant, t0)
			if err != nil || len(failed) != 0 || len(cns) != 1 || cns[0].System() != tc.system {
				t.Fatalf("governed connectors: %v, failed %v, %v", cns, failed, err)
			}
			if len(built) != 1 {
				t.Fatalf("connector built %d times", len(built))
			}
			wantSecret := govSecret
			if tc.typ == "agentcore" {
				wantSecret = ""
			}
			p := built[0]
			if p.Type != tc.typ || p.BaseURL != tc.base || p.Settings[tc.setting] != tc.want || p.Secret != wantSecret {
				t.Errorf("opened with %+v", p)
			}
			read(t, st, func(c *store.TenantTx) error {
				got, err := s.StoredSystems(c)
				if err != nil || !slices.Equal(got, []string{tc.system}) {
					t.Errorf("stored systems = %v, %v", got, err)
				}
				return nil
			})

			s.Runner.Gov.Connector = func(governed.Params, governed.Net) (connectors.Connector, error) {
				return nil, errors.New(tc.typ + ": bad config")
			}
			cns, failed, err = s.GovernedConnectors(context.Background(), st.DB, st.Tenant, t0)
			if err != nil || len(cns) != 0 || len(failed) != 1 {
				t.Fatalf("after a failure: %v, failed %v, %v", cns, failed, err)
			}
			for name, e := range failed {
				var no *connectors.NotOpenedError
				if !errors.As(e, &no) || no.System != tc.system {
					t.Errorf("%s: failure %v does not name the %s system", name, e, tc.system)
				}
			}
		})
	}
}

// storedSystem names the system the connector reports for every stored governed type, not the type id.
func TestStoredSystemIsTheConnectorsSystem(t *testing.T) {
	s := liveSvc(t)
	for typ, want := range map[string]string{"azurerbac": "azure", "gcpiam": "gcp", "unixssh": "unix", "sftpdrop": "sftp",
		"githubscan": "github-scan", "kubernetes": "kubernetes", "bedrock": "aws-bedrock", "agentcore": "aws-agentcore",
		"google_workspace": "google_workspace"} {
		if got := s.storedSystem(nil, ActiveConnection{connectorType: typ}); got != want {
			t.Errorf("storedSystem(%s) = %q, want %q", typ, got, want)
		}
	}
}

// The endpoints of these types are refused on save unless the connector would open them: https, a public
// host, never a cloud metadata service, and the host rules of the Azure and Salesforce services.
func TestAgentPlatformConfigRefusesUnopenableURLs(t *testing.T) {
	const guids = `"tenant_id":"11111111-2222-3333-4444-555555555555","client_id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"`
	for _, tc := range []struct {
		typ, name, cfg string
		bad            bool
	}{
		{"mcp", "ok", `{"base_url":"https://tools.acme.example/mcp","correlation_key":"id","settings":{"owner":"olu@acme.example"}}`, false},
		{"mcp", "http", `{"base_url":"http://tools.acme.example/mcp","correlation_key":"id","settings":{"owner":"olu@acme.example"}}`, true},
		{"mcp", "metadata", `{"base_url":"https://169.254.169.254/mcp","correlation_key":"id","settings":{"owner":"olu@acme.example"}}`, true},
		{"mcp", "metadata name", `{"base_url":"https://metadata.google.internal/mcp","correlation_key":"id","settings":{"owner":"olu@acme.example"}}`, true},
		{"foundry", "ok", `{"base_url":"https://acme.services.ai.azure.com/api/projects/support","correlation_key":"id","settings":{` + guids + `}}`, false},
		{"foundry", "other host", `{"base_url":"https://evil.example.com/api/projects/support","correlation_key":"id","settings":{` + guids + `}}`, true},
		{"foundry", "metadata", `{"base_url":"https://169.254.169.254/api/projects/support","correlation_key":"id","settings":{` + guids + `}}`, true},
		{"copilot", "ok", `{"base_url":"https://acme.crm.dynamics.com","correlation_key":"id","settings":{` + guids + `}}`, false},
		{"copilot", "other host", `{"base_url":"https://evil.example.com","correlation_key":"id","settings":{` + guids + `}}`, true},
		{"copilot", "path", `{"base_url":"https://acme.crm.dynamics.com/api","correlation_key":"id","settings":{` + guids + `}}`, true},
		{"agentforce", "ok", `{"base_url":"https://acme.my.salesforce.com","correlation_key":"id"}`, false},
		{"agentforce", "other host", `{"base_url":"https://evil.example.com","correlation_key":"id"}`, true},
		{"agentforce", "metadata", `{"base_url":"https://169.254.169.254","correlation_key":"id"}`, true},
	} {
		t.Run(tc.typ+" "+tc.name, func(t *testing.T) {
			gt, _ := governed.Lookup(tc.typ)
			r, ok := template.MustDefault().Get(gt.Template)
			if !ok {
				t.Fatal("no template")
			}
			cfg, err := DecodeConfig([]byte(tc.cfg))
			if err != nil {
				t.Fatal(err)
			}
			errs := ValidateConnEnv(cfg, r, tc.typ, "prod")
			var onURL bool
			for _, fe := range errs {
				onURL = onURL || fe.Field == "base_url"
			}
			if onURL != tc.bad || (!tc.bad && len(errs) != 0) {
				t.Errorf("errors %v, want a base_url error: %v", errs, tc.bad)
			}
		})
	}
}
