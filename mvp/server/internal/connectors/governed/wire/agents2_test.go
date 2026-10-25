package wire_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/agentforce/agentforcefake"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/copilotstudio/copilotfake"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/foundryagents/foundryfake"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed/wire"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/vertexagents/vertexfake"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/checks"
)

const (
	vxSA   = "tessera-reader@acme-agents-prod.iam.gserviceaccount.com"
	sfKey  = "3MVG9ExampleConsumerKey"
	sfUser = "integration@acme.example"
)

type agentRig struct {
	p        governed.Params
	n        governed.Net
	system   string
	template string
	agents   int
}

func vertexRig(t *testing.T) agentRig {
	t.Helper()
	fk := vertexfake.New(vxSA, "acme-agents-prod", "us-central1",
		vertexfake.Engine{ID: "1001", DisplayName: "support", ServiceAccount: "agent@acme-agents-prod.iam.gserviceaccount.com", Secrets: []string{"crm"}},
		vertexfake.Engine{ID: "1002", DisplayName: "other"})
	srv, n := serve(t, fk)
	n.Endpoints = map[string]string{"TESSERA_VERTEX_API_URL": srv.URL, "TESSERA_VERTEX_TOKEN_URL": srv.URL + "/token"}
	return agentRig{governed.Params{Type: governed.Vertex, Secret: vertexfake.Key(vxSA),
		Settings: map[string]string{"project_id": "acme-agents-prod", "location": "us-central1", "owner": "olu@acme.example"}}, n, "gcp-vertex", "vertex", 2}
}

func foundryRig(t *testing.T) agentRig {
	t.Helper()
	fk := foundryfake.New(azTenant, azClient, azSecret,
		foundryfake.Agent{ID: "asst_1", Name: "support", Metadata: map[string]string{"sponsor": "pat@acme.example"}, Tools: []map[string]any{{"type": "code_interpreter"}}},
		foundryfake.Agent{ID: "asst_2", Name: "other"})
	srv, n := serve(t, fk)
	n.Endpoints = map[string]string{"TESSERA_FOUNDRY_AUTHORITY_URL": srv.URL}
	return agentRig{governed.Params{Type: governed.Foundry, BaseURL: srv.URL + "/api/projects/support", Secret: azSecret,
		Settings: map[string]string{"tenant_id": azTenant, "client_id": azClient}}, n, "azure-foundry", "foundry", 2}
}

func copilotRig(t *testing.T) agentRig {
	t.Helper()
	fk := copilotfake.New(azTenant, azClient, azSecret, map[string]string{"a0000000-0000-0000-0000-000000000001": "pat@acme.example"},
		[]copilotfake.Bot{{ID: "b0000000-0000-0000-0000-00000000000a", Name: "HR", Schema: "cr1_hr", AuthMode: 2, Owner: "a0000000-0000-0000-0000-000000000001"},
			{ID: "b0000000-0000-0000-0000-00000000000b", Name: "FAQ", Schema: "cr1_faq", AuthMode: 1}},
		[]copilotfake.Component{{ID: "c0000000-0000-0000-0000-000000000001", Name: "Mail", Schema: "cr1_hr.action.Mail", Bot: "b0000000-0000-0000-0000-00000000000a"}})
	srv, n := serve(t, fk)
	n.Endpoints = map[string]string{"TESSERA_COPILOT_AUTHORITY_URL": srv.URL}
	return agentRig{governed.Params{Type: governed.Copilot, BaseURL: srv.URL, Secret: azSecret,
		Settings: map[string]string{"tenant_id": azTenant, "client_id": azClient}}, n, "copilot-studio", "copilot", 2}
}

func agentforceRig(t *testing.T) agentRig {
	t.Helper()
	fk := agentforcefake.New(sfKey, sfUser, map[string]string{"005000000000002AAA": "pat@acme.example"},
		[]agentforcefake.Bot{{ID: "0Xx000000000001AAA", Dev: "Service_Agent", Label: "Service", Type: "ExternalCopilot", Owner: "005000000000002AAA"},
			{ID: "0Xx000000000002AAA", Dev: "Other", Label: "Other", Type: "InternalCopilot"}},
		map[string]string{"16j000000000001AAA": "Service_Agent"},
		[]agentforcefake.Function{{ID: "1Tj000000000001AAA", Dev: "Create_Case", Target: "Create_Case_Flow", TargetType: "flow"}},
		[][2]string{{"16j000000000001AAA", "1Tj000000000001AAA"}})
	srv, n := serve(t, fk)
	return agentRig{governed.Params{Type: governed.Agentforce, BaseURL: srv.URL, Secret: agentforcefake.Credential(sfKey, sfUser)}, n, "salesforce-agentforce", "agentforce", 2}
}

var agentRigs = map[string]func(*testing.T) agentRig{"vertex": vertexRig, "foundry": foundryRig, "copilot": copilotRig, "agentforce": agentforceRig}

func TestAgentPlatformProbersAndConnectors(t *testing.T) {
	for name, mk := range agentRigs {
		t.Run(name, func(t *testing.T) {
			r := mk(t)
			pr := prober(t, r.p, r.n)
			wantPass(t, pr, r.template, "auth_ok", "read_probe")
			auth, err := pr.Authenticate(context.Background())
			if err != nil || !auth.OK || auth.Identity == "" || auth.Mode == "" {
				t.Errorf("auth = %+v, %v", auth, err)
			}
			s, err := pr.Sample(context.Background(), connectors.SampleQuery{Op: "probe"})
			if err != nil || !s.Available || s.PerClass["agent"] != r.agents {
				t.Errorf("sample = %+v, %v", s, err)
			}
			cn, err := wire.Connector(r.p, r.n)
			if err != nil {
				t.Fatal(err)
			}
			res, err := cn.Discover(context.Background())
			if err != nil || cn.System() != r.system || len(res.Agents) != r.agents || res.Stats == nil || len(res.Permissions) == 0 {
				t.Fatalf("discover = %+v, %v", res, err)
			}
			if o := res.Identities[0].Owner; o == nil && name != "vertex" || name == "vertex" && (o == nil || o.Email != "olu@acme.example") {
				t.Errorf("owner = %+v", o)
			}
		})
	}
}

func TestAgentPlatformProber_WrongCredential(t *testing.T) {
	for name, bad := range map[string]func(*agentRig){
		"vertex": func(r *agentRig) {
			r.p.Secret = vertexfake.Key("someone-else@acme-agents-prod.iam.gserviceaccount.com")
		},
		"foundry":    func(r *agentRig) { r.p.Secret = "x" + azSecret },
		"copilot":    func(r *agentRig) { r.p.Secret = "x" + azSecret },
		"agentforce": func(r *agentRig) { r.p.Secret = agentforcefake.Credential("wrong-consumer-key", sfUser) },
	} {
		t.Run(name, func(t *testing.T) {
			r := agentRigs[name](t)
			bad(&r)
			if res := run(t, prober(t, r.p, r.n), "auth_ok", checks.Env{TemplateID: r.template}); res.Status != checks.Fail {
				t.Errorf("auth_ok with a wrong credential: %s %s", res.Status, res.Message)
			}
		})
	}
}

// A connection never carries an endpoint override, and the wiring refuses one outside dev. The hosts the
// bearer token goes to are the public ones in prod.
func TestAgentPlatformEndpointOverridesAreRefusedOutsideDev(t *testing.T) {
	for name, mk := range agentRigs {
		t.Run(name, func(t *testing.T) {
			r := mk(t)
			if len(r.n.Endpoints) > 0 {
				for _, env := range []string{config.Prod, config.Test} {
					r.n.RT = connsync.Runtime{Env: env}
					if _, err := wire.Prober(r.p, r.n); err == nil || !strings.Contains(err.Error(), "refused outside dev") {
						t.Errorf("%s prober: %v", env, err)
					}
					if _, err := wire.Connector(r.p, r.n); err == nil {
						t.Errorf("%s connector accepted an override", env)
					}
				}
				r.n.Endpoints = map[string]string{"TESSERA_" + strings.ToUpper(name) + "_OTHER": "https://x.example"}
				r.n.RT = connsync.Runtime{Env: config.Dev}
				if _, err := wire.Prober(r.p, r.n); err == nil {
					t.Error("an unknown override key was accepted")
				}
			}
			// a host that is not the vendor's is refused in prod whatever the connection says
			r.n.Endpoints, r.n.RT = nil, connsync.Runtime{Env: config.Prod}
			if _, err := wire.Prober(r.p, r.n); (err == nil) != (r.p.BaseURL == "") {
				t.Errorf("a connection to a loopback host in prod: %v", err)
			}
		})
	}
}

func TestAgentPlatformPublicHostsInProd(t *testing.T) {
	prod := connsync.Runtime{Env: config.Prod}
	for _, p := range []governed.Params{
		{Type: governed.Vertex, Secret: vertexfake.Key(vxSA), Settings: map[string]string{"project_id": "acme-agents-prod", "location": "us-central1"}},
		{Type: governed.Foundry, BaseURL: "https://acme.services.ai.azure.com/api/projects/support", Secret: azSecret, Settings: map[string]string{"tenant_id": azTenant, "client_id": azClient}},
		{Type: governed.Copilot, BaseURL: "https://acme.crm.dynamics.com", Secret: azSecret, Settings: map[string]string{"tenant_id": azTenant, "client_id": azClient}},
		{Type: governed.Agentforce, BaseURL: "https://acme.my.salesforce.com", Secret: agentforcefake.Credential(sfKey, sfUser)},
	} {
		_, n := serve(t, nil)
		n.RT = prod
		if _, err := wire.Prober(p, n); err != nil {
			t.Errorf("%s: %v", p.Type, err)
		}
		if _, err := wire.Connector(p, n); err != nil {
			t.Errorf("%s connector: %v", p.Type, err)
		}
		q := p
		q.BaseURL = "https://evil.example" + strings.TrimPrefix(strings.TrimPrefix(p.BaseURL, "https://"), strings.SplitN(strings.TrimPrefix(p.BaseURL, "https://"), "/", 2)[0])
		if p.BaseURL != "" {
			if _, err := wire.Prober(q, n); err == nil {
				t.Errorf("%s: %s accepted in prod", p.Type, q.BaseURL)
			}
		}
	}
}

func TestAgentPlatformsPart2ParamsNeverPrintTheSecret(t *testing.T) {
	for name, mk := range agentRigs {
		r := mk(t)
		r.p.Secret = "TOP-SECRET-VALUE"
		for _, f := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if got := fmt.Sprintf(f, r.p); strings.Contains(got, "TOP-SECRET-VALUE") {
				t.Errorf("%s %s prints the secret: %s", name, f, got)
			}
		}
		env, err := r.p.Env()
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"KEY", "CREDENTIAL"} {
			if v := env("TESSERA_" + strings.ToUpper(name) + "_" + k); v != "" && (strings.Contains(v, "TOP-SECRET") || !strings.HasPrefix(v, "env:")) {
				t.Errorf("%s %s = %q", name, k, v)
			}
		}
		for _, k := range []string{"API_URL", "TOKEN_URL", "AUTHORITY_URL"} {
			if v := env("TESSERA_" + strings.ToUpper(name) + "_" + k); v != "" {
				t.Errorf("%s: a connection carries an endpoint override %s = %q", name, k, v)
			}
		}
	}
}
