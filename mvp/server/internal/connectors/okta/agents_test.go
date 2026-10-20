package okta

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

const (
	agentSupport = "0oa1agentsupport01" // service app, sponsored
	agentOrphan  = "0oa1agentorphan001" // service app, no sponsor
	webApp       = "0oa1webapp0000001"  // not a service app
)

// withAgents serves the service apps and their credential and grant listings.
func (f *fake) withAgents() {
	f.body["/api/v1/apps"] = string(connsynctest.Fixture(f.t, "apps_agents.json", f.srv.URL))
	for _, id := range []string{agentSupport, agentOrphan, webApp} {
		f.body["/api/v1/apps/"+id+"/users"] = `[]`
		f.body["/api/v1/apps/"+id+"/groups"] = `[]`
		f.body["/api/v1/apps/"+id+"/credentials/secrets"] = `[]`
		f.body["/api/v1/apps/"+id+"/credentials/jwks"] = `[]`
		f.body["/api/v1/apps/"+id+"/grants"] = `[]`
	}
	f.body["/api/v1/apps/"+agentSupport+"/credentials/secrets"] = string(connsynctest.Fixture(f.t, "agent_secrets.json", f.srv.URL))
	f.body["/api/v1/apps/"+agentSupport+"/credentials/jwks"] = string(connsynctest.Fixture(f.t, "agent_jwks.json", f.srv.URL))
	f.body["/api/v1/apps/"+agentSupport+"/grants"] = string(connsynctest.Fixture(f.t, "agent_grants.json", f.srv.URL))
}

func agentCfg() Config {
	c := ssws()
	c.DiscoverAgents = true
	return c
}

func identity(res *connectors.DiscoveryResult, xid string) *connectors.IdentityRecord {
	for i := range res.Identities {
		if res.Identities[i].ExternalID == xid {
			return &res.Identities[i]
		}
	}
	return nil
}

func TestAgentsAreOffByDefault(t *testing.T) {
	f := newFake(t)
	f.withAgents()
	res, err := f.connector(ssws()).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Agents) != 0 || len(res.AgentSnapshotOf) != 0 || f.srv.Count("/api/v1/apps/"+agentSupport+"/credentials") != 0 {
		t.Errorf("agents = %d, snapshot %v", len(res.Agents), res.AgentSnapshotOf)
	}
}

func TestAgentsDiscovered(t *testing.T) {
	f := newFake(t)
	f.withAgents()
	res, err := f.connector(agentCfg()).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Agents) != 2 || len(res.AgentSnapshotOf) != 1 || res.AgentSnapshotOf[0] != System {
		t.Fatalf("agents = %d, snapshot %v (the web app is not an agent)", len(res.Agents), res.AgentSnapshotOf)
	}
	support := identity(res, "okta-app:"+agentSupport)
	if support == nil || support.Type != "ai_agent" || support.Name != "Support Triage Agent" ||
		support.Owner == nil || support.Owner.Email != "ada.fixture@example.com" {
		t.Errorf("support agent = %+v", support)
	}
	if o := identity(res, "okta-app:"+agentOrphan); o == nil || o.Type != "ai_agent" || o.Owner != nil {
		t.Errorf("orphan agent = %+v", o)
	}
	if identity(res, "okta-app:"+webApp) != nil {
		t.Error("a web app became an agent")
	}
	rec := map[string]connectors.AgentRecord{}
	for _, a := range res.Agents {
		rec[a.ExternalID] = a
	}
	if r := rec[agentSupport]; r.Kind != AgentKind || r.CreatorRef != "ben.sample@fixture.example" || r.SponsorRef != "ada.fixture@example.com" {
		t.Errorf("support record = %+v", r)
	}
	if r := rec[agentOrphan]; r.Sponsor != nil || r.SponsorRef != "" {
		t.Errorf("orphan record = %+v", r)
	}
	// credentials: the active secret and the key, by id and date; not the inactive secret
	var secrets []string
	for _, s := range res.Secrets {
		secrets = append(secrets, s.ExternalID+" "+s.Kind)
	}
	if len(secrets) != 2 || secrets[0] != agentSupport+":ocs1secretactive01 client_secret" || secrets[1] != agentSupport+":pks1key0000000001 jwk" {
		t.Errorf("secrets = %v", secrets)
	}
	raw, _ := json.Marshal(res)
	if strings.Contains(string(raw), "SHOULD-NEVER-BE-READ") {
		t.Error("secret material from the credential responses reached the result")
	}
	// scopes: the active grants only; a .manage scope is privileged
	privileged := map[string]bool{}
	for _, p := range res.Permissions {
		if p.ResourceExternalID == apiResource {
			privileged[p.Action] = p.Privileged
		}
	}
	if len(privileged) != 2 || privileged["okta.users.read"] || !privileged["okta.groups.manage"] {
		t.Errorf("scope permissions = %v", privileged)
	}
}

func TestAgentsForbiddenCredentialsAreSkipped(t *testing.T) {
	f := newFake(t)
	f.withAgents()
	f.status["/api/v1/apps/"+agentSupport+"/credentials"] = 403
	f.status["/api/v1/apps/"+agentSupport+"/grants"] = 403
	res, err := f.connector(agentCfg()).Discover(context.Background())
	if err != nil {
		t.Fatalf("a missing scope failed the sync: %v", err)
	}
	if len(res.Agents) != 2 || len(res.Secrets) != 0 {
		t.Errorf("agents = %d, secrets = %d", len(res.Agents), len(res.Secrets))
	}
}

func TestAgentsIngestAndViolations(t *testing.T) {
	f := newFake(t)
	f.withAgents()
	db := testkit.Open(t)
	testkit.CreateTenant(t, db, tenantA, "okta-agents")
	st := syncTenant(t, db, tenantA, context.Background(), hr{}, f.connector(agentCfg()))
	if st.Discovery.Agents != 2 {
		t.Fatalf("agents = %d", st.Discovery.Agents)
	}
	testkit.Read(t, &testkit.DB{DB: db, Tenant: tenantA}, func(tx *store.TenantTx) error {
		idents, _ := tx.Identities()
		byXID := map[string]*store.Identity{}
		for _, i := range idents {
			byXID[i.ExternalID] = i
		}
		// Ada is not in this test's HR, so the sponsor does not resolve: both agents are unowned.
		if a := byXID["okta-app:"+agentSupport]; a == nil || a.Type != "ai_agent" || a.OwnerID != nil {
			t.Errorf("support agent = %+v", a)
		}
		secrets, _ := tx.Secrets()
		if len(secrets) != 2 {
			t.Errorf("secrets = %d", len(secrets))
		}
		g, err := graph.Build(tx, testkit.Now)
		if err != nil {
			t.Fatal(err)
		}
		pols, err := policy.NewLoader(policies.FS).Load()
		if err != nil {
			t.Fatal(err)
		}
		viol, err := policy.Evaluate(pols, policy.NewContext(g, tx, testkit.Now))
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, v := range viol {
			if v.PolicyID == "nhi-ownership" {
				got[v.IdentityName] = true
			}
		}
		if !got["Support Triage Agent"] || !got["Research Agent"] {
			t.Errorf("nhi-ownership violations = %v", got)
		}
		eff := g.EffectivePermissions(byXID["okta-app:"+agentSupport].ID)
		if eff.Len() != 2 {
			t.Errorf("support agent's effective permissions = %d, want its two granted scopes", eff.Len())
		}
		return nil
	})
}
