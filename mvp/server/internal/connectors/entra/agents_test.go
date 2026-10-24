package entra

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

const (
	agentSupport = "dddddddd-0000-4000-8000-000000000001" // sponsored by an active user
	agentOrphan  = "dddddddd-0000-4000-8000-000000000002" // no sponsor
	agentLeft    = "dddddddd-0000-4000-8000-000000000003" // sponsor's account is disabled

	blueprintSupport = "bbbbbbbb-0000-4000-8000-000000000001" // sponsored by Ada
	blueprintNoOwner = "bbbbbbbb-0000-4000-8000-000000000002" // no sponsor
	// agents link to a blueprint by its appId, which differs from its object id
	blueprintSupportApp = "55550000-0000-4000-8000-000000000001"
)

// Blueprints, the agent-to-blueprint link (by appId) and managerApplications (issue #478).
func TestBlueprintsAndManagerDiscovered(t *testing.T) {
	f := newFake(t)
	f.withAgents()
	res, err := f.connector(agentCfg()).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Blueprints) != 2 {
		t.Fatalf("blueprints = %+v", res.Blueprints)
	}
	b := res.Blueprints[0]
	if b.ExternalID != blueprintSupport || b.Name != "Support Agent Blueprint" || b.SponsorRef != "ada.fixture@example.com" ||
		b.Sponsor == nil || b.CreatorRef != "app:11110000-0000-4000-8000-000000000001" {
		t.Errorf("support blueprint = %+v", b)
	}
	if o := res.Blueprints[1]; o.ExternalID != blueprintNoOwner || o.Sponsor != nil || o.SponsorRef != "" {
		t.Errorf("unsponsored blueprint = %+v", o)
	}
	for _, a := range res.Agents {
		switch a.ExternalID {
		case agentSupport:
			if a.BlueprintAppID != blueprintSupportApp || len(a.ManagerApplications) != 1 || a.ManagerApplications[0] != "66660000-0000-4000-8000-000000000001" {
				t.Errorf("support agent link = %+v", a)
			}
		default:
			if a.BlueprintAppID != "" || len(a.ManagerApplications) != 0 {
				t.Errorf("agent %s link = %+v, want none", a.ExternalID, a)
			}
		}
	}
}

func TestBlueprintsUnavailableIsNotAFailure(t *testing.T) {
	f := newFake(t)
	f.withAgents()
	f.status["/beta/applications"] = 403
	res, err := f.connector(agentCfg()).Discover(context.Background())
	if err != nil || len(res.Blueprints) != 0 || len(res.Agents) != 3 {
		t.Errorf("blueprints = %d, agents = %d, err = %v", len(res.Blueprints), len(res.Agents), err)
	}
	if len(res.BlueprintSnapshotOf) != 0 || res.Partial == "" || strings.Contains(res.Partial, "leaky") {
		t.Errorf("a failed blueprint list claimed a snapshot or hid the error: snapshot %v, partial %q", res.BlueprintSnapshotOf, res.Partial)
	}
}

// A blueprint list that fails (403) must not delete the blueprints stored earlier.
func TestBlueprintsSurviveAFailedList(t *testing.T) {
	f := newFake(t)
	f.withAgents()
	db := testkit.Open(t)
	testkit.CreateTenant(t, db, tenantA, "entra-bp-survive")
	syncTenant(t, db, tenantA, context.Background(), hr{}, f.connector(agentCfg()))
	f.status["/beta/applications"] = 403
	syncTenant(t, db, tenantA, context.Background(), hr{}, f.connector(agentCfg()))
	testkit.Read(t, &testkit.DB{DB: db, Tenant: tenantA}, func(tx *store.TenantTx) error {
		if bps, _ := tx.AgentBlueprints(); len(bps) != 2 {
			t.Errorf("blueprints after a 403 = %d, want the 2 stored before", len(bps))
		}
		return nil
	})
}

// withAgents serves the Agent ID fixtures (Graph beta) next to the directory ones.
func (f *fake) withAgents() {
	f.body["/beta/servicePrincipals/microsoft.graph.agentIdentity"] = string(connsynctest.Fixture(f.t, "agents.json", f.srv.URL))
	for i, id := range []string{agentSupport, agentOrphan, agentLeft} {
		name := "agent_sponsors_" + string(rune('1'+i)) + ".json"
		f.body["/beta/servicePrincipals/"+id+"/microsoft.graph.agentIdentity/sponsors"] = string(connsynctest.Fixture(f.t, name, f.srv.URL))
	}
	f.body["/beta/applications/"+blueprintNoOwner+"/microsoft.graph.agentIdentityBlueprint/sponsors"] = `{"value":[]}`
	f.body["/beta/applications/microsoft.graph.agentIdentityBlueprint"] = string(connsynctest.Fixture(f.t, "blueprints.json", f.srv.URL))
	f.body["/beta/applications/"+blueprintSupport+"/microsoft.graph.agentIdentityBlueprint/sponsors"] = string(connsynctest.Fixture(f.t, "blueprint_sponsors_1.json", f.srv.URL))
}

func agentCfg() Config {
	c := baseCfg()
	c.DiscoverAgents = true
	return c
}

func identityOf(res *connectors.DiscoveryResult, xid string) *connectors.IdentityRecord {
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
	res, err := f.connector(baseCfg()).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Agents) != 0 || len(res.AgentSnapshotOf) != 0 || f.srv.Count("/beta") != 0 {
		t.Errorf("agents = %d, snapshot %v, beta requests %d", len(res.Agents), res.AgentSnapshotOf, f.srv.Count("/beta"))
	}
	if identityOf(res, "entra-sp:"+spBilling).Type != "service" {
		t.Error("a service principal stopped being a service identity")
	}
}

func TestAgentsDiscovered(t *testing.T) {
	f := newFake(t)
	f.withAgents()
	res, err := f.connector(agentCfg()).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Agents) != 3 || len(res.AgentSnapshotOf) != 1 || res.AgentSnapshotOf[0] != System {
		t.Fatalf("agents = %d, snapshot %v", len(res.Agents), res.AgentSnapshotOf)
	}
	support := identityOf(res, "entra-sp:"+agentSupport)
	if support == nil || support.Type != "ai_agent" || support.Name != "Support Triage Agent" ||
		support.Owner == nil || support.Owner.Email != "ada.fixture@example.com" {
		t.Errorf("support agent identity = %+v", support)
	}
	for _, id := range []string{agentOrphan, agentLeft} {
		if a := identityOf(res, "entra-sp:"+id); a == nil || a.Type != "ai_agent" || a.Owner != nil {
			t.Errorf("agent %s without an active sponsor: %+v", id, a)
		}
	}
	if identityOf(res, "entra-sp:"+spBilling).Type != "service" {
		t.Error("the ordinary service principal changed type")
	}
	kinds := map[string]string{}
	for _, a := range res.Accounts {
		kinds[a.ExternalID] = a.Kind
	}
	for _, id := range []string{agentSupport, agentOrphan, agentLeft} {
		if kinds[id] != "agent" {
			t.Errorf("account %s kind = %q, want agent", id, kinds[id])
		}
	}
	// provenance: creator and sponsor as Entra spells them
	rec := map[string]connectors.AgentRecord{}
	for _, a := range res.Agents {
		rec[a.ExternalID] = a
	}
	if r := rec[agentSupport]; r.Kind != AgentKind || r.CreatorRef != "app:11110000-0000-4000-8000-000000000001" ||
		r.SponsorRef != "ada.fixture@example.com" || r.Sponsor == nil {
		t.Errorf("support record = %+v", r)
	}
	if r := rec[agentLeft]; r.SponsorRef != "Ben.Sample@Fixture.onmicrosoft.com" || r.Sponsor != nil {
		t.Errorf("left-sponsor record = %+v (a disabled sponsor must be named but not active)", r)
	}
	if r := rec[agentOrphan]; r.SponsorRef != "" || r.Sponsor != nil || r.CreatorRef != "" {
		t.Errorf("orphan record = %+v", r)
	}
	// credentials: the live secret and certificate, not the expired secret; ids and names only
	var secrets []string
	for _, s := range res.Secrets {
		if strings.HasPrefix(s.ExternalID, agentSupport+":") {
			secrets = append(secrets, s.Kind+"/"+s.Name)
		}
	}
	if len(secrets) != 2 || secrets[0] != "client_secret/triage secret" || secrets[1] != "certificate/triage cert" {
		t.Errorf("secrets = %v", secrets)
	}
	raw, _ := json.Marshal(res)
	for _, leak := range []string{"zq7", "hint", "secretText"} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("the result carries %q from the credential response", leak)
		}
	}
}

func TestAgentsUnavailableIsNotAFailure(t *testing.T) {
	f := newFake(t)
	f.withAgents()
	f.status["/beta/"] = 403
	res, err := f.connector(agentCfg()).Discover(context.Background())
	if err != nil {
		t.Fatalf("a tenant without Agent ID access failed the sync: %v", err)
	}
	if len(res.Agents) != 0 || len(res.AgentSnapshotOf) != 0 {
		t.Errorf("agents = %d, snapshot %v: nothing may be claimed as a snapshot", len(res.Agents), res.AgentSnapshotOf)
	}
	if identityOf(res, "entra-sp:"+spBilling) == nil {
		t.Error("the directory read was lost")
	}
}

func TestAgentsServerError(t *testing.T) {
	f := newFake(t)
	f.withAgents()
	f.status["/beta/"] = 500
	f.statusBody["/beta/"] = `{"error":{"code":"x","message":"leaky-body-should-never-surface"}}`
	c := f.connector(agentCfg())
	c.api.Backoff = connsync.Backoff{Base: 1, Max: 1, MaxAttempts: 1, Sleep: (&connsynctest.NoSleep{}).Sleep}
	_, err := c.Discover(context.Background())
	if err == nil || strings.Contains(err.Error(), "leaky") {
		t.Errorf("err = %v, want a failure that does not quote the body", err)
	}
}

// Agents end up in the graph as ai_agent identities and the existing
// nhi-ownership policy reports the ones with no active sponsor.
func TestAgentsIngestAndOwnershipViolations(t *testing.T) {
	f := newFake(t)
	f.withAgents()
	db := testkit.Open(t)
	testkit.CreateTenant(t, db, tenantA, "entra-agents")
	st := syncTenant(t, db, tenantA, context.Background(), hr{}, f.connector(agentCfg()))
	if st.Discovery.Agents != 3 {
		t.Fatalf("agents = %d", st.Discovery.Agents)
	}
	tdb := &testkit.DB{DB: db, Tenant: tenantA}
	testkit.Read(t, tdb, func(tx *store.TenantTx) error {
		idents, _ := tx.Identities()
		byXID := map[string]*store.Identity{}
		for _, i := range idents {
			byXID[i.ExternalID] = i
		}
		support := byXID["entra-sp:"+agentSupport]
		if support.Type != "ai_agent" || support.OwnerID == nil || *support.OwnerID != byXID["EMP-2001"].ID {
			t.Errorf("support agent = %+v, want an ai_agent owned by Ada", support)
		}
		profiles, err := tx.AgentProfiles()
		if err != nil || len(profiles) != 3 {
			t.Fatalf("profiles = %v, %v", profiles, err)
		}
		for _, p := range profiles {
			if p.Source != System || p.Kind != AgentKind {
				t.Errorf("profile = %+v", p)
			}
			if p.ExternalID == agentSupport && (p.SponsorID == nil || *p.SponsorID != byXID["EMP-2001"].ID) {
				t.Errorf("support sponsor = %v", p.SponsorID)
			}
		}
		bps, _ := tx.AgentBlueprints()
		links, _ := tx.AgentLinks()
		if len(bps) != 2 || bps[0].SponsorID == nil || *bps[0].SponsorID != byXID["EMP-2001"].ID || bps[1].SponsorID != nil {
			t.Errorf("blueprints = %+v", bps)
		}
		if len(links) != 1 || links[0].ExternalID != agentSupport || links[0].BlueprintAppID != blueprintSupportApp ||
			links[0].ManagerApplications != "66660000-0000-4000-8000-000000000001" {
			t.Errorf("links = %+v", links)
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
		if !got["Orphan Research Agent"] || !got["Left Sponsor Agent"] || got["Support Triage Agent"] {
			t.Errorf("nhi-ownership violations = %v", got)
		}
		return nil
	})

	// a second sync with the sponsorless agent gone from Entra removes its profile
	f.body["/beta/servicePrincipals/microsoft.graph.agentIdentity"] = `{"value":[]}`
	f.body["/beta/applications/microsoft.graph.agentIdentityBlueprint"] = `{"value":[]}`
	syncTenant(t, db, tenantA, context.Background(), hr{}, f.connector(agentCfg()))
	testkit.Read(t, tdb, func(tx *store.TenantTx) error {
		if bps, _ := tx.AgentBlueprints(); len(bps) != 0 {
			t.Errorf("blueprints after they left Entra = %d", len(bps))
		}
		if ls, _ := tx.AgentLinks(); len(ls) != 0 {
			t.Errorf("links after the agents left Entra = %d", len(ls))
		}
		if ps, _ := tx.AgentProfiles(); len(ps) != 0 {
			t.Errorf("profiles after the agents left Entra = %d", len(ps))
		}
		return nil
	})
}
