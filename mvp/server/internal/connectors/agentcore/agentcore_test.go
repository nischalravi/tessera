package agentcore

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

var tenantA = tenancy.MustParse("00000000-0000-4000-8000-0000000000e1")

func fixtureConnector(t *testing.T) *Connector {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("testdata", "runtimes.json"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(FileAPI{Path: abs}, func() time.Time { return testkit.Now })
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDiscoverMapsRuntimes(t *testing.T) {
	res, err := fixtureConnector(t).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Identities) != 3 || len(res.Agents) != 3 || len(res.Accounts) != 3 || len(res.AgentSnapshotOf) != 1 {
		t.Fatalf("identities %d agents %d accounts %d snapshot %v", len(res.Identities), len(res.Agents), len(res.Accounts), res.AgentSnapshotOf)
	}
	byX := map[string]connectors.IdentityRecord{}
	for _, i := range res.Identities {
		byX[i.ExternalID] = i
	}
	support := byX["agentcore:support_copilot-AbC123"]
	if support.Type != "ai_agent" || support.Owner == nil || support.Owner.Email != "ada.fixture@example.com" || support.Status != "active" {
		t.Errorf("support = %+v", support)
	}
	if ops := byX["agentcore:ops_agent-XyZ789"]; ops.Owner != nil {
		t.Errorf("ops agent has no sponsor tag but owner = %+v", ops.Owner)
	}
	if old := byX["agentcore:old_bot-Q1w2e3"]; old.Status != "disabled" {
		t.Errorf("a deleting runtime is %q", old.Status)
	}
	rec := map[string]connectors.AgentRecord{}
	for _, a := range res.Agents {
		rec[a.ExternalID] = a
	}
	if r := rec["support_copilot-AbC123"]; r.Kind != AgentKind || r.CreatorRef != "ben.sample@fixture.example" || r.Creator == nil {
		t.Errorf("support record = %+v", r)
	}
	// with no creator tag the creator is the principal that created the runtime: a name, not an identity
	if r := rec["ops_agent-XyZ789"]; r.CreatorRef != "arn:aws:iam::111122223333:user/dana" || r.Creator != nil {
		t.Errorf("ops record = %+v", r)
	}
	if len(res.Secrets) != 2 || res.Secrets[0].Kind != "oauth_client_secret" {
		t.Errorf("secrets = %+v", res.Secrets)
	}
}

func TestDiscoverIsDeterministicAndReadOnly(t *testing.T) {
	c := fixtureConnector(t)
	a, err := c.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.Discover(context.Background())
	if len(a.Edges) != len(b.Edges) || len(a.Permissions) != len(b.Permissions) {
		t.Error("two reads of one snapshot differ")
	}
	if err := c.StreamEvents(context.Background(), nil, nil); err != nil {
		t.Errorf("StreamEvents = %v", err)
	}
}

func TestSnapshotErrors(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"runtimes": [`), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]string{"missing": filepath.Join(dir, "none.json"), "malformed": bad} {
		c, _ := New(FileAPI{Path: p}, nil)
		if _, err := c.Discover(context.Background()); err == nil {
			t.Errorf("%s snapshot: no error", name)
		}
	}
	badID := filepath.Join(dir, "id.json")
	if err := os.WriteFile(badID, []byte(`{"runtimes":[{"id":"../x","name":"n"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, _ := New(FileAPI{Path: badID}, nil)
	if _, err := c.Discover(context.Background()); err == nil || !strings.Contains(err.Error(), "not valid") {
		t.Errorf("invalid runtime id: err = %v", err)
	}
}

func TestFromEnvRefusals(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if _, err := FromEnv(env(map[string]string{"TESSERA_ENV": "prod", "TESSERA_AGENTCORE_SNAPSHOT": "/x.json"}), testkit.Now); err == nil {
		t.Error("a snapshot connector was built in prod")
	}
	if _, err := FromEnv(env(map[string]string{"TESSERA_ENV": "dev"}), testkit.Now); err == nil {
		t.Error("built without a snapshot")
	}
	if _, err := FromEnv(env(map[string]string{"TESSERA_ENV": "dev", "TESSERA_AGENTCORE_SNAPSHOT": "relative.json"}), testkit.Now); err == nil {
		t.Error("a relative snapshot path was accepted")
	}
	if c, err := FromEnv(env(map[string]string{"TESSERA_ENV": "dev", "TESSERA_AGENTCORE_SNAPSHOT": "/abs/x.json"}), testkit.Now); err != nil || c.System() != System {
		t.Errorf("dev with a snapshot: %v, %v", c, err)
	}
}

type hr struct{}

func (hr) System() string      { return "workday" }
func (hr) DisplayName() string { return "HR (test)" }
func (hr) TypeName() string    { return "TestHR" }
func (hr) Discover(context.Context) (*connectors.DiscoveryResult, error) {
	e := "ada.fixture@example.com"
	return &connectors.DiscoveryResult{Identities: []connectors.IdentityRecord{
		{ExternalID: "EMP-2001", Name: "Ada Fixture", Type: "human", Email: &e, Status: "active"}}}, nil
}
func (hr) StreamEvents(context.Context, *time.Time, func(connectors.Event) error) error { return nil }

// An agent with no active sponsor, one that reaches PII and one holding
// privileged prod access each raise a violation of an existing policy.
func TestIngestRaisesTheExistingPolicies(t *testing.T) {
	db := testkit.Open(t)
	testkit.CreateTenant(t, db, tenantA, "agentcore")
	err := db.InTenant(context.Background(), tenantA, func(c *store.TenantTx) error {
		_, err := ingest.Sync(c, testkit.Now, []connectors.Connector{hr{}, fixtureConnector(t)}, nil)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	testkit.Read(t, &testkit.DB{DB: db, Tenant: tenantA}, func(tx *store.TenantTx) error {
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
			got[v.PolicyID+"/"+v.IdentityName] = true
		}
		for _, want := range []string{"nhi-ownership/ops-agent", "ai-agents-no-pii/support-copilot", "nhi-no-prod-admin/ops-agent"} {
			if !got[want] {
				t.Errorf("missing violation %s; got %v", want, got)
			}
		}
		for _, not := range []string{"nhi-ownership/support-copilot", "ai-agents-no-pii/ops-agent", "nhi-ownership/old-bot"} {
			if got[not] {
				t.Errorf("unexpected violation %s", not)
			}
		}
		ps, err := tx.AgentProfiles()
		if err != nil || len(ps) != 3 {
			t.Errorf("profiles = %d, %v", len(ps), err)
		}
		return nil
	})
}
