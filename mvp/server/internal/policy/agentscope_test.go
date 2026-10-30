package policy_test

import (
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/agentscope"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// Agent scopes (issue #653, AC-7) over the tiny world: helper-bot is an AI agent owned by Alice that holds
// snowflake:SELECT on CUSTOMERS (prod, pii), which is a read; Alice holds s3 permissions only. svc-etl is not an
// agent, but a profile row makes it one for the purpose of the selector: it holds s3:GetObject on customer-pii,
// which its (terminated) owner Dave holds too.

func scopeDoc(key, source, ext string, actions, systems []string, extra string) string {
	return "schema: tessera.agentscope/v1\nkey: " + key + "\nname: " + key + "\nagent:\n  source: " + source +
		"\n  external_id: " + ext + "\nallow:\n  actions: [" + strings.Join(actions, ",") + "]\n  resources:\n    - systems: [" +
		strings.Join(systems, ",") + "]\n" + extra
}

// putScope stores a scope document as an active scope.
func putScope(t *testing.T, st *testkit.DB, doc string, status string) {
	t.Helper()
	d, fs := agentscope.Parse([]byte(doc))
	if len(fs) > 0 {
		t.Fatal(fs)
	}
	js, _ := d.JSON()
	testkit.Write(t, st, func(c *store.TenantTx) error {
		return c.InsertAgentScope(&store.AgentScope{Key: d.Key, Status: status, Name: d.Name, Doc: js, DocSHA256: "x", Version: 1,
			CreatedAt: testkit.Now, UpdatedAt: testkit.Now})
	})
}

func profile(t *testing.T, st *testkit.DB, id int64, source, ext string) {
	t.Helper()
	testkit.Write(t, st, func(c *store.TenantTx) error {
		return c.UpsertAgentProfile(&store.AgentProfile{Source: source, ExternalID: ext, IdentityID: id, Kind: "agent"}, testkit.Now)
	})
}

// scopePolicies is what the API evaluates: the base policies and the tenant's scopes.
func scopePolicies(t *testing.T, st *testkit.DB) []*policy.Policy {
	t.Helper()
	return testkit.Get(t, st, func(c *store.TenantTx) ([]*policy.Policy, error) {
		return policy.WithAgentScopes(c, testkit.Policies(t))
	})
}

func TestAgentScopeViolations(t *testing.T) {
	tests := []struct {
		name     string
		scope    string
		status   string
		outScope bool // helper-bot is out of scope
		exceeds  bool // helper-bot holds what Alice does not
		contains string
	}{
		{"read on the system it uses is inside", scopeDoc("hb", "entra", "hb", []string{"read"}, []string{"snowflake"}, ""),
			"active", false, true, "does not"},
		{"the owner ceiling can be turned off", scopeDoc("hb", "entra", "hb", []string{"read"}, []string{"snowflake"}, "owner_ceiling: false\n"),
			"active", false, false, ""},
		{"write only: a read is outside", scopeDoc("hb", "entra", "hb", []string{"write"}, []string{"snowflake"}, "owner_ceiling: false\n"),
			"active", true, false, "outside its scope hb"},
		{"another system: outside", scopeDoc("hb", "entra", "hb", []string{"read", "write"}, []string{"aws"}, "owner_ceiling: false\n"),
			"active", true, false, "snowflake:SELECT on"},
		{"admin and delegate are not read", scopeDoc("hb", "entra", "hb", []string{"admin", "delegate"}, []string{"snowflake"}, "owner_ceiling: false\n"),
			"active", true, false, ""},
		{"a retired scope does not apply", scopeDoc("hb", "entra", "hb", []string{"write"}, []string{"snowflake"}, ""),
			"retired", false, false, ""},
		{"a scope for another agent does not apply", scopeDoc("other", "entra", "someone-else", []string{"write"}, []string{"aws"}, ""),
			"active", false, false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st, ids := testkit.Tiny(t)
			profile(t, st, ids["helper-bot"], "entra", "hb")
			putScope(t, st, tc.scope, tc.status)
			pols := scopePolicies(t, st)
			out, exc := violations(t, st, policy.PolicyAgentOutOfScope, pols), violations(t, st, policy.PolicyAgentExceedsOwner, pols)
			if got := len(out) == 1; got != tc.outScope || len(out) > 1 {
				t.Errorf("out-of-scope findings = %+v; want present: %v", out, tc.outScope)
			}
			if got := len(exc) == 1; got != tc.exceeds || len(exc) > 1 {
				t.Errorf("exceeds-owner findings = %+v; want present: %v", exc, tc.exceeds)
			}
			for _, v := range append(out, exc...) {
				if *v.IdentityID != ids["helper-bot"] {
					t.Errorf("a finding about someone else: %+v", v)
				}
				if v.Severity != "high" || len(v.Evidence) == 0 || len(v.Edges) == 0 {
					t.Errorf("finding lacks severity, evidence or edges: %+v", v)
				}
			}
			if tc.contains != "" {
				all := append(out, exc...)
				if len(all) == 0 || !strings.Contains(all[0].Message+strings.Join(all[0].Evidence, "|"), tc.contains) {
					t.Errorf("findings %+v lack %q", all, tc.contains)
				}
			}
		})
	}
}

func TestAgentScopeKeysAndSeverity(t *testing.T) {
	st, ids := testkit.Tiny(t)
	profile(t, st, ids["helper-bot"], "entra", "hb")
	putScope(t, st, scopeDoc("hb", "entra", "hb", []string{"write"}, []string{"snowflake"}, "severity: critical\n"), "active")
	pols := scopePolicies(t, st)
	out := violations(t, st, policy.PolicyAgentOutOfScope, pols)
	exc := violations(t, st, policy.PolicyAgentExceedsOwner, pols)
	if len(out) != 1 || out[0].Key != "hb:"+itoa(ids["helper-bot"]) || out[0].Severity != "critical" {
		t.Errorf("out-of-scope = %+v", out)
	}
	if len(exc) != 1 || exc[0].Key != "hb:"+itoa(ids["helper-bot"])+":owner" || !strings.Contains(exc[0].Message, "Alice") && !strings.Contains(strings.ToLower(exc[0].Message), "alice") {
		t.Errorf("exceeds-owner = %+v", exc)
	}
}

// An agent that holds only what its owner holds, inside its scope, has no finding; default deny applies the moment
// it holds something the scope does not list.
func TestAgentScopeInsideScopeAndOwner(t *testing.T) {
	st, ids := testkit.Tiny(t)
	profile(t, st, ids["svc-etl"], "test", "etl")
	putScope(t, st, scopeDoc("etl", "test", "etl", []string{"read"}, []string{"aws"}, ""), "active")
	pols := scopePolicies(t, st)
	if vs := violations(t, st, policy.PolicyAgentOutOfScope, pols); len(vs) != 0 {
		t.Errorf("out of scope: %+v", vs)
	}
	// its owner Dave is terminated, so there is no ceiling to stay under: fail closed, never skipped
	if vs := violations(t, st, policy.PolicyAgentExceedsOwner, pols); len(vs) != 1 || !strings.Contains(vs[0].Message, "terminated") {
		t.Errorf("exceeds-owner with a terminated owner = %+v", vs)
	}
	// narrowing the scope to a tag svc-etl's resource lacks makes the same permission a finding
	testkit.Write(t, st, func(c *store.TenantTx) error {
		s, err := c.AgentScopeByKey("etl")
		if err != nil {
			return err
		}
		d, _ := agentscope.Parse([]byte(scopeDoc("etl", "test", "etl", []string{"read"}, []string{"aws"}, "      tags_any: [payments]\n")))
		s.Doc, _ = d.JSON()
		s.Version++
		return c.SaveAgentScope(s, s.Version-1)
	})
	if vs := violations(t, st, policy.PolicyAgentOutOfScope, scopePolicies(t, st)); len(vs) != 1 {
		t.Errorf("a permission outside the narrowed scope: %+v", vs)
	}
}

// A blueprint scope applies to every agent linked to the blueprint, and the scopes of an agent are a union.
func TestAgentScopeBlueprintAndUnion(t *testing.T) {
	st, ids := testkit.Tiny(t)
	profile(t, st, ids["helper-bot"], "entra", "hb")
	testkit.Write(t, st, func(c *store.TenantTx) error {
		return c.UpsertAgentLink(&store.AgentLink{Source: "entra", ExternalID: "hb", BlueprintAppID: "bp-1"})
	})
	bp := "schema: tessera.agentscope/v1\nkey: bp\nname: bp\nagent:\n  blueprint: bp-1\nallow:\n  actions: [write]\n  resources:\n    - systems: [snowflake]\nowner_ceiling: false\n"
	putScope(t, st, bp, "active")
	pols := scopePolicies(t, st)
	out := violations(t, st, policy.PolicyAgentOutOfScope, pols)
	if len(out) != 1 || !strings.HasPrefix(out[0].Key, "bp:") {
		t.Fatalf("the blueprint scope did not apply: %+v", out)
	}
	// the agent's own scope allows the read, and one scope allowing a permission is enough
	putScope(t, st, scopeDoc("hb", "entra", "hb", []string{"read"}, []string{"snowflake"}, "owner_ceiling: false\n"), "active")
	if out := violations(t, st, policy.PolicyAgentOutOfScope, scopePolicies(t, st)); len(out) != 0 {
		t.Errorf("a permission one scope allows was reported: %+v", out)
	}
}

// An owner that is itself a scoped agent lends its scope as the ceiling: what its scope does not allow, its agent
// may not hold either.
func TestAgentScopeOwnerScopeIsTheCeiling(t *testing.T) {
	st, ids := testkit.Tiny(t)
	// svc-etl's owner Dave holds what svc-etl holds; scope Dave as an agent that may not read aws
	profile(t, st, ids["svc-etl"], "test", "etl")
	profile(t, st, ids["dave"], "test", "dave")
	putScope(t, st, scopeDoc("etl", "test", "etl", []string{"read"}, []string{"aws"}, ""), "active")
	putScope(t, st, scopeDoc("dave", "test", "dave", []string{"write"}, []string{"aws"}, "owner_ceiling: false\n"), "active")
	exc := violations(t, st, policy.PolicyAgentExceedsOwner, scopePolicies(t, st))
	if len(exc) != 1 || *exc[0].IdentityID != ids["svc-etl"] {
		t.Errorf("exceeds-owner = %+v; want svc-etl, whose owner's scope allows writes only", exc)
	}
}

func TestWithAgentScopesOnlyWhenTheTenantHasOne(t *testing.T) {
	st, ids := testkit.Tiny(t)
	base := testkit.Policies(t)
	if got := scopePolicies(t, st); len(got) != len(base) {
		t.Fatalf("a tenant with no scope got %d policies; want %d", len(got), len(base))
	}
	profile(t, st, ids["helper-bot"], "entra", "hb")
	putScope(t, st, scopeDoc("hb", "entra", "hb", []string{"read"}, []string{"snowflake"}, ""), "retired")
	if got := scopePolicies(t, st); len(got) != len(base) {
		t.Fatalf("a tenant with only a retired scope got %d policies", len(got))
	}
	putScope(t, st, scopeDoc("hb2", "entra", "hb", []string{"read"}, []string{"snowflake"}, ""), "active")
	got := scopePolicies(t, st)
	if len(got) != len(base)+2 || got[len(got)-2].ID != policy.PolicyAgentOutOfScope || got[len(got)-1].ID != policy.PolicyAgentExceedsOwner {
		t.Fatalf("policies = %d, want base + the two invariants", len(got))
	}
	for _, p := range got[len(got)-2:] {
		if _, ok := policy.Evaluators[p.Type]; !ok || !p.Enabled {
			t.Errorf("%s has no evaluator or is off", p.ID)
		}
	}
	// a stored document that no longer reads is an error, not a scope dropped
	testkit.Write(t, st, func(c *store.TenantTx) error {
		s, _ := c.AgentScopeByKey("hb2")
		s.Doc, s.Version = `{"key":"hb2","bogus":true}`, 2
		return c.SaveAgentScope(s, 1)
	})
	err := testkit.Get(t, st, func(c *store.TenantTx) (error, error) {
		_, err := policy.WithAgentScopes(c, base)
		return err, nil
	})
	if err == nil {
		t.Error("an unreadable stored scope was skipped")
	}
}

// Without a database the selectors cannot be resolved: nothing is reported rather than everything.
func TestAgentScopeNeedsTheDatabase(t *testing.T) {
	g := graph.New()
	p := &policy.Policy{ID: policy.PolicyAgentOutOfScope, Type: policy.TypeAgentOutOfScope, Enabled: true}
	vs, err := policy.Evaluate([]*policy.Policy{p}, policy.NewContext(g, nil, testkit.Now))
	if err != nil || len(vs) != 0 {
		t.Errorf("Evaluate = %v, %v", vs, err)
	}
}

// An agent's own scope is its ceiling: a broader blueprint scope does not widen it.
func TestAgentScopeOwnScopeBeatsBlueprint(t *testing.T) {
	st, ids := testkit.Tiny(t)
	profile(t, st, ids["helper-bot"], "entra", "hb")
	testkit.Write(t, st, func(c *store.TenantTx) error {
		return c.UpsertAgentLink(&store.AgentLink{Source: "entra", ExternalID: "hb", BlueprintAppID: "bp-1"})
	})
	putScope(t, st, "schema: tessera.agentscope/v1\nkey: bp\nname: bp\nagent:\n  blueprint: bp-1\nallow:\n  actions: [read]\n  resources:\n    - systems: [snowflake]\nowner_ceiling: false\n", "active")
	if out := violations(t, st, policy.PolicyAgentOutOfScope, scopePolicies(t, st)); len(out) != 0 {
		t.Fatalf("the blueprint scope allows the read: %+v", out)
	}
	putScope(t, st, scopeDoc("hb", "entra", "hb", []string{"read"}, []string{"aws"}, "owner_ceiling: false\n"), "active")
	out := violations(t, st, policy.PolicyAgentOutOfScope, scopePolicies(t, st))
	if len(out) != 1 || !strings.HasPrefix(out[0].Key, "hb:") {
		t.Errorf("the agent's narrower scope did not apply: %+v", out)
	}
}

// The owner ceiling fails closed: no owner, an owner chain that is a cycle, or one that ends at an agent reports
// every permission the agent holds.
func TestAgentScopeOwnerChainFailsClosed(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, st *testkit.DB, ids map[string]int64)
		want  string
	}{
		{"no owner", func(t *testing.T, st *testkit.DB, ids map[string]int64) {
			testkit.Write(t, st, func(c *store.TenantTx) error { return c.SetIdentityOwner(ids["helper-bot"], nil) })
		}, "no owner"},
		{"a cycle through an agent owner", func(t *testing.T, st *testkit.DB, ids map[string]int64) {
			profile(t, st, ids["alice"], "entra", "alice")
			hb := ids["helper-bot"]
			testkit.Write(t, st, func(c *store.TenantTx) error { return c.SetIdentityOwner(ids["alice"], &hb) })
		}, "cycle"},
		{"a chain that ends at an agent", func(t *testing.T, st *testkit.DB, ids map[string]int64) {
			profile(t, st, ids["alice"], "entra", "alice")
			testkit.Write(t, st, func(c *store.TenantTx) error { return c.SetIdentityOwner(ids["alice"], nil) })
		}, "ends at an agent"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st, ids := testkit.Tiny(t)
			profile(t, st, ids["helper-bot"], "entra", "hb")
			putScope(t, st, scopeDoc("hb", "entra", "hb", []string{"read"}, []string{"snowflake"}, ""), "active")
			tc.setup(t, st, ids)
			exc := violations(t, st, policy.PolicyAgentExceedsOwner, scopePolicies(t, st))
			if len(exc) != 1 || *exc[0].IdentityID != ids["helper-bot"] || !strings.Contains(exc[0].Message, tc.want) {
				t.Errorf("exceeds-owner = %+v; want one for helper-bot naming %q", exc, tc.want)
			}
		})
	}
}
