package policy_test

import (
	"reflect"
	"slices"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/sod"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

func sodPol(fns ...[]sod.Selector) *sod.Bundle {
	b := &sod.Bundle{Ruleset: sod.RulesetDoc{Key: "t", Name: "T", Enabled: true}}
	var keys []string
	for i, s := range fns {
		k := string(rune('a' + i))
		keys = append(keys, k)
		b.Functions = append(b.Functions, sod.FunctionDoc{Key: k, Name: "fn " + k, Selectors: s})
	}
	b.Risks = []sod.RiskDoc{{Key: "r", Name: "R", Priority: "high", Functions: keys}}
	return b
}

func detect(t *testing.T, st *testkit.DB, risks []*sod.Risk) []sod.Violation {
	t.Helper()
	return testkit.Get(t, st, func(c *store.TenantTx) ([]sod.Violation, error) {
		g, err := graph.Build(c, testkit.Now)
		if err != nil {
			return nil, err
		}
		return policy.NewContext(g, c, testkit.Now).SoD(risks), nil
	})
}

func who(vs []sod.Violation, ids map[string]int64) []int64 {
	out := []int64{}
	for _, v := range vs {
		out = append(out, v.IdentityID)
	}
	slices.Sort(out)
	return out
}

// The legacy YAML SoD policy and the risk imported from it give identical
// findings, down to key, message, evidence and edges.
func TestLegacyBundleMatchesYAMLEvaluator(t *testing.T) {
	st, _ := testkit.Tiny(t)
	pols := testkit.Policies(t)
	legacy := violations(t, st, "sod-payments", pols)
	if len(legacy) == 0 {
		t.Fatal("the tiny world has no SoD finding to compare")
	}
	b, err := policy.LegacyBundle(pols, true)
	if err != nil || b == nil {
		t.Fatal(b, err)
	}
	got := testkit.Get(t, st, func(c *store.TenantTx) ([]policy.Violation, error) {
		g, err := graph.Build(c, testkit.Now)
		if err != nil {
			return nil, err
		}
		eff := policy.Effective(pols, sod.CompileBundle(b))
		vs, err := policy.Evaluate(eff, policy.NewContext(g, c, testkit.Now))
		var out []policy.Violation
		for _, v := range vs {
			if v.PolicyID == "sod-payments" {
				out = append(out, v)
			}
		}
		return out, err
	})
	if !reflect.DeepEqual(legacy, got) {
		t.Errorf("legacy %+v\nrisk   %+v", legacy, got)
	}
}

// The seeded larkspur tenant holds the imported ruleset; its violations are
// exactly those the YAML policies report.
func TestSeededLarkspurViolationsUnchanged(t *testing.T) {
	st := testkit.Demo(t)
	pols := testkit.Policies(t)
	var legacy, fromDB []policy.Violation
	testkit.Read(t, st, func(c *store.TenantTx) error {
		if n, _ := c.CountSodRulesets(); n != 1 {
			t.Fatalf("seeded rulesets = %d, want the imported one", n)
		}
		g, err := graph.Build(c, testkit.Now)
		if err != nil {
			return err
		}
		ctx := policy.NewContext(g, c, testkit.Now)
		all, err := policy.Evaluate(pols, ctx)
		if err != nil {
			return err
		}
		for _, v := range all {
			if v.PolicyID == "sod-payments" {
				legacy = append(legacy, v)
			}
		}
		risks, err := sod.Compile(c)
		if err != nil {
			return err
		}
		for _, v := range ctx.SoD(risks) {
			fromDB = append(fromDB, policy.ToViolation(v))
		}
		return nil
	})
	if len(legacy) == 0 {
		t.Fatal("larkspur has no SoD violations; the comparison would prove nothing")
	}
	if !reflect.DeepEqual(legacy, fromDB) {
		t.Errorf("the seeded ruleset changed the findings:\nyaml %d, db %d", len(legacy), len(fromDB))
	}
}

func TestDetectionRules(t *testing.T) {
	st, ids := testkit.Tiny(t)
	create, approve := pat("payments:create"), pat("payments:approve")
	t.Run("through groups to both halves", func(t *testing.T) {
		vs := detect(t, st, sod.CompileBundle(sodPol(create, approve)))
		if !slices.Equal(who(vs, ids), []int64{ids["bob"]}) {
			t.Fatalf("who = %v", vs)
		}
		v := vs[0]
		if v.Function1.Key != "a" || v.Function2.Key != "b" || v.Key != "r:"+itoa(ids["bob"]) || v.Status != "open" {
			t.Errorf("violation = %+v", v)
		}
		if len(v.Sides[0].Grants) != 1 || len(v.Sides[0].Grants[0].Paths) == 0 || len(v.Sides[1].Grants[0].Paths) == 0 {
			t.Errorf("paths missing: %+v", v.Sides)
		}
	})
	t.Run("a function overlapping the other does not conflict through one entitlement", func(t *testing.T) {
		if vs := detect(t, st, sod.CompileBundle(sodPol(pat("payments:*"), create))); len(vs) != 1 {
			// bob holds approve (only in a) and create (in both): a=approve, b=create is distinct
			t.Errorf("overlap with a distinct pair: %d", len(vs))
		}
		if vs := detect(t, st, sod.CompileBundle(sodPol(create, create))); len(vs) != 0 {
			t.Errorf("one entitlement against itself: %d", len(vs))
		}
	})
	t.Run("system and attribute narrow a function", func(t *testing.T) {
		for name, sels := range map[string][]sod.Selector{
			"wrong system":        {{System: "aws", NamePattern: "payments:create"}},
			"wrong environment":   {{NamePattern: "payments:create", Attribute: "environment", Value: "dev"}},
			"wrong tag":           {{NamePattern: "payments:create", Attribute: "tag", Value: "pii"}},
			"wrong resource":      {{NamePattern: "payments:create", Attribute: "resource", Value: "Other*"}},
			"wrong privileged":    {{NamePattern: "payments:create", Attribute: "privileged", Value: "true"}},
			"no such entitlement": {{NamePattern: "payments:refund"}},
		} {
			if vs := detect(t, st, sod.CompileBundle(sodPol(sels, approve))); len(vs) != 0 {
				t.Errorf("%s still conflicts", name)
			}
		}
		right := []sod.Selector{{System: "workday", NamePattern: "payments:create", Attribute: "environment", Value: "prod"},
			{NamePattern: "x", Attribute: "tag", Value: "payments"}}
		if vs := detect(t, st, sod.CompileBundle(sodPol(right, approve))); len(vs) != 1 {
			t.Errorf("the right system and attribute: %d", len(vs))
		}
	})
	t.Run("an entitlement id selector", func(t *testing.T) {
		var pid int64
		testkit.Read(t, st, func(c *store.TenantTx) error {
			ps, _ := c.Permissions()
			for _, p := range ps {
				if p.Action == "payments:create" {
					pid = p.ID
				}
			}
			return nil
		})
		sel := []sod.Selector{{System: "workday", EntitlementID: &pid}}
		if vs := detect(t, st, sod.CompileBundle(sodPol(sel, approve))); len(vs) != 1 {
			t.Errorf("by id: %d", len(vs))
		}
	})
	t.Run("three functions give one violation per conflicting pair", func(t *testing.T) {
		vs := detect(t, st, sod.CompileBundle(sodPol(create, approve, pat("s3:GetObject"))))
		if len(vs) != 1 || vs[0].Key != "r:"+itoa(ids["bob"])+":a+b" {
			t.Errorf("pairs: %+v", vs)
		}
		vs = detect(t, st, sod.CompileBundle(sodPol(create, approve, pat("iam:*"))))
		if len(vs) != 1 {
			t.Errorf("a third function nobody-with-both holds adds nothing: %d", len(vs))
		}
	})
	t.Run("subjects limit who is checked", func(t *testing.T) {
		b := sodPol(create, approve)
		b.Risks[0].Subjects = &sod.Subjects{IdentityTypes: []string{"service"}}
		if vs := detect(t, st, sod.CompileBundle(b)); len(vs) != 0 {
			t.Errorf("humans checked by a service-only risk: %d", len(vs))
		}
		b.Risks[0].Subjects = &sod.Subjects{IdentityTypes: []string{"human"}, Condition: map[string]any{"attr": "identity.department", "op": "eq", "value": "Nowhere"}}
		if vs := detect(t, st, sod.CompileBundle(b)); len(vs) != 0 {
			t.Errorf("a false condition still checks: %d", len(vs))
		}
	})
	t.Run("a disabled ruleset checks nothing", func(t *testing.T) {
		b := sodPol(create, approve)
		b.Ruleset.Enabled = false
		if risks := sod.CompileBundle(b); len(risks) != 0 {
			t.Errorf("compiled %d", len(risks))
		}
	})
}

// Simulate: granting a group that completes the second half is introduced.
func TestSimulateIntroducesRisk(t *testing.T) {
	st, ids := testkit.Tiny(t)
	risks := sod.CompileBundle(sodPol(pat("payments:create"), pat("payments:approve")))
	testkit.Read(t, st, func(c *store.TenantTx) error {
		g, err := graph.Build(c, testkit.Now)
		if err != nil {
			return err
		}
		run := func(gr *graph.Snapshot) []sod.Violation { return policy.NewContext(gr, c, testkit.Now).SoD(risks) }
		after := g.Copy()
		acct, clerks, approvers := graph.Key("account", ids["acct:okta:alice"]), graph.Key("group", ids["group:okta:payments-clerks"]),
			graph.Key("group", ids["group:okta:payments-approvers"])
		if err := after.AddEdge(acct, clerks, "member_of", "simulated", nil); err != nil {
			return err
		}
		if in := sod.Introduced(run(g), run(after)); len(in) != 0 {
			t.Errorf("one half introduced %d", len(in))
		}
		if err := after.AddEdge(acct, approvers, "member_of", "simulated", nil); err != nil {
			return err
		}
		in := sod.Introduced(run(g), run(after))
		if len(in) != 1 || in[0].IdentityID != ids["alice"] {
			t.Errorf("both halves introduced %+v", in)
		}
		return nil
	})
}

func itoa(n int64) string {
	b := []byte{}
	if n == 0 {
		return "0"
	}
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

func pat(p string) []sod.Selector { return []sod.Selector{{NamePattern: p}} }
