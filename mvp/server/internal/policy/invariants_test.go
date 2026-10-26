package policy_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

const piiInvariant = `@id("ai-agents-no-pii") @name("AI agents may not access PII") @severity("critical") @type("forbidden_access")
forbid (principal, action == Tessera::Action::"reach", resource)
when { principal.type == "ai_agent" && principal.status == "active" && resource.tags.contains("pii") };
`

func evalOn(t *testing.T, db *testkit.DB, pols []*policy.Policy) []policy.Violation {
	t.Helper()
	return testkit.Get(t, db, func(c *store.TenantTx) ([]policy.Violation, error) {
		g, err := graph.Build(c, testkit.Now)
		if err != nil {
			return nil, err
		}
		return policy.Evaluate(pols, policy.NewContext(g, c, testkit.Now))
	})
}

// A fact reached only through an approximate permission is reported, flagged
// LowFidelity, and never blocks (design decision 6); an exact fact of the same
// policy blocks. The YAML engine finds the same set and flags nothing.
func TestCedarLowFidelityNeverBlocks(t *testing.T) {
	db, ids := testkit.Tiny(t)
	testkit.Write(t, db, func(c *store.TenantTx) error {
		perms, err := c.Permissions()
		if err != nil {
			return err
		}
		for _, p := range perms {
			if p.System == "aws" && p.ExternalID == "get-pii" {
				_, err = c.UpsertEvaluatorEdge(graph.Key("account", ids["acct:snowflake:HELPER_BOT"]), graph.Key("perm", p.ID),
					"direct_grant", testkit.Now, store.EdgeEvaluation{ExplanationID: "ex-1", Outcome: graph.OutcomeAllow, Fidelity: graph.FidelityApprox})
				return err
			}
		}
		t.Fatal("no aws get-pii permission")
		return nil
	})
	var yamlPol *policy.Policy
	for _, p := range testkit.Policies(t) {
		if p.ID == "ai-agents-no-pii" {
			yamlPol = p
		}
	}
	text, err := policy.ToCedar(yamlPol)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := policy.ParseInvariants("ai-agents-no-pii", []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	want, got := evalOn(t, db, []*policy.Policy{yamlPol}), evalOn(t, db, cs)
	equalViolations(t, "approximate", want, got)
	if len(got) != 2 {
		t.Fatalf("violations = %d, want the exact select-customers and the approximate get-pii: %+v", len(got), got)
	}
	low := 0
	for _, v := range got {
		if v.LowFidelity {
			low++
			if !strings.Contains(v.Message, "s3:GetObject") {
				t.Errorf("the low-fidelity finding is %q", v.Message)
			}
		}
	}
	for _, v := range want {
		if v.LowFidelity {
			t.Error("the YAML engine flagged a finding")
		}
	}
	if low != 1 {
		t.Errorf("%d low-fidelity findings, want 1", low)
	}
	if b := policy.Blocking(got); len(b) != 1 || b[0].LowFidelity {
		t.Errorf("Blocking = %+v, want only the exact finding", b)
	}
	// the JSON of a YAML finding has no low_fidelity key (the /api/violations fixtures do not change)
	if strings.Contains(string(mustJSON(t, want)), "low_fidelity") {
		t.Error("a YAML violation serializes low_fidelity")
	}
}

func TestOverlayInvariants(t *testing.T) {
	db, _ := testkit.Tiny(t)
	base := testkit.Policies(t)
	yamlOnly := evalOn(t, db, base)

	// no source: the YAML policies, unchanged
	testkit.Read(t, db, func(c *store.TenantTx) error {
		pols, unreadable, err := policy.TenantPolicies(c, base)
		if err != nil || unreadable != nil || len(pols) != len(base) || pols[0] != base[0] {
			t.Errorf("no sources: %d policies, unreadable %v, err %v", len(pols), unreadable, err)
		}
		return nil
	})

	// a source replaces the YAML policy of its id in place and adds new ids
	testkit.Write(t, db, func(c *store.TenantTx) error {
		if ch, err := policy.ImportInvariant(c, "ai-agents-no-pii", []byte(piiInvariant), "", "tester", testkit.Now); err != nil || !ch {
			t.Fatalf("import = %v %v", ch, err)
		}
		if ch, err := policy.ImportInvariant(c, "ai-agents-no-pii", []byte(piiInvariant), "", "tester", testkit.Now); err != nil || ch {
			t.Errorf("a second import changed the source: %v %v", ch, err)
		}
		_, err := policy.ImportInvariant(c, "leavers", []byte(`@id("leavers-own") @severity("low") forbid (principal, action == Tessera::Action::"reach", resource) when { principal.status == "terminated" };`),
			`{"commit":"abc"}`, "tester", testkit.Now)
		return err
	})
	var overlaid []*policy.Policy
	testkit.Read(t, db, func(c *store.TenantTx) error {
		var unreadable error
		var err error
		if overlaid, unreadable, err = policy.TenantPolicies(c, base); err != nil || unreadable != nil {
			t.Fatalf("overlay: %v %v", unreadable, err)
		}
		return nil
	})
	if len(overlaid) != len(base)+1 {
		t.Fatalf("overlay has %d policies, want %d", len(overlaid), len(base)+1)
	}
	for i, p := range base {
		o := overlaid[i]
		if (p.ID == "ai-agents-no-pii") != (o.Cedar != nil) || o.ID != p.ID {
			t.Errorf("policy %d is %s (cedar %v), base %s", i, o.ID, o.Cedar != nil, p.ID)
		}
	}
	if last := overlaid[len(overlaid)-1]; last.ID != "leavers-own" || last.Cedar == nil || last.Severity != "low" {
		t.Errorf("the added policy is %+v", last)
	}
	got := evalOn(t, db, overlaid)
	n := 0
	for _, v := range got {
		if v.PolicyID == "leavers-own" {
			n++
		}
	}
	if n == 0 {
		t.Error("the added invariant found nothing")
	}
	// the replaced invariant finds what the YAML found; the added one is extra
	var without []policy.Violation
	for _, v := range got {
		if v.PolicyID != "leavers-own" {
			without = append(without, v)
		}
	}
	equalViolations(t, "overlay", yamlOnly, without)

	// disabled: the policy is switched off, the YAML of its id is not used
	testkit.Write(t, db, func(c *store.TenantTx) error {
		_, err := policy.SetInvariantStatus(c, "ai-agents-no-pii", store.PolicyDisabled, "tester", testkit.Now)
		return err
	})
	testkit.Read(t, db, func(c *store.TenantTx) error {
		pols, unreadable, err := policy.TenantPolicies(c, base)
		if err != nil || unreadable != nil {
			t.Fatal(unreadable, err)
		}
		for _, v := range func() []policy.Violation {
			g, _ := graph.Build(c, testkit.Now)
			vs, _ := policy.Evaluate(pols, policy.NewContext(g, c, testkit.Now))
			return vs
		}() {
			if v.PolicyID == "ai-agents-no-pii" {
				t.Error("a disabled invariant found a violation")
			}
		}
		return nil
	})
	vs, err := versions(t, db)
	if err != nil || len(vs) != 2 || vs[1].Status != store.PolicyDisabled {
		t.Errorf("history = %+v %v", vs, err)
	}
}

func versions(t *testing.T, db *testkit.DB) ([]*store.PolicyVersion, error) {
	t.Helper()
	var vs []*store.PolicyVersion
	var err error
	testkit.Read(t, db, func(c *store.TenantTx) error {
		vs, err = c.PolicyVersions(store.PolicyKindInvariant, "ai-agents-no-pii")
		return nil
	})
	return vs, err
}

// A bundle that does not load never half-applies: the overlay fails whole and
// the caller keeps the embedded YAML.
func TestOverlayInvariantsFailsClosed(t *testing.T) {
	db, _ := testkit.Tiny(t)
	base := testkit.Policies(t)
	put := func(key, cedar string) {
		testkit.Write(t, db, func(c *store.TenantTx) error {
			_, err := c.PutPolicySource(&store.PolicySource{Kind: store.PolicyKindInvariant, Key: key, Cedar: cedar,
				Status: store.PolicyActive, UpdatedBy: "t"}, testkit.Now)
			return err
		})
	}
	put("good", piiInvariant)
	for name, cedar := range map[string]string{
		"syntax":   `@id("x") forbid (principal, action == Tessera::Action::"reach", resource) when {`,
		"unknown":  `@id("x") forbid (principal, action == Tessera::Action::"reach", resource) when { principal.nope };`,
		"two ids":  piiInvariant, // @id also in "good"
		"a permit": `@id("x") permit (principal, action == Tessera::Action::"reach", resource);`,
	} {
		put("bad", cedar)
		testkit.Read(t, db, func(c *store.TenantTx) error {
			pols, unreadable, err := policy.TenantPolicies(c, base)
			if err != nil || unreadable == nil || len(pols) != len(base) {
				t.Errorf("%s: unreadable %v, err %v, %d policies", name, unreadable, err, len(pols))
			}
			for _, p := range pols {
				if p.Cedar != nil {
					t.Errorf("%s: a Cedar invariant is evaluated from a bundle that does not load", name)
				}
			}
			return nil
		})
	}
	// a source whose Cedar no longer matches its digest is not trusted either
	if _, err := policy.OverlayInvariants(base, []*store.PolicySource{{Kind: store.PolicyKindInvariant, Key: "k", Cedar: piiInvariant,
		SHA256: strings.Repeat("0", 64), Status: store.PolicyActive}}); err == nil {
		t.Error("a source with a wrong digest was loaded")
	}
	// ImportInvariant refuses what would not load, and stores nothing
	testkit.Write(t, db, func(c *store.TenantTx) error {
		if _, err := policy.ImportInvariant(c, "nope", []byte(`permit (principal, action, resource);`), "", "t", testkit.Now); err == nil {
			t.Error("imported a permit")
		}
		if _, err := c.PolicySource(store.PolicyKindInvariant, "nope"); err == nil {
			t.Error("a refused import left a source")
		}
		return nil
	})
}

// Without a database the exist and credential facts do not exist: those
// invariants find nothing (as the YAML evaluators do), and reach facts still work.
func TestCedarWithoutDatabase(t *testing.T) {
	db, _ := testkit.Tiny(t)
	ps := portable(t)
	testkit.Read(t, db, func(c *store.TenantTx) error {
		g, err := graph.Build(c, testkit.Now)
		if err != nil {
			return err
		}
		for _, p := range ps {
			want, err := policy.Evaluate([]*policy.Policy{p.yaml}, policy.NewContext(g, nil, testkit.Now))
			if err != nil {
				t.Fatal(err)
			}
			got, err := policy.Evaluate([]*policy.Policy{p.cedar}, policy.NewContext(g, nil, testkit.Now))
			if err != nil {
				t.Fatal(err)
			}
			equalViolations(t, "no db "+p.yaml.ID, want, got)
		}
		return nil
	})
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
