package policy_test

import (
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

func TestMain(m *testing.M) { testkit.Main(m) }

func violations(t *testing.T, st *testkit.DB, policyID string, pols []*policy.Policy) []policy.Violation {
	t.Helper()
	vs := testkit.Get(t, st, func(c *store.TenantTx) ([]policy.Violation, error) {
		g, err := graph.Build(c, testkit.Now)
		if err != nil {
			return nil, err
		}
		return policy.Evaluate(pols, policy.NewContext(g, c, testkit.Now))
	})
	var out []policy.Violation
	for _, v := range vs {
		if policyID == "" || v.PolicyID == policyID {
			out = append(out, v)
		}
	}
	return out
}

func identityIDs(vs []policy.Violation) []int64 {
	out := []int64{}
	for _, v := range vs {
		out = append(out, *v.IdentityID)
	}
	return out
}

func TestAllRepoPoliciesLoadAndHaveKnownTypes(t *testing.T) {
	pols := testkit.Policies(t)
	ids := map[string]bool{}
	for _, p := range pols {
		ids[p.ID] = true
		if _, ok := policy.Evaluators[p.Type]; !ok {
			t.Errorf("policy %s has unknown type %s", p.ID, p.Type)
		}
	}
	for _, want := range []string{"sod-payments", "no-standing-prod-admin", "ai-agents-no-pii"} {
		if !ids[want] {
			t.Errorf("missing policy %s", want)
		}
	}
}

func TestTinyWorldPolicyFindings(t *testing.T) {
	st, ids := testkit.Tiny(t)
	pols := testkit.Policies(t)
	tests := []struct {
		policy   string
		want     []string // identity external ids
		contains []string // substrings of message or first evidence line
	}{
		{"sod-payments", []string{"bob"}, []string{"payments:create", "payments:approve"}},
		{"no-standing-prod-admin", []string{"carol"}, []string{"okta:platform"}},
		{"ai-agents-no-pii", []string{"helper-bot"}, []string{"PII_READER"}},
		{"nhi-ownership", []string{"svc-etl"}, []string{"Dave, who is terminated"}}, // owner left
		{"stale-secrets", []string{"svc-etl"}, []string{"400 days old"}},
		{"terminated-access", []string{"dave"}, []string{"aws:dave"}},
	}
	for _, tc := range tests {
		t.Run(tc.policy, func(t *testing.T) {
			vs := violations(t, st, tc.policy, pols)
			want := []int64{}
			for _, x := range tc.want {
				want = append(want, ids[x])
			}
			if got := identityIDs(vs); !slices.Equal(got, want) {
				t.Fatalf("identities = %v, want %v", got, want)
			}
			text := vs[0].Message + "\n" + strings.Join(vs[0].Evidence, "\n")
			for _, s := range tc.contains {
				if !strings.Contains(text, s) {
					t.Errorf("%q not in %q", s, text)
				}
			}
		})
	}
}

func TestJITOnlyAdminIsNotAViolation(t *testing.T) {
	st, ids := testkit.Tiny(t)
	testkit.Write(t, st, func(c *store.TenantTx) error {
		exp := testkit.Now.Add(2 * time.Hour)
		_, err := c.InsertEdge(&store.GrantEdge{Src: graph.Key("account", ids["acct:okta:alice"]),
			Dst: graph.Key("group", ids["group:aws:ProdAdmin"]), Relation: "member_of", Source: "jit", ExpiresAt: &exp,
			CreatedAt: testkit.Now})
		return err
	})
	got := identityIDs(violations(t, st, "no-standing-prod-admin", testkit.Policies(t)))
	if !slices.Equal(got, []int64{ids["carol"]}) {
		t.Errorf("got %v, want only carol", got)
	}
}

func TestInlinePolicyParsing(t *testing.T) {
	st, ids := testkit.Tiny(t)
	p, err := policy.Parse(map[string]any{"id": "x", "type": "forbidden_access", "severity": "low",
		"subjects":  map[string]any{"identity_types": []any{"human"}},
		"resources": map[string]any{"tags_any": []any{"payments"}}}, "")
	if err != nil {
		t.Fatal(err)
	}
	vs := violations(t, st, "", []*policy.Policy{p})
	for _, v := range vs {
		if *v.IdentityID != ids["bob"] {
			t.Errorf("unexpected violation for %s", v.IdentityName)
		}
	}
	if len(vs) != 2 { // payments:create and payments:approve
		t.Errorf("violations = %d, want 2", len(vs))
	}
}

func TestParseValidation(t *testing.T) {
	tests := []struct {
		name    string
		doc     map[string]any
		wantErr bool
		check   func(*policy.Policy) bool
	}{
		{"needs id", map[string]any{"type": "nhi_ownership"}, true, nil},
		{"needs type", map[string]any{"id": "x"}, true, nil},
		{"defaults", map[string]any{"id": "x", "type": "nhi_ownership"}, false,
			func(p *policy.Policy) bool { return p.Name == "x" && p.Severity == "medium" && p.Enabled }},
		{"disabled", map[string]any{"id": "x", "type": "nhi_ownership", "enabled": false}, false,
			func(p *policy.Policy) bool { return !p.Enabled }},
		{"spec keeps extra keys", map[string]any{"id": "x", "type": "secret_max_age", "max_age_days": 30}, false,
			func(p *policy.Policy) bool { return p.Spec["max_age_days"] == 30 && p.Spec["id"] == nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := policy.Parse(tc.doc, "")
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v", err)
			}
			if tc.check != nil && !tc.check(p) {
				t.Errorf("unexpected policy %+v", p)
			}
		})
	}
}

func TestDisabledAndUnknownPolicies(t *testing.T) {
	st, _ := testkit.Tiny(t)
	ctx := testkit.Get(t, st, func(c *store.TenantTx) (*policy.Context, error) {
		g, err := graph.Build(c, testkit.Now)
		return policy.NewContext(g, nil, testkit.Now), err
	})
	off := &policy.Policy{ID: "off", Type: "nope", Enabled: false}
	if vs, err := policy.Evaluate([]*policy.Policy{off}, ctx); err != nil || len(vs) != 0 {
		t.Errorf("disabled policy: %v %v", vs, err)
	}
	bad := &policy.Policy{ID: "bad", Type: "nope", Enabled: true}
	if _, err := policy.Evaluate([]*policy.Policy{bad}, ctx); err == nil {
		t.Error("unknown policy type should fail")
	}
}

func TestSecretMaxAgeThreshold(t *testing.T) {
	st, _ := testkit.Tiny(t)
	tests := []struct {
		maxAge any
		want   int
	}{{90, 1}, {399, 1}, {400, 0}, {1000, 0}}
	for _, tc := range tests {
		p := &policy.Policy{ID: "age", Name: "age", Type: "secret_max_age", Severity: "low", Enabled: true,
			Spec: map[string]any{"max_age_days": tc.maxAge}}
		if got := len(violations(t, st, "", []*policy.Policy{p})); got != tc.want {
			t.Errorf("max_age_days=%v: %d violations, want %d", tc.maxAge, got, tc.want)
		}
	}
}

func TestEvaluateSortsBySeverityPolicyAndName(t *testing.T) {
	st, _ := testkit.Tiny(t)
	vs := violations(t, st, "", testkit.Policies(t))
	for i := 1; i < len(vs); i++ {
		a, b := vs[i-1], vs[i]
		ra, rb := policy.SeverityRank[a.Severity], policy.SeverityRank[b.Severity]
		if ra < rb || (ra == rb && a.PolicyID > b.PolicyID) ||
			(ra == rb && a.PolicyID == b.PolicyID && a.IdentityName > b.IdentityName) {
			t.Errorf("out of order at %d: %s/%s/%s before %s/%s/%s", i, a.Severity, a.PolicyID, a.IdentityName,
				b.Severity, b.PolicyID, b.IdentityName)
		}
	}
}

func TestDiffViolationsByKey(t *testing.T) {
	v := func(k string) policy.Violation { return policy.Violation{Key: k} }
	d := policy.DiffViolations([]policy.Violation{v("c"), v("a"), v("b")}, []policy.Violation{v("b"), v("d"), v("e")})
	keys := func(vs []policy.Violation) []string {
		out := []string{}
		for _, x := range vs {
			out = append(out, x.Key)
		}
		return out
	}
	if got := keys(d.Resolved); !slices.Equal(got, []string{"a", "c"}) {
		t.Errorf("resolved = %v", got)
	}
	if got := keys(d.Introduced); !slices.Equal(got, []string{"d", "e"}) {
		t.Errorf("introduced = %v", got)
	}
}

func TestLoaderReadsMultiDocumentListsAndReloads(t *testing.T) {
	fsys := fstest.MapFS{
		"a.yaml": {Data: []byte("- id: one\n  type: nhi_ownership\n- id: two\n  type: nhi_ownership\n")},
		"b.yml":  {Data: []byte("id: three\ntype: nhi_ownership\n")},
		"c.txt":  {Data: []byte("ignored")},
	}
	l := policy.NewLoader(fsys)
	pols, err := l.Load()
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, p := range pols {
		ids = append(ids, p.ID)
	}
	if !slices.Equal(ids, []string{"one", "two", "three"}) {
		t.Fatalf("ids = %v", ids)
	}
	fsys["b.yml"] = &fstest.MapFile{Data: []byte("id: four\ntype: nhi_ownership\nseverity: high\n")}
	pols, err = l.Load()
	if err != nil {
		t.Fatal(err)
	}
	if pols[2].ID != "four" {
		t.Errorf("changed file not reloaded: %s", pols[2].ID)
	}
	fsys["bad.yaml"] = &fstest.MapFile{Data: []byte("- just a string\n")}
	if _, err := l.Load(); err == nil {
		t.Error("non-mapping document should fail to load")
	}
}

func TestDemoPoliciesProduceExpectedFindings(t *testing.T) {
	st := testkit.Demo(t)
	by := map[string][]string{}
	for _, v := range violations(t, st, "", testkit.Policies(t)) {
		by[v.PolicyID] = append(by[v.PolicyID], v.IdentityName)
	}
	if !slices.Equal(by["sod-payments"], []string{"Priya Ramaswamy"}) {
		t.Errorf("sod = %v", by["sod-payments"])
	}
	for _, n := range []string{"Support Copilot", "Data Analyst Agent"} {
		if !slices.Contains(by["ai-agents-no-pii"], n) {
			t.Errorf("ai-agents-no-pii missing %s: %v", n, by["ai-agents-no-pii"])
		}
	}
	leavers := slices.Clone(by["terminated-access"])
	slices.Sort(leavers)
	if want := []string{"Dmitri Ostrowski", "Hollis Brightwater", "Oren Whitlock"}; !slices.Equal(leavers, want) {
		t.Errorf("terminated-access = %v, want %v", leavers, want)
	}
}
