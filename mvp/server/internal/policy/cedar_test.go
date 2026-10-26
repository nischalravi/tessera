package policy_test

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata/cedar")

// extraYAML are policies beyond the shipped ones, to cover every field of the
// seven types the engine reads: statuses, systems, actions, environments
// (including none), privileged, tags, secret age and MFA strength.
const extraYAML = `
- {id: x-forbid-wide, name: wide, type: forbidden_access, severity: high,
   subjects: {identity_types: [human, service], statuses: [active, terminated]},
   resources: {systems: [aws, snowflake], actions: [s3:GetObject, snowflake:SELECT, iam:*], environment: prod}}
- {id: x-forbid-noenv, name: noenv, type: forbidden_access, severity: low,
   resources: {environment: null, tags_any: [pii, secret]}}
- {id: x-forbid-priv, name: priv, type: forbidden_access, severity: critical,
   subjects: {identity_types: [ai_agent, service]}, resources: {privileged: true}}
- {id: x-forbid-all, name: all, type: forbidden_access, subjects: {}, resources: {}}
- {id: x-forbid-never, name: never, type: forbidden_access, subjects: {statuses: []}, resources: {actions: []}}
- {id: x-nostanding-priv, name: ns, type: no_standing_access, severity: high, match: {privileged: true}}
- {id: x-nostanding-tags, name: ns2, type: no_standing_access, severity: medium,
   subjects: {statuses: [active, terminated]}, match: {tags_any: [payments, pii], environment: prod}}
- {id: x-nostanding-any, name: ns3, type: no_standing_access, match: {}}
- {id: x-term, name: term, type: terminated_with_access, severity: critical}
- {id: x-secret30, name: s30, type: secret_max_age, severity: medium, max_age_days: 30}
- {id: x-secret-frac, name: sfrac, type: secret_max_age, max_age_days: 45.5}
- {id: x-secret-zero, name: s0, type: secret_max_age, max_age_days: 0}
- {id: x-nhi, name: nhi, type: nhi_ownership, severity: high}
- {id: x-mfa, name: mfa, type: mfa_required, severity: high}
- {id: x-mfa-push, name: mfapush, type: mfa_required, require: push,
   subjects: {identity_types: [human], statuses: [active, terminated]}}
- {id: x-mfa-otp, name: mfaotp, type: mfa_required, require: otp, subjects: {identity_types: [human, service]}}
- {id: x-disabled, name: off, type: forbidden_access, enabled: false, resources: {tags_any: [pii]}}
`

// portable is the policies the differential runs over: the shipped files, the
// extra ones, each with the Cedar of its port.
type portedPolicy struct {
	yaml  *policy.Policy
	cedar *policy.Policy
	text  string
}

func portable(t *testing.T) []portedPolicy {
	t.Helper()
	pols := testkit.Policies(t)
	extra, err := policy.NewLoader(fstest.MapFS{"extra.yaml": {Data: []byte(extraYAML)}}).Load()
	if err != nil {
		t.Fatal(err)
	}
	var out []portedPolicy
	for _, p := range append(pols, extra...) {
		text, err := policy.ToCedar(p)
		if errors.Is(err, policy.ErrNotPortable) {
			if p.Type != "separation_of_duties" {
				t.Errorf("%s (%s) is not portable: %v", p.ID, p.Type, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ToCedar(%s): %v", p.ID, err)
		}
		cs, err := policy.ParseInvariants(p.ID, []byte(text))
		if err != nil || len(cs) != 1 {
			t.Fatalf("the port of %s does not load: %v\n%s", p.ID, err, text)
		}
		out = append(out, portedPolicy{p, cs[0], text})
	}
	return out
}

// canon is a violation list in a comparable form: LowFidelity is the Cedar
// engine's addition and is compared apart; the order is by policy and key.
func canon(t *testing.T, vs []policy.Violation) []string {
	t.Helper()
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		v.LowFidelity = false
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, string(b))
	}
	sort.Strings(out)
	return out
}

func equalViolations(t *testing.T, label string, want, got []policy.Violation) {
	t.Helper()
	w, g := canon(t, want), canon(t, got)
	if len(w) != len(g) {
		t.Errorf("%s: YAML found %d violations, Cedar %d", label, len(w), len(g))
	}
	for i := 0; i < len(w) && i < len(g); i++ {
		if w[i] != g[i] {
			t.Errorf("%s: violation %d differs\n yaml:  %s\n cedar: %s", label, i, w[i], g[i])
			return
		}
	}
	// the evaluator's own order (severity, policy, name) must agree where it is decided
	for i := range want {
		if i < len(got) && (want[i].PolicyID != got[i].PolicyID || want[i].IdentityName != got[i].IdentityName) {
			t.Errorf("%s: order differs at %d: yaml %s/%s, cedar %s/%s", label, i, want[i].PolicyID, want[i].IdentityName,
				got[i].PolicyID, got[i].IdentityName)
			return
		}
	}
}

// compare evaluates every ported policy both ways over the graph and database of c.
func compare(t *testing.T, label string, c *store.TenantTx, g *graph.Snapshot, ps []portedPolicy) (total int) {
	t.Helper()
	for _, p := range ps {
		ctx := policy.NewContext(g, c, testkit.Now)
		want, err := policy.Evaluate([]*policy.Policy{p.yaml}, ctx)
		if err != nil {
			t.Fatalf("%s %s: yaml: %v", label, p.yaml.ID, err)
		}
		got, err := policy.Evaluate([]*policy.Policy{p.cedar}, policy.NewContext(g, c, testkit.Now))
		if err != nil {
			t.Fatalf("%s %s: cedar: %v", label, p.yaml.ID, err)
		}
		equalViolations(t, label+" "+p.yaml.ID, want, got)
		total += len(want)
	}
	return total
}

// TestCedarPortMatchesYAML is the differential of access-as-code AC-3: every
// YAML policy and its Cedar port give the same violations, field for field, on
// the tiny world, the seeded demo company and generated worlds, and on what-if
// graphs with time-boxed (JIT) grants.
func TestCedarPortMatchesYAML(t *testing.T) {
	ps := portable(t)
	seen := map[string]bool{}
	for _, p := range ps {
		seen[p.yaml.Type] = true
	}
	for _, typ := range []string{"forbidden_access", "no_standing_access", "terminated_with_access", "secret_max_age", "nhi_ownership", "mfa_required"} {
		if !seen[typ] {
			t.Errorf("no policy of type %s is compared", typ)
		}
	}
	withViolations := map[string]int{}
	run := func(label string, db *testkit.DB, whatIf bool) {
		testkit.Read(t, db, func(c *store.TenantTx) error {
			g, err := graph.Build(c, testkit.Now)
			if err != nil {
				return err
			}
			graphs := map[string]*graph.Snapshot{"": g}
			if whatIf {
				graphs["jit"] = jitVariant(g, int64(len(label)))
			}
			for name, gr := range graphs {
				for _, p := range ps {
					n := compare(t, label+"/"+name, c, gr, []portedPolicy{p})
					withViolations[p.yaml.Type] += n
				}
			}
			return nil
		})
	}
	tiny, _ := testkit.Tiny(t)
	run("tiny", tiny, true)
	run("demo", testkit.Demo(t), true)
	for seed := int64(1); seed <= 12; seed++ {
		run(fmt.Sprintf("gen%d", seed), genWorld(t, seed), true)
	}
	// the worlds exercise every type: each finds something, so equality is not vacuous
	for _, typ := range []string{"forbidden_access", "no_standing_access", "terminated_with_access", "secret_max_age", "nhi_ownership", "mfa_required"} {
		if withViolations[typ] == 0 {
			t.Errorf("no world gave a %s violation; the differential proves nothing for it", typ)
		}
	}
}

// jitVariant adds time-boxed grants to random accounts, as a what-if does: a
// path through one is not standing.
func jitVariant(g *graph.Snapshot, salt int64) *graph.Snapshot {
	r := rand.New(rand.NewSource(salt))
	after := g.Copy()
	var accts, targets []string
	for _, n := range after.Nodes() {
		switch n.Kind {
		case "account":
			accts = append(accts, n.Key)
		case "group", "perm":
			targets = append(targets, n.Key)
		}
	}
	sort.Strings(accts)
	sort.Strings(targets)
	if len(accts) == 0 || len(targets) == 0 {
		return after
	}
	exp := testkit.Now.Add(4 * time.Hour)
	for i := 0; i < 12; i++ {
		_ = after.AddEdge(accts[r.Intn(len(accts))], targets[r.Intn(len(targets))], "member_of", "jit", &exp)
	}
	return after
}

// TestCedarPortGolden pins the Cedar of every shipped policy that ports.
func TestCedarPortGolden(t *testing.T) {
	shipped := map[string]bool{}
	for _, p := range testkit.Policies(t) {
		shipped[p.ID] = true
	}
	for _, p := range portable(t) {
		if !shipped[p.yaml.ID] {
			continue
		}
		path := filepath.Join("testdata", "cedar", p.yaml.ID+".cedar")
		if *updateGolden {
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(p.text), 0o600); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path) // #nosec G304 -- fixed testdata path
		if err != nil {
			t.Fatalf("%v (run go test ./internal/policy -run Golden -update)", err)
		}
		if string(want) != p.text {
			t.Errorf("the Cedar of %s changed:\n%s\nwant:\n%s", p.yaml.ID, p.text, want)
		}
	}
}

func TestToCedarNotPortable(t *testing.T) {
	load := func(doc string) *policy.Policy {
		ps, err := policy.NewLoader(fstest.MapFS{"p.yaml": {Data: []byte(doc)}}).Load()
		if err != nil || len(ps) != 1 {
			t.Fatalf("%v %v", ps, err)
		}
		return ps[0]
	}
	for name, doc := range map[string]string{
		"sod":            "{id: s, type: separation_of_duties, conflict: {a: [x], b: [y]}}",
		"condition":      "{id: c, type: forbidden_access, subjects: {identity_types: [human], condition: {attr: identity.department, op: eq, value: Finance}}}",
		"scalar actions": "{id: a, type: forbidden_access, resources: {actions: s3}}",
		"scalar tags":    "{id: t, type: forbidden_access, resources: {tags_any: pii}}",
		"bad age":        "{id: b, type: secret_max_age, max_age_days: ninety}",
		"bad mfa":        "{id: m, type: mfa_required, require: strong}",
		"long text":      "{id: l, type: terminated_with_access, description: '" + strings.Repeat("x", 2000) + "'}",
	} {
		if _, err := policy.ToCedar(load(doc)); !errors.Is(err, policy.ErrNotPortable) {
			t.Errorf("%s: ToCedar = %v, want ErrNotPortable", name, err)
		}
	}
	// a description with quotes, newlines and non-ASCII survives the round trip
	p := load("{id: q, type: terminated_with_access, name: \"Naïve \\\"q\\\"\", description: \"line 1\\nline \\\\ 2\\ttab\"}")
	text, err := policy.ToCedar(p)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := policy.ParseInvariants("q", []byte(text))
	if err != nil || cs[0].Name != p.Name || cs[0].Description != p.Description {
		t.Errorf("round trip: %v %q %q", err, cs[0].Name, cs[0].Description)
	}
}

func TestParseInvariantsRefuses(t *testing.T) {
	const head = `@id("i") @severity("high") `
	for name, src := range map[string]string{
		"empty":        ``,
		"permit":       head + `permit (principal, action == Tessera::Action::"reach", resource);`,
		"no id":        `forbid (principal, action == Tessera::Action::"reach", resource);`,
		"bad id":       `@id("a b") forbid (principal, action == Tessera::Action::"reach", resource);`,
		"bad severity": `@id("i") @severity("urgent") forbid (principal, action == Tessera::Action::"reach", resource);`,
		"any action":   head + `forbid (principal, action, resource);`,
		"two actions":  head + `forbid (principal, action in [Tessera::Action::"reach", Tessera::Action::"exist"], resource);`,
		"type vs fact": head + `@type("secret_max_age") forbid (principal, action == Tessera::Action::"reach", resource);`,
		"unknown attr": head + `forbid (principal, action == Tessera::Action::"reach", resource) when { principal.nope == "x" };`,
		"unguarded":    head + `forbid (principal, action == Tessera::Action::"reach", resource) when { principal.department == "x" };`,
		"duplicate":    head + `forbid (principal, action == Tessera::Action::"reach", resource); ` + head + `forbid (principal, action == Tessera::Action::"exist", resource);`,
		"syntax":       head + `forbid (principal, action == Tessera::Action::"reach", resource) when {`,
		"too deep":     head + `forbid (principal, action == Tessera::Action::"reach", resource) when { ` + strings.Repeat("(", 40) + "true" + strings.Repeat(")", 40) + ` };`,
		"bad require":  head + `@type("mfa_required") @require("strong") forbid (principal, action == Tessera::Action::"exist", resource);`,
	} {
		if _, err := policy.ParseInvariants("f", []byte(src)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	ps, err := policy.ParseInvariants("f", []byte(head+`forbid (principal, action == Tessera::Action::"hold_credential", resource) when { resource.age_days > 30 };`))
	if err != nil || len(ps) != 1 || ps[0].Type != policy.TypeInvariant || ps[0].Severity != "high" || ps[0].Cedar.Fact != policy.FactHoldCredential {
		t.Errorf("a valid invariant: %v %+v", err, ps)
	}
}

func FuzzParseInvariants(f *testing.F) {
	f.Add([]byte(`@id("i") forbid (principal, action == Tessera::Action::"reach", resource) when { context.standing };`))
	f.Add([]byte(`@id("i") @type("mfa_required") forbid (principal, action == Tessera::Action::"exist", resource);`))
	f.Add([]byte(`permit (principal, action, resource);`))
	f.Add([]byte(`@id("`))
	f.Fuzz(func(t *testing.T, src []byte) {
		ps, err := policy.ParseInvariants("fuzz", src)
		if err != nil {
			return
		}
		for _, p := range ps {
			if p.Cedar == nil || p.ID == "" || policy.SeverityRank[p.Severity] == 0 {
				t.Fatalf("a loaded invariant is incomplete: %+v", p)
			}
		}
	})
}
