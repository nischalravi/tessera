package policybundle

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/cedarx"
)

// TestFile is tests/<name>.yaml (tessera.test/v1): entities in Cedar's entity
// JSON format, cases that give a request and the expected decision, and an
// optional snapshot of facts with the invariant violations and low-fidelity
// findings expected from it.
type TestFile struct {
	Path     string    `yaml:"-"`
	Schema   string    `yaml:"schema"`
	Name     string    `yaml:"name"`
	Entities []any     `yaml:"entities"`
	Cases    []Case    `yaml:"cases"`
	Snapshot *Snapshot `yaml:"snapshot"`
	set      *cedarx.Entities
}

// Case is one expected decision. Against is birthright, agents or invariants;
// when empty it is birthright for a birthright request and invariants for a fact.
// Expect is allow or deny; for invariants a deny is a violation. By, when given,
// is the exact set of @id annotations of the policies that decided.
type Case struct {
	Name      string         `yaml:"name"`
	Against   string         `yaml:"against"`
	Principal string         `yaml:"principal"`
	Action    string         `yaml:"action"`
	Resource  string         `yaml:"resource"`
	Context   map[string]any `yaml:"context"`
	Expect    string         `yaml:"expect"`
	By        []string       `yaml:"by"`
}

// Snapshot is a fixture of facts evaluated against every invariant.
type Snapshot struct {
	Facts      []Fact     `yaml:"facts"`
	Violations []Expected `yaml:"violations"`
	Findings   []Expected `yaml:"findings"`
}

// Fact is one fact of a snapshot; Action is reach, exist or hold_credential.
type Fact struct {
	Principal string         `yaml:"principal"`
	Action    string         `yaml:"action"`
	Resource  string         `yaml:"resource"`
	Context   map[string]any `yaml:"context"`
}

// Expected names a fact an invariant fires on.
type Expected struct {
	Invariant string `yaml:"invariant"`
	Principal string `yaml:"principal"`
	Action    string `yaml:"action"`
	Resource  string `yaml:"resource"`
}

const (
	maxCases = 1000
	maxFacts = 5000
	actionNS = "Tessera::Action::"
)

var testActions = []string{"birthright", "reach", "exist", "hold_credential"}

func (l *loader) loadTests() {
	for _, p := range l.yamlFiles(DirTests) {
		var t TestFile
		if err := decode(l.files[p], &t); err != nil {
			l.addErr(p, err)
			continue
		}
		t.Path = p
		before := len(l.diags)
		l.checkTest(&t)
		if len(l.diags) == before {
			l.b.Tests = append(l.b.Tests, t)
		}
	}
}

// reqKey normalizes the principal, action and resource of a request, or says why not.
func reqKey(principal, action, resource string) (cedarx.Request, error) {
	var r cedarx.Request
	var err error
	if r.Principal, err = cedarx.ParseUID(principal); err != nil {
		return r, fmt.Errorf("principal: %v", err)
	}
	if r.Resource, err = cedarx.ParseUID(resource); err != nil {
		return r, fmt.Errorf("resource: %v", err)
	}
	a := strings.TrimPrefix(action, actionNS)
	a = strings.Trim(a, `"`)
	if !contains(testActions, a) {
		return r, fmt.Errorf("action %q is one of %s", action, strings.Join(testActions, ", "))
	}
	r.Action = cedarx.UID{Type: "Tessera::Action", ID: a}
	return r, nil
}

func (l *loader) checkTest(t *TestFile) {
	p := t.Path
	if t.Schema != TagTest {
		l.add(p, 0, "invalid_schema", "schema is %q; expected %q", t.Schema, TagTest)
	}
	if len(t.Cases) > maxCases || (t.Snapshot != nil && len(t.Snapshot.Facts) > maxFacts) {
		l.add(p, 0, "too_many", "at most %d cases and %d facts per test file", maxCases, maxFacts)
		return
	}
	if len(t.Cases) == 0 && t.Snapshot == nil {
		l.add(p, 0, "empty_test", "a test file needs cases or a snapshot")
	}
	set := &cedarx.Entities{}
	if len(t.Entities) > 0 {
		raw, err := json.Marshal(t.Entities)
		if err == nil {
			var own *cedarx.Entities
			own, err = cedarx.ParseEntities(raw)
			if err == nil {
				err = set.Merge(own)
			}
		}
		if err != nil {
			l.addErr(p, err)
			return
		}
	}
	if l.b.entities != nil {
		// the bundle's own objects are in scope; the test's entities win on the same uid
		merged := &cedarx.Entities{}
		_ = merged.Merge(l.b.entities)
		if err := merged.Merge(set); err != nil {
			l.addErr(p, err)
			return
		}
		set = merged
	}
	if err := l.b.Schema.ValidateSet(set); err != nil {
		l.addErr(p, err)
		return
	}
	t.set = set
	names := map[string]bool{}
	for i, c := range t.Cases {
		where := fmt.Sprintf("case %d (%s)", i+1, c.Name)
		if c.Name == "" || names[c.Name] {
			l.add(p, 0, "invalid_case", "case %d needs a name, unique in the file", i+1)
		}
		names[c.Name] = true
		if _, err := reqKey(c.Principal, c.Action, c.Resource); err != nil {
			l.add(p, 0, "invalid_case", "%s: %v", where, err)
		}
		if c.Expect != "allow" && c.Expect != "deny" {
			l.add(p, 0, "invalid_case", "%s: expect is allow or deny", where)
		}
		if c.Against != "" && !contains([]string{"birthright", "agents", "invariants"}, c.Against) {
			l.add(p, 0, "invalid_case", "%s: against is birthright, agents or invariants", where)
		}
		if _, err := json.Marshal(c.Context); err != nil {
			l.add(p, 0, "invalid_case", "%s: context: %v", where, err)
		}
	}
	if s := t.Snapshot; s != nil {
		for i, f := range s.Facts {
			r, err := reqKey(f.Principal, f.Action, f.Resource)
			switch {
			case err != nil:
				l.add(p, 0, "invalid_fact", "fact %d: %v", i+1, err)
			case r.Action.ID == "birthright":
				l.add(p, 0, "invalid_fact", "fact %d: a fact is reach, exist or hold_credential", i+1)
			}
			if _, err := json.Marshal(f.Context); err != nil {
				l.add(p, 0, "invalid_fact", "fact %d: context: %v", i+1, err)
			}
		}
		for _, group := range [][]Expected{s.Violations, s.Findings} {
			for i, e := range group {
				if _, err := expectedKey(e); err != nil {
					l.add(p, 0, "invalid_expectation", "expectation %d: %v", i+1, err)
				}
			}
		}
	}
}

func expectedKey(e Expected) (string, error) {
	r, err := reqKey(e.Principal, e.Action, e.Resource)
	if err != nil {
		return "", err
	}
	if e.Invariant == "" {
		return "", fmt.Errorf("invariant (an @id) is required")
	}
	return e.Invariant + " | " + r.Principal.String() + " | " + r.Action.ID + " | " + r.Resource.String(), nil
}

// Result is the outcome of one test case or snapshot of a test file. Err is empty on a pass.
type Result struct {
	Path string
	Name string
	Err  string
}

// OK reports whether the result passed.
func (r Result) OK() bool { return r.Err == "" }

func (r Result) String() string {
	if r.OK() {
		return fmt.Sprintf("PASS %s: %s", r.Path, r.Name)
	}
	return fmt.Sprintf("FAIL %s: %s: %s", r.Path, r.Name, r.Err)
}

func (b *Bundle) setsFor(against string) ([]*cedarx.Policies, error) {
	var files []PolicyFile
	switch against {
	case "birthright":
		files = b.Birthright
	case "agents":
		files = b.Agents
	default:
		files = b.Invariants
	}
	var out []*cedarx.Policies
	for _, f := range files {
		out = append(out, f.Policies)
	}
	if against == "invariants" || against == "" {
		// invariants are forbids over an implicit permit of everything
		implicit, err := cedarx.ParsePolicies("implicit", []byte(`permit (principal, action, resource);`))
		if err != nil {
			return nil, err
		}
		out = append(out, implicit)
	}
	return out, nil
}

func ctxJSON(m map[string]any) []byte {
	if len(m) == 0 {
		return nil
	}
	raw, _ := json.Marshal(m) // checked at load
	return raw
}

func ids(d cedarx.Decision) []string {
	var out []string
	for _, r := range d.Reasons {
		if r.ID != "" {
			out = append(out, r.ID)
		}
	}
	sort.Strings(out)
	return out
}

// RunTests runs every test file of a bundle that loaded without findings, in
// path order: each case, then each snapshot. It never touches the network or a
// database; the answer depends only on the bytes of the repository.
func (b *Bundle) RunTests() []Result {
	var out []Result
	for _, t := range b.Tests {
		for _, c := range t.Cases {
			out = append(out, Result{Path: t.Path, Name: c.Name, Err: b.runCase(&t, c)})
		}
		if t.Snapshot != nil {
			out = append(out, Result{Path: t.Path, Name: "snapshot", Err: b.runSnapshot(&t)})
		}
	}
	return out
}

func (b *Bundle) runCase(t *TestFile, c Case) string {
	req, _ := reqKey(c.Principal, c.Action, c.Resource)
	req.Context = ctxJSON(c.Context)
	against := c.Against
	if against == "" {
		against = "invariants"
		if req.Action.ID == "birthright" {
			against = "birthright"
		}
	}
	sets, err := b.setsFor(against)
	if err != nil {
		return err.Error()
	}
	d, err := cedarx.Decide(t.set, req, sets...)
	if err != nil {
		return err.Error()
	}
	if len(d.Errors) > 0 {
		return "a policy failed to evaluate: " + strings.Join(d.Errors, "; ")
	}
	got := "deny"
	if d.Allow {
		got = "allow"
	}
	if got != c.Expect {
		return fmt.Sprintf("expected %s, got %s (decided by %s)", c.Expect, got, list(ids(d)))
	}
	if c.By != nil {
		want := append([]string(nil), c.By...)
		sort.Strings(want)
		if g := ids(d); strings.Join(g, ",") != strings.Join(want, ",") {
			return fmt.Sprintf("expected %s, decided by %s; wanted %s", c.Expect, list(g), list(want))
		}
	}
	return ""
}

func list(s []string) string {
	if len(s) == 0 {
		return "no policy"
	}
	return strings.Join(s, ", ")
}

// runSnapshot evaluates every fact against every invariant. A fired forbid is a
// violation; but a reach fact whose fidelity is not EXACT never blocks (design
// §10, decision 6): it is a finding. The sets must equal the expected ones.
func (b *Bundle) runSnapshot(t *TestFile) string {
	sets, err := b.setsFor("invariants")
	if err != nil {
		return err.Error()
	}
	violations, findings := map[string]bool{}, map[string]bool{}
	for i, f := range t.Snapshot.Facts {
		req, _ := reqKey(f.Principal, f.Action, f.Resource)
		req.Context = ctxJSON(f.Context)
		d, err := cedarx.Decide(t.set, req, sets...)
		if err != nil {
			return fmt.Sprintf("fact %d: %v", i+1, err)
		}
		if len(d.Errors) > 0 {
			return fmt.Sprintf("fact %d: a policy failed to evaluate: %s", i+1, strings.Join(d.Errors, "; "))
		}
		if d.Allow {
			continue
		}
		low := req.Action.ID == "reach" && f.Context["fidelity"] != "EXACT"
		for _, r := range d.Reasons {
			if r.ID == "" {
				continue
			}
			key, _ := expectedKey(Expected{Invariant: r.ID, Principal: f.Principal, Action: f.Action, Resource: f.Resource})
			if low {
				findings[key] = true
			} else {
				violations[key] = true
			}
		}
	}
	wantV, wantF := keys(t.Snapshot.Violations), keys(t.Snapshot.Findings)
	var problems []string
	problems = append(problems, diff("violation", violations, wantV)...)
	problems = append(problems, diff("low-fidelity finding", findings, wantF)...)
	return strings.Join(problems, "; ")
}

func keys(es []Expected) map[string]bool {
	m := map[string]bool{}
	for _, e := range es {
		k, _ := expectedKey(e)
		m[k] = true
	}
	return m
}

func diff(what string, got, want map[string]bool) []string {
	var out []string
	for _, k := range sortedKeys(want) {
		if !got[k] {
			out = append(out, fmt.Sprintf("expected %s [%s] did not occur", what, k))
		}
	}
	for _, k := range sortedKeys(got) {
		if !want[k] {
			out = append(out, fmt.Sprintf("unexpected %s [%s]", what, k))
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
