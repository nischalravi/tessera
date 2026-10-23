package perms

import (
	"slices"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The heuristics table (design §10.10, GR-19). Cases follow the documented
// order of Grouper's permission heuristics: a more specific resource beats a
// less specific one, then a more specific action, then how directly the
// assignment reaches the subject, and among equals a disallow beats an allow.
// The set is built in memory (no database): the closures are given directly.
//
// Resources: ledger implies entry, entry implies line. Actions: admin implies
// write, write implies read.

const def = "def1"

func testSet(as ...*Assignment) *Set {
	s := newSet(nil)
	s.byDef[def] = &closures{
		names: map[string]map[string]bool{
			"ledger": {"entry": true, "line": true},
			"entry":  {"line": true},
		},
		actions: map[string]map[string]bool{
			"admin": {"write": true, "read": true},
			"write": {"read": true},
		},
	}
	s.Assignments = as
	return s
}

func asg(id, res, act string, mods ...func(*Assignment)) *Assignment {
	a := &Assignment{ID: id, DefID: def, NameID: res, ActionID: act, Resource: res, Action: act, Role: "role-a", RoleName: "app:a"}
	for _, m := range mods {
		m(a)
	}
	return a
}

func deny(a *Assignment)                     { a.Disallowed = true }
func role(g store.GroupID) func(*Assignment) { return func(a *Assignment) { a.Role = g } }
func subject(id int64) func(*Assignment) {
	return func(a *Assignment) { a.Subject = &id }
}
func limit(name string, vs ...string) func(*Assignment) {
	return func(a *Assignment) { a.Limits = append(a.Limits, Limit{Name: name, Values: vs}) }
}
func window(from, to time.Time) func(*Assignment) {
	return func(a *Assignment) { a.EnabledFrom, a.DisabledAt = &from, &to }
}

var t0 = time.Date(2026, 3, 2, 10, 0, 0, 0, time.UTC)

func TestHeuristics_Table(t *testing.T) {
	sub := Subject{Identity: 7, Roles: map[store.GroupID]bool{"role-a": true, "role-b": true}, Direct: map[store.GroupID]bool{"role-a": true}}
	for _, tc := range []struct {
		name         string
		as           []*Assignment
		res, act     string
		ctx          Context
		want         string
		via          []string
		conditional  bool
		limitsFailed []string
	}{
		{name: "nothing assigned", res: "entry", act: "read", want: "no_permission"},
		{name: "exact allow", as: []*Assignment{asg("a1", "entry", "read")}, res: "entry", act: "read", want: "allowed", via: []string{"a1"}},
		{name: "resource inheritance", as: []*Assignment{asg("a1", "ledger", "read")}, res: "line", act: "read", want: "allowed", via: []string{"a1"}},
		{name: "inheritance does not run upward", as: []*Assignment{asg("a1", "line", "read")}, res: "ledger", act: "read", want: "no_permission"},
		{name: "action inheritance", as: []*Assignment{asg("a1", "entry", "admin")}, res: "entry", act: "read", want: "allowed", via: []string{"a1"}},
		{name: "action inheritance does not run upward", as: []*Assignment{asg("a1", "entry", "read")}, res: "entry", act: "write", want: "no_permission"},
		{name: "resource and action inheritance together", as: []*Assignment{asg("a1", "ledger", "admin")}, res: "line", act: "read", want: "allowed", via: []string{"a1"}},
		{name: "another role's assignment does not reach the subject", as: []*Assignment{asg("a1", "entry", "read", role("role-z"))}, res: "entry", act: "read", want: "no_permission"},
		{name: "disallow alone", as: []*Assignment{asg("a1", "entry", "read", deny)}, res: "entry", act: "read", want: "disallowed", via: []string{"a1"}},
		{name: "disallow beats allow at the same rank", as: []*Assignment{asg("a1", "entry", "read"), asg("a2", "entry", "read", deny)},
			res: "entry", act: "read", want: "disallowed", via: []string{"a1", "a2"}},
		{name: "more specific resource: allow beats an inherited disallow", as: []*Assignment{asg("a1", "ledger", "read", deny), asg("a2", "entry", "read")},
			res: "entry", act: "read", want: "allowed", via: []string{"a2"}},
		{name: "more specific resource: disallow beats an inherited allow", as: []*Assignment{asg("a1", "ledger", "read"), asg("a2", "entry", "read", deny)},
			res: "entry", act: "read", want: "disallowed", via: []string{"a2"}},
		{name: "more specific action: allow beats an inherited disallow", as: []*Assignment{asg("a1", "entry", "admin", deny), asg("a2", "entry", "read")},
			res: "entry", act: "read", want: "allowed", via: []string{"a2"}},
		{name: "resource outranks action", as: []*Assignment{asg("a1", "entry", "admin"), asg("a2", "ledger", "read", deny)},
			res: "entry", act: "read", want: "allowed", via: []string{"a1"}},
		{name: "resource outranks action, the other way", as: []*Assignment{asg("a1", "entry", "admin", deny), asg("a2", "ledger", "read")},
			res: "entry", act: "read", want: "disallowed", via: []string{"a1"}},
		{name: "subject assignment beats a role's disallow", as: []*Assignment{asg("a1", "entry", "read", deny), asg("a2", "entry", "read", subject(7))},
			res: "entry", act: "read", want: "allowed", via: []string{"a2"}},
		{name: "subject disallow beats a role's allow", as: []*Assignment{asg("a1", "entry", "read"), asg("a2", "entry", "read", subject(7), deny)},
			res: "entry", act: "read", want: "disallowed", via: []string{"a2"}},
		{name: "another identity's pair is ignored", as: []*Assignment{asg("a1", "entry", "read", subject(8))}, res: "entry", act: "read", want: "no_permission"},
		{name: "a pair needs the role", as: []*Assignment{asg("a1", "entry", "read", subject(7), role("role-z"))}, res: "entry", act: "read", want: "no_permission"},
		{name: "direct role beats a nested role", as: []*Assignment{asg("a1", "entry", "read", role("role-b"), deny), asg("a2", "entry", "read")},
			res: "entry", act: "read", want: "allowed", via: []string{"a2"}},
		{name: "nested role's allow loses to a direct role's disallow", as: []*Assignment{asg("a1", "entry", "read", role("role-b")), asg("a2", "entry", "read", deny)},
			res: "entry", act: "read", want: "disallowed", via: []string{"a2"}},
		{name: "not yet enabled", as: []*Assignment{asg("a1", "entry", "read", window(t0.Add(time.Hour), t0.Add(2*time.Hour)))}, res: "entry", act: "read", want: "no_permission"},
		{name: "expired", as: []*Assignment{asg("a1", "entry", "read", window(t0.Add(-2*time.Hour), t0))}, res: "entry", act: "read", want: "no_permission"},
		{name: "inside its dates", as: []*Assignment{asg("a1", "entry", "read", window(t0.Add(-time.Hour), t0.Add(time.Hour)))}, res: "entry", act: "read", want: "allowed", via: []string{"a1"}},
		{name: "an expired disallow lets the allow through", as: []*Assignment{asg("a1", "entry", "read"), asg("a2", "entry", "read", deny, window(t0.Add(-2*time.Hour), t0))},
			res: "entry", act: "read", want: "allowed", via: []string{"a1"}},
		{name: "limit without a context is conditional", as: []*Assignment{asg("a1", "entry", "read", limit("x:l:amountLessThan", "100"))},
			res: "entry", act: "read", want: "allowed", via: []string{"a1"}, conditional: true},
		{name: "limit holds", as: []*Assignment{asg("a1", "entry", "read", limit("x:l:amountLessThan", "100"))},
			res: "entry", act: "read", ctx: Context{"amount": int64(99)}, want: "allowed", via: []string{"a1"}},
		{name: "limit fails: the assignment is set aside", as: []*Assignment{asg("a1", "entry", "read", limit("x:l:amountLessThan", "100"))},
			res: "entry", act: "read", ctx: Context{"amount": int64(100)}, want: "no_permission", limitsFailed: []string{"a1"}},
		{name: "a failed limit lets a broader allow decide", as: []*Assignment{asg("a1", "entry", "read", limit("x:l:amountLessThan", "100"), deny), asg("a2", "ledger", "read")},
			res: "entry", act: "read", ctx: Context{"amount": int64(500)}, want: "allowed", via: []string{"a2"}, limitsFailed: []string{"a1"}},
		{name: "a limit that does not compile never holds", as: []*Assignment{asg("a1", "entry", "read", limit("x:l:nonsense", "1"))},
			res: "entry", act: "read", ctx: Context{}, want: "no_permission", limitsFailed: []string{"a1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testSet(tc.as...)
			q := Query{DefID: def, NameID: tc.res, ActionID: tc.act, Resource: tc.res, Action: tc.act}
			d, err := s.Decide(sub, q, tc.ctx, t0)
			if err != nil {
				t.Fatal(err)
			}
			if d.Reason != tc.want || d.Allowed != (tc.want == "allowed") {
				t.Errorf("decision = %s (allowed %v), want %s", d.Reason, d.Allowed, tc.want)
			}
			var via []string
			for _, a := range d.Via {
				via = append(via, a.ID)
			}
			slices.Sort(via)
			if !slices.Equal(via, tc.via) {
				t.Errorf("via = %v, want %v", via, tc.via)
			}
			if d.Conditional != tc.conditional {
				t.Errorf("conditional = %v, want %v", d.Conditional, tc.conditional)
			}
			if !slices.Equal(d.LimitsFailed, tc.limitsFailed) {
				t.Errorf("limits failed = %v, want %v", d.LimitsFailed, tc.limitsFailed)
			}
		})
	}
}

// TestEffective_ExpandsInheritance: an assignment on ledger/admin lists every
// (resource, action) it implies, and the verdict of each follows the heuristics.
func TestEffective_ExpandsInheritance(t *testing.T) {
	s := testSet(asg("a1", "ledger", "admin"), asg("a2", "entry", "write", deny))
	s.nameFull, s.actionName = map[string]string{}, map[string]string{}
	for _, n := range []string{"ledger", "entry", "line"} {
		s.nameFull[n] = "f:d:" + n
	}
	for _, a := range []string{"admin", "write", "read"} {
		s.actionName[a] = a
	}
	sub := Subject{Identity: 1, Roles: map[store.GroupID]bool{"role-a": true}, Direct: map[store.GroupID]bool{"role-a": true}}
	got, truncated, err := s.Effective(sub, t0)
	if err != nil || truncated {
		t.Fatalf("Effective = %v, %v", truncated, err)
	}
	type row struct {
		res, act string
		allowed  bool
	}
	var rows []row
	for _, e := range got {
		rows = append(rows, row{e.Resource, e.Action, e.Allowed})
	}
	// entry/write is exact for a2 (disallow), so it beats ledger/admin; entry/read has the exact resource for a2;
	// line/write has the exact action for a2; line/read ties and the disallow wins; write does not imply admin
	want := []row{
		{"f:d:entry", "admin", true}, {"f:d:entry", "read", false}, {"f:d:entry", "write", false},
		{"f:d:ledger", "admin", true}, {"f:d:ledger", "read", true}, {"f:d:ledger", "write", true},
		{"f:d:line", "admin", true}, {"f:d:line", "read", false}, {"f:d:line", "write", false},
	}
	if !slices.Equal(rows, want) {
		t.Errorf("effective = %v\nwant %v", rows, want)
	}
}
