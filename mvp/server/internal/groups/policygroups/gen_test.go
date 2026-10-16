package policygroups

import (
	"fmt"
	"math/rand"
	"strings"
)

// A generator of random policy files in the fragment, and of random subjects, for
// the property tests of the compiler and of the PDP agreement.

var (
	genCampuses = []string{"main", "north", "Main", "a b"}
	genDepts    = []string{"cs", "math", "art"}
	genAffils   = []string{"faculty", "staff", "student"}
	genTitles   = []string{"dean", "chair"}
)

type gen struct {
	r      *rand.Rand
	groups []string // names a condition may refer to
}

// newGen is a test generator: a predictable source is the point.
func newGen(seed int64, groups []string) *gen {
	return &gen{r: rand.New(rand.NewSource(seed)), groups: groups}
}

func (g *gen) pick(xs []string) string { return xs[g.r.Intn(len(xs))] }

// atom is a positive or guarded test: always valid under testSchema.
func (g *gen) atom() Expr {
	switch g.r.Intn(8) {
	case 0, 1, 2:
		return InGroup{Name: g.pick(g.groups)}
	case 3:
		return AttrEq{Attr: "campus", Value: g.pick(genCampuses)}
	case 4:
		return AttrIn{Attr: "campus", Values: []string{g.pick(genCampuses), g.pick(genCampuses)}}
	case 5:
		return And{L: AttrHas{Attr: "department"}, R: AttrEq{Attr: "department", Value: g.pick(genDepts)}}
	case 6:
		return And{L: AttrHas{Attr: "affiliation"}, R: AttrContains{Attr: "affiliation", Value: g.pick(genAffils)}}
	}
	if g.r.Intn(2) == 0 {
		return AttrHas{Attr: g.pick([]string{"title", "department", "affiliation"})}
	}
	return And{L: AttrHas{Attr: "title"}, R: AttrEq{Attr: "title", Value: g.pick(genTitles)}}
}

func (g *gen) expr(depth int) Expr {
	if depth <= 0 || g.r.Intn(4) == 0 {
		return g.atom()
	}
	switch g.r.Intn(4) {
	case 0:
		return Not{X: g.expr(depth - 1)}
	case 1:
		return Or{L: g.expr(depth - 1), R: g.expr(depth - 1)}
	}
	return And{L: g.expr(depth - 1), R: g.expr(depth - 1)}
}

// policy is a condition that selects a bounded set: a positive base narrowed by anything.
func (g *gen) policyCond() Expr {
	return And{L: g.atom(), R: g.expr(3)}
}

// file renders a policy file for the group with 1 to 3 permits and up to 2 forbids.
func (g *gen) file(group string) string {
	var sb strings.Builder
	for i, n := 0, 1+g.r.Intn(3); i < n; i++ {
		fmt.Fprintf(&sb, "permit (principal, action == Tessera::Action::\"member\", resource == Tessera::Group::%q)\nwhen { %s };\n", group, String(g.policyCond()))
	}
	for i, n := 0, g.r.Intn(3); i < n; i++ {
		fmt.Fprintf(&sb, "forbid (principal, action == Tessera::Action::\"member\", resource == Tessera::Group::%q)\nwhen { %s };\n", group, String(g.policyCond()))
	}
	return sb.String()
}

// fakeSubject is an identity: the groups it is in and its attribute values.
type fakeSubject struct {
	groups map[string]bool // lower-cased group name
	attrs  map[string][]string
}

func (s fakeSubject) InGroup(name string) (bool, error) { return s.groups[strings.ToLower(name)], nil }
func (s fakeSubject) Attr(name string) ([]string, bool) {
	v := s.attrs[name]
	return v, len(v) > 0
}

func (g *gen) subject() fakeSubject {
	s := fakeSubject{groups: map[string]bool{}, attrs: map[string][]string{"campus": {g.pick(genCampuses)}}}
	for _, n := range g.groups {
		s.groups[strings.ToLower(n)] = g.r.Intn(2) == 0
	}
	if g.r.Intn(3) > 0 {
		s.attrs["department"] = []string{g.pick(genDepts)}
	}
	if g.r.Intn(3) > 0 {
		s.attrs["title"] = []string{g.pick(genTitles)}
	}
	for _, a := range genAffils {
		if g.r.Intn(3) == 0 {
			s.attrs["affiliation"] = append(s.attrs["affiliation"], a)
		}
	}
	return s
}
