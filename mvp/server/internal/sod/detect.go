package sod

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
)

// Match reports whether pattern matches s: `*` matches any run of characters
// (including none), `\` escapes the next character, everything else is literal.
func Match(pattern, s string) bool {
	p, t := []rune(pattern), []rune(s)
	pi, ti, star, mark := 0, 0, -1, 0
	for ti < len(t) {
		switch {
		case pi < len(p) && p[pi] == '\\' && pi+1 < len(p) && p[pi+1] == t[ti]:
			pi, ti = pi+2, ti+1
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, ti
			pi++
		case pi < len(p) && p[pi] != '\\' && p[pi] == t[ti]:
			pi, ti = pi+1, ti+1
		case star >= 0:
			mark++
			pi, ti = star+1, mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

// EscapePattern makes s match only itself in a name pattern.
func EscapePattern(s string) string {
	return strings.NewReplacer(`\`, `\\`, `*`, `\*`).Replace(s)
}

// Matches reports whether the selector picks the effective permission.
func (s *Selector) Matches(ep *graph.EffectivePermission) bool {
	if s.System != "" && s.System != ep.System {
		return false
	}
	if s.EntitlementID != nil {
		if ep.PermID != *s.EntitlementID {
			return false
		}
	} else if !Match(s.NamePattern, ep.Action) {
		return false
	}
	switch s.Attribute {
	case "":
	case "environment":
		if ep.Environment == nil || *ep.Environment != s.Value {
			return false
		}
	case "tag":
		if !contains(ep.Tags, s.Value) {
			return false
		}
	case "resource":
		if !Match(s.Value, ep.ResourceName) {
			return false
		}
	case "privileged":
		if (s.Value == "true") != ep.Privileged {
			return false
		}
	default:
		return false
	}
	return true
}

// Function is a compiled function: what the engine matches against.
type Function struct {
	ID        string
	Key       string
	Name      string
	Selectors []Selector
}

// Matches reports whether any selector picks the permission.
func (f *Function) Matches(ep *graph.EffectivePermission) bool {
	for i := range f.Selectors {
		if f.Selectors[i].Matches(ep) {
			return true
		}
	}
	return false
}

// Violation statuses.
const StatusOpen = "open"

// Ref names a function in a violation.
type Ref struct {
	ID   string `json:"id"`
	Key  string `json:"key"`
	Name string `json:"name"`
}

// RulesetRef names the ruleset a risk belongs to.
type RulesetRef struct {
	ID   string `json:"id"`
	Key  string `json:"key"`
	Name string `json:"name"`
}

// Risk is a compiled risk: its functions in order, its ruleset and the
// subjects it applies to. Only enabled rulesets' active risks are compiled.
type Risk struct {
	ID              string
	Key             string
	Name            string
	Description     string
	Priority        string
	BusinessProcess string
	OwnerID         *int64
	Version         int
	Ruleset         RulesetRef
	Functions       []*Function
	Subjects        Subjects
	Remediation     []string // explicit remediation options; none: all
}

// Grant is one entitlement an identity holds on one side of a violation, with
// the paths that grant it.
type Grant struct {
	PermKey    string   `json:"perm_key"`
	Action     string   `json:"action"`
	Resource   string   `json:"resource"`
	System     string   `json:"system"`
	Privileged bool     `json:"privileged"`
	Paths      []string `json:"paths"`
}

// Side is one half of a violation: a function and the entitlements held from it.
type Side struct {
	Function Ref     `json:"function"`
	Grants   []Grant `json:"grants"`
}

// Violation is one identity holding both halves of a risk.
type Violation struct {
	Key             string     `json:"key"`
	RiskID          string     `json:"risk_id"`
	RiskKey         string     `json:"risk_key"`
	RiskName        string     `json:"risk_name"`
	Priority        string     `json:"priority"`
	Ruleset         RulesetRef `json:"ruleset"`
	BusinessProcess string     `json:"business_process"`
	IdentityID      int64      `json:"identity_id"`
	IdentityName    string     `json:"identity_name"`
	Function1       Ref        `json:"function1"`
	Function2       Ref        `json:"function2"`
	Entitlement     string     `json:"entitlement"`
	Systems         []string   `json:"systems"`
	Sides           [2]Side    `json:"sides"`
	Status          string     `json:"status"` // open, mitigated, accepted, mitigation_pending (see mitigation.go)
	Mitigation      *Cover     `json:"mitigation,omitempty"`
	Message         string     `json:"message"`
	Evidence        []string   `json:"evidence"`
	Edges           [][]string `json:"edges"`
	// ExplanationID names the AWS evaluator trace behind the finding; absent
	// when no evaluated permission or edge is implicated. It is one trace, not
	// both sides': permission a's if it has one, else b's, else the first
	// evaluated implicated edge's.
	ExplanationID string `json:"explanation_id,omitempty"`
}

// Env is what detection needs from the caller: the graph, and who a risk's
// subjects select (the caller owns attribute lookups for conditions).
type Env struct {
	Graph    *graph.Snapshot
	Subjects func(*Subjects) []int64
}

const (
	maxGrants       = 5 // entitlements listed per side
	maxPathsPerPerm = 3
)

func ref(f *Function) Ref { return Ref{f.ID, f.Key, f.Name} }

func evidence(g *graph.Snapshot, ep *graph.EffectivePermission) ([]string, [][]string) {
	paths := ep.Paths
	if len(paths) > maxPathsPerPerm {
		paths = paths[:maxPathsPerPerm]
	}
	texts, edges := []string{}, [][]string{}
	for _, p := range paths {
		texts = append(texts, g.PathText(p))
	}
	for _, p := range paths {
		if fh, ok := graph.FirstHopEdge(p); ok {
			dup := false
			for _, e := range edges {
				if e[0] == fh[0] && e[1] == fh[1] {
					dup = true
					break
				}
			}
			if !dup {
				edges = append(edges, []string{fh[0], fh[1]})
			}
		}
	}
	return texts, edges
}

func grants(g *graph.Snapshot, eps []*graph.EffectivePermission) []Grant {
	out := []Grant{}
	for _, ep := range eps {
		if len(out) == maxGrants {
			break
		}
		ev, _ := evidence(g, ep)
		out = append(out, Grant{PermKey: ep.PermKey, Action: ep.Action, Resource: ep.ResourceName, System: ep.System,
			Privileged: ep.Privileged, Paths: ev})
	}
	return out
}

// pick returns the first pair of distinct entitlements, one from a and one
// from b (a function overlapping another cannot conflict through one
// entitlement alone).
func pick(a, b []*graph.EffectivePermission) (x, y *graph.EffectivePermission) {
	for _, p := range a {
		for _, q := range b {
			if p.PermKey != q.PermKey {
				return p, q
			}
		}
	}
	return nil, nil
}

// Detect lists the violations of the risks: for each risk, each identity in
// its subjects, and each pair of the risk's functions that the identity holds
// one distinct entitlement of both. A risk of exactly two functions gives at
// most one violation per identity, keyed "<risk key>:<identity id>".
func Detect(env Env, risks []*Risk) []Violation {
	var out []Violation
	for _, r := range risks {
		if len(r.Functions) < 2 {
			continue
		}
		for _, iid := range env.Subjects(&r.Subjects) {
			node := env.Graph.Node(graph.Key("identity", iid))
			if node == nil {
				continue
			}
			held := make([][]*graph.EffectivePermission, len(r.Functions))
			any := false
			for _, ep := range env.Graph.EffectivePermissions(iid).Values() {
				for i, f := range r.Functions {
					if f.Matches(ep) {
						held[i] = append(held[i], ep)
						any = true
					}
				}
			}
			if !any {
				continue
			}
			for i := 0; i < len(r.Functions); i++ {
				for j := i + 1; j < len(r.Functions); j++ {
					a, b := pick(held[i], held[j])
					if a == nil {
						continue
					}
					out = append(out, violation(env.Graph, r, node, i, j, held[i], held[j], a, b))
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := PriorityRank[out[i].Priority], PriorityRank[out[j].Priority]
		if ri != rj {
			return ri > rj
		}
		if out[i].RiskKey != out[j].RiskKey {
			return out[i].RiskKey < out[j].RiskKey
		}
		if out[i].IdentityName != out[j].IdentityName {
			return out[i].IdentityName < out[j].IdentityName
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func violation(g *graph.Snapshot, r *Risk, n *graph.Node, i, j int, ha, hb []*graph.EffectivePermission, a, b *graph.EffectivePermission) Violation {
	key := fmt.Sprintf("%s:%d", r.Key, n.ID)
	if len(r.Functions) > 2 {
		key += ":" + r.Functions[i].Key + "+" + r.Functions[j].Key
	}
	evA, edA := evidence(g, a)
	evB, edB := evidence(g, b)
	systems := []string{a.System}
	if b.System != a.System {
		systems = append(systems, b.System)
	}
	sort.Strings(systems)
	expl := ""
	for _, ep := range []*graph.EffectivePermission{a, b} {
		if expl == "" && len(ep.ExplanationIDs) > 0 {
			expl = ep.ExplanationIDs[0]
		}
	}
	edges := append(edA, edB...)
	if expl == "" {
		expl = g.EdgesExplanation(edges)
	}
	return Violation{
		ExplanationID: expl,
		Key:           key, RiskID: r.ID, RiskKey: r.Key, RiskName: r.Name, Priority: r.Priority, Ruleset: r.Ruleset,
		BusinessProcess: r.BusinessProcess, IdentityID: n.ID, IdentityName: n.Label,
		Function1: ref(r.Functions[i]), Function2: ref(r.Functions[j]),
		Entitlement: a.Action + " / " + b.Action, Systems: systems,
		Sides:  [2]Side{{ref(r.Functions[i]), grants(g, ha)}, {ref(r.Functions[j]), grants(g, hb)}},
		Status: StatusOpen, Message: fmt.Sprintf("%s can both %s and %s on %s", n.Label, a.Action, b.Action, a.ResourceName),
		Evidence: append(evA, evB...), Edges: append(edA, edB...),
	}
}

// Introduced returns the violations of after whose key is not in before.
func Introduced(before, after []Violation) []Violation {
	had := make(map[string]bool, len(before))
	for _, v := range before {
		had[v.Key] = true
	}
	out := []Violation{}
	for _, v := range after {
		if !had[v.Key] {
			out = append(out, v)
		}
	}
	return out
}
