package blast

import (
	"math/bits"
	"sort"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/query"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/simulate"
)

// Lists in a report are cut to these, so the answer to a very large change stays a size a pull request can show;
// the counts in Summary are never cut.
const (
	MaxIdentities = 200
	MaxResources  = 100
	MaxViolations = 100
	maxActions    = 10
)

// AgentType is the identity type of an AI agent.
const AgentType = "ai_agent"

// Person is an identity of the tenant, as the report names it.
type Person struct {
	ID   int64
	Name string
	Type string // human, service or ai_agent
}

// AWSDiff is the AWS half of a change: the cells that differ between the base and the head snapshot, and how the
// AWS principals map to identities.
type AWSDiff struct {
	Changes []query.Change
	// Principals maps a principal ARN to the identity that owns its aws account (the collector's materialized
	// account, external id = ARN). A principal with no entry is counted as unlinked.
	Principals map[string]int64
}

// Inputs are what Summarize joins.
type Inputs struct {
	People map[int64]Person
	Graph  *simulate.Result // nil: no simulation ran, so the violations are reported as zero (the API always runs one)
	AWS    *AWSDiff         // nil: no AWS operations
}

// Summary totals the change. Counts are exact; they are never cut like the lists.
type Summary struct {
	IdentitiesAffected int `json:"identities_affected"`
	IdentitiesGaining  int `json:"identities_gaining"`
	IdentitiesLosing   int `json:"identities_losing"`
	AgentsGaining      int `json:"agents_gaining"`
	AgentsLosing       int `json:"agents_losing"`
	// GraphPermissionsGained and Lost count the effective permissions the graph edits add and remove.
	GraphPermissionsGained int `json:"graph_permissions_gained"`
	GraphPermissionsLost   int `json:"graph_permissions_lost"`
	// AWSPathsGained and Lost count (action, resource) pairs summed over the identities that gain or lose them.
	AWSPathsGained int64 `json:"aws_paths_gained"`
	AWSPathsLost   int64 `json:"aws_paths_lost"`
	// UnlinkedPrincipals are AWS principals the diff reaches that no identity owns an account for: their change is
	// real but cannot be attributed to a person, service or agent.
	UnlinkedPrincipals int `json:"unlinked_principals"`
	// Approximate counts the principals whose answer changed only in its conditions or fidelity, and results that
	// rest on approximate evaluation; they are not counted as gains or losses.
	Approximate     int `json:"approximate"`
	ResourcesGained int `json:"resources_gained"`
}

// TypeDelta is the change for one identity type.
type TypeDelta struct {
	Type              string `json:"type"`
	IdentitiesGaining int    `json:"identities_gaining"`
	IdentitiesLosing  int    `json:"identities_losing"`
}

// ResourceDelta is the change for one resource: how many identities gain a path to it, and how many of those are
// agents.
type ResourceDelta struct {
	Resource          string   `json:"resource"`
	Systems           []string `json:"systems"`
	IdentitiesGaining int      `json:"identities_gaining"`
	AgentsGaining     int      `json:"agents_gaining"`
	IdentitiesLosing  int      `json:"identities_losing"`
	// Actions are the first few (sorted) actions on the resource that change.
	Actions []string `json:"actions"`
}

// IdentityDelta is the change for one identity.
type IdentityDelta struct {
	IdentityID             int64  `json:"identity_id"`
	Name                   string `json:"name"`
	Type                   string `json:"type"`
	GraphPermissionsGained int    `json:"graph_permissions_gained"`
	GraphPermissionsLost   int    `json:"graph_permissions_lost"`
	AWSPathsGained         int64  `json:"aws_paths_gained"`
	AWSPathsLost           int64  `json:"aws_paths_lost"`
}

// ViolationRef names one policy finding that the change introduces or resolves.
type ViolationRef struct {
	Key          string `json:"key"`
	PolicyID     string `json:"policy_id"`
	Severity     string `json:"severity"`
	IdentityID   *int64 `json:"identity_id"`
	IdentityName string `json:"identity_name"`
	Message      string `json:"message"`
}

// Violations are the policy findings before and after, as policy.DiffViolations gives them. The agent-scope
// counts are the findings of the two agent scope invariants (AC-7) among them.
type Violations struct {
	Before               int            `json:"before"`
	After                int            `json:"after"`
	Introduced           []ViolationRef `json:"introduced"`
	Resolved             []ViolationRef `json:"resolved"`
	IntroducedTotal      int            `json:"introduced_total"`
	ResolvedTotal        int            `json:"resolved_total"`
	AgentScopeIntroduced int            `json:"agent_scope_introduced"`
	AgentScopeResolved   int            `json:"agent_scope_resolved"`
	IntroducedOmitted    int            `json:"introduced_omitted"`
	ResolvedOmitted      int            `json:"resolved_omitted"`
}

// Report is the joined, sorted answer.
type Report struct {
	Summary           Summary         `json:"summary"`
	ByIdentityType    []TypeDelta     `json:"by_identity_type"`
	ByResource        []ResourceDelta `json:"by_resource"`
	ResourcesOmitted  int             `json:"resources_omitted"`
	Identities        []IdentityDelta `json:"identities"`
	IdentitiesOmitted int             `json:"identities_omitted"`
	Violations        Violations      `json:"violations"`
}

// bitset is a set of dense identity indexes.
type bitset []uint64

func newBitset(n int) bitset { return make(bitset, (n+63)/64) }

func (b bitset) set(i int)      { b[i>>6] |= 1 << (uint(i) & 63) }
func (b bitset) has(i int) bool { return b[i>>6]&(1<<(uint(i)&63)) != 0 }

// count is the number of members, of those in mask when mask is not nil.
func (b bitset) count(mask bitset) int {
	n := 0
	for i, w := range b {
		if mask != nil {
			w &= mask[i]
		}
		n += bits.OnesCount64(w)
	}
	return n
}

type resAgg struct {
	gain, lose bitset
	systems    map[string]bool
	actions    map[string]bool
}

// Summarize joins the graph and AWS answers. Identities are indexed in id order and every list is sorted, so the
// report is a function of the inputs alone.
func Summarize(in Inputs) *Report {
	people := make(map[int64]Person, len(in.People))
	for id, p := range in.People {
		people[id] = p
	}
	if in.Graph != nil { // an identity the graph names that the caller did not list
		for _, ic := range in.Graph.Identities {
			if _, ok := people[ic.IdentityID]; !ok {
				people[ic.IdentityID] = Person{ID: ic.IdentityID, Name: ic.Name, Type: ic.Type}
			}
		}
	}
	ids := make([]int64, 0, len(people))
	for id := range people {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	idx := make(map[int64]int, len(ids))
	types := make([]string, len(ids))
	for i, id := range ids {
		idx[id], types[i] = i, people[id].Type
	}
	n := len(ids)
	agents := newBitset(n)
	for i, t := range types {
		if t == AgentType {
			agents.set(i)
		}
	}
	gain, lose := newBitset(n), newBitset(n)
	deltas := make([]IdentityDelta, n)
	touched := newBitset(n)
	touch := func(i int) *IdentityDelta {
		touched.set(i)
		d := &deltas[i]
		if d.Name == "" {
			p := people[ids[i]]
			d.IdentityID, d.Name, d.Type = p.ID, p.Name, p.Type
		}
		return d
	}
	res := map[string]*resAgg{}
	agg := func(name string) *resAgg {
		r := res[name]
		if r == nil {
			r = &resAgg{gain: newBitset(n), lose: newBitset(n), systems: map[string]bool{}, actions: map[string]bool{}}
			res[name] = r
		}
		return r
	}
	rep := &Report{ByIdentityType: []TypeDelta{}, ByResource: []ResourceDelta{}, Identities: []IdentityDelta{},
		Violations: Violations{Introduced: []ViolationRef{}, Resolved: []ViolationRef{}}}
	sum := &rep.Summary

	if g := in.Graph; g != nil {
		for _, ic := range g.Identities {
			i := idx[ic.IdentityID]
			d := touch(i)
			for _, a := range ic.Added {
				gain.set(i)
				d.GraphPermissionsGained++
				sum.GraphPermissionsGained++
				r := agg(a.Resource)
				r.gain.set(i)
				r.systems[a.System] = true
				r.actions[a.Action] = true
			}
			for _, rm := range ic.Removed {
				lose.set(i)
				d.GraphPermissionsLost++
				sum.GraphPermissionsLost++
				r := agg(rm.Resource)
				r.lose.set(i)
				r.systems[rm.System] = true
				r.actions[rm.Action] = true
			}
		}
		rep.Violations = violationsOf(g)
	}

	if a := in.AWS; a != nil {
		unlinked := map[string]bool{}
		for ci := range a.Changes {
			c := &a.Changes[ci]
			paths := int64(c.ActionCount) * int64(c.ResourceCount)
			for _, p := range c.Principals {
				id, ok := a.Principals[p]
				if !ok {
					unlinked[p] = true
					continue
				}
				i, known := idx[id]
				if !known {
					unlinked[p] = true
					continue
				}
				switch c.Kind {
				case query.Gained:
					gain.set(i)
					touch(i).AWSPathsGained += paths
					sum.AWSPathsGained += paths
					for _, name := range c.Resources {
						r := agg(name)
						r.gain.set(i)
						r.systems["aws"] = true
						for _, act := range c.Actions {
							r.actions[act] = true
						}
					}
				case query.Lost:
					lose.set(i)
					touch(i).AWSPathsLost += paths
					sum.AWSPathsLost += paths
					for _, name := range c.Resources {
						r := agg(name)
						r.lose.set(i)
						r.systems["aws"] = true
						for _, act := range c.Actions {
							r.actions[act] = true
						}
					}
				default: // the conditions or the fidelity changed, not whether the access exists
					sum.Approximate++
				}
			}
		}
		sum.UnlinkedPrincipals = len(unlinked)
	}

	// by identity type
	byType := map[string]*TypeDelta{}
	for i := 0; i < n; i++ {
		g, l := gain.has(i), lose.has(i)
		if !g && !l {
			continue
		}
		td := byType[types[i]]
		if td == nil {
			td = &TypeDelta{Type: types[i]}
			byType[types[i]] = td
		}
		if g {
			td.IdentitiesGaining++
			sum.IdentitiesGaining++
			if types[i] == AgentType {
				sum.AgentsGaining++
			}
		}
		if l {
			td.IdentitiesLosing++
			sum.IdentitiesLosing++
			if types[i] == AgentType {
				sum.AgentsLosing++
			}
		}
		sum.IdentitiesAffected++
	}
	for _, td := range byType {
		rep.ByIdentityType = append(rep.ByIdentityType, *td)
	}
	sort.Slice(rep.ByIdentityType, func(i, j int) bool { return rep.ByIdentityType[i].Type < rep.ByIdentityType[j].Type })

	// by resource
	names := make([]string, 0, len(res))
	for name := range res {
		names = append(names, name)
	}
	sort.Strings(names)
	var all []ResourceDelta
	for _, name := range names {
		r := res[name]
		d := ResourceDelta{Resource: name, Systems: sortedKeys(r.systems), IdentitiesGaining: r.gain.count(nil),
			AgentsGaining: r.gain.count(agents), IdentitiesLosing: r.lose.count(nil)}
		if d.IdentitiesGaining > 0 {
			sum.ResourcesGained++
		}
		d.Actions = sortedKeys(r.actions)
		if len(d.Actions) > maxActions {
			d.Actions = d.Actions[:maxActions]
		}
		all = append(all, d)
	}
	sort.SliceStable(all, func(i, j int) bool { // names are already in order, and the sort is stable
		if all[i].IdentitiesGaining != all[j].IdentitiesGaining {
			return all[i].IdentitiesGaining > all[j].IdentitiesGaining
		}
		return all[i].IdentitiesLosing > all[j].IdentitiesLosing
	})
	if len(all) > MaxResources {
		rep.ResourcesOmitted, all = len(all)-MaxResources, all[:MaxResources]
	}
	if all != nil {
		rep.ByResource = all
	}

	// identities, the biggest changes first
	var list []IdentityDelta
	for i := 0; i < n; i++ {
		if touched.has(i) {
			list = append(list, deltas[i])
		}
	}
	score := func(d *IdentityDelta) int64 { return int64(d.GraphPermissionsGained) + d.AWSPathsGained }
	sort.SliceStable(list, func(i, j int) bool { return score(&list[i]) > score(&list[j]) })
	if len(list) > MaxIdentities {
		rep.IdentitiesOmitted, list = len(list)-MaxIdentities, list[:MaxIdentities]
	}
	if list != nil {
		rep.Identities = list
	}
	return rep
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func violationsOf(g *simulate.Result) Violations {
	v := Violations{Before: g.Summary.ViolationsBefore, After: g.Summary.ViolationsAfter,
		Introduced: []ViolationRef{}, Resolved: []ViolationRef{}}
	agent := func(id string) bool {
		return id == policy.PolicyAgentOutOfScope || id == policy.PolicyAgentExceedsOwner
	}
	cut := func(in []policy.Violation, scoped *int) ([]ViolationRef, int) {
		out := []ViolationRef{}
		for _, x := range in {
			if agent(x.PolicyID) {
				*scoped++
			}
			if len(out) < MaxViolations {
				out = append(out, ViolationRef{Key: x.Key, PolicyID: x.PolicyID, Severity: x.Severity, IdentityID: x.IdentityID,
					IdentityName: x.IdentityName, Message: x.Message})
			}
		}
		return out, len(in) - len(out)
	}
	v.Introduced, v.IntroducedOmitted = cut(g.Violations.Introduced, &v.AgentScopeIntroduced)
	v.Resolved, v.ResolvedOmitted = cut(g.Violations.Resolved, &v.AgentScopeResolved)
	v.IntroducedTotal, v.ResolvedTotal = len(g.Violations.Introduced), len(g.Violations.Resolved)
	return v
}
