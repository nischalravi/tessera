// Package mining suggests business roles from the access people hold today
// (issue #298, "Role mining").
//
// The engine is deterministic and has no random seed: the same people, the
// same entitlements and the same parameters always give the same candidates.
// Input is every active person's standing entitlements (groups reached by an
// account's non-expiring grant), optionally filtered by department, title and
// worker type.
//
//  1. Entitlements held by fewer than MinMembers people are dropped.
//  2. People with the same remaining set share a profile. Profiles are
//     ordered (most people, then largest set, then key) and clustered with a
//     leader pass: a profile joins the cluster whose leader it matches best,
//     if that is at least MinSimilarity Jaccard similarity, else it starts a
//     cluster. A cluster's core is the intersection of its profiles.
//  3. A core of at least MinEntitlements becomes a candidate. Its coverage is
//     everyone, in the whole filtered population, who holds all of it.
//     Outliers are covered people who also hold an entitlement few of the
//     others do.
//  4. The attribute (department, title or worker type) whose values best
//     predict coverage (F1, greedy over the values of one attribute) is the
//     suggested birthright rule.
//
// Bounds: MaxPeople people per run, MaxEntitlementsPerPerson, MaxProfiles
// clustered profiles, MaxWork comparison steps (the run stops early and is
// marked truncated) and MaxCandidates results. Everything is integer maths
// so results do not vary by platform.
package mining

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Algorithm names the version of the method; it is part of the snapshot hash.
const Algorithm = "jaccard-leader-v1"

// Limits.
const (
	MaxPeople                = 20000
	MaxEntitlementsPerPerson = 300
	MaxProfiles              = 3000
	MaxWork                  = 40_000_000
	MaxCandidates            = 100
	MaxOutliers              = 200
	MaxOutlierExtras         = 50
	MaxFilterValues          = 20
	MaxFilterLen             = 120
	outlierPct               = 25 // an extra held by under 25% of the covered is rare
	minRuleF1                = 50 // no rule is suggested below this predictive F1 (percent)
)

// Defaults.
const (
	DefaultMinMembers      = 3
	DefaultMinEntitlements = 2
	DefaultMinSimilarity   = 60
	DefaultMaxCandidates   = 25
)

// Params are a run's settings. Filters are any-of lists (empty: no filter).
type Params struct {
	Department      []string `json:"department"`
	Title           []string `json:"title"`
	Type            []string `json:"type"` // worker type
	MinMembers      int      `json:"min_members"`
	MinEntitlements int      `json:"min_entitlements"`
	MinSimilarity   int      `json:"min_similarity"` // Jaccard, percent
	MaxCandidates   int      `json:"max_candidates"`
}

// ParamError is a refused parameter.
type ParamError struct{ Msg string }

func (e *ParamError) Error() string { return e.Msg }

func cleanList(name string, vs []string) ([]string, error) {
	out := []string{}
	for _, v := range vs {
		if v = strings.TrimSpace(v); v == "" {
			continue
		}
		if len(v) > MaxFilterLen {
			return nil, &ParamError{fmt.Sprintf("a %s filter value is at most %d characters", name, MaxFilterLen)}
		}
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	if len(out) > MaxFilterValues {
		return nil, &ParamError{fmt.Sprintf("the %s filter lists at most %d values", name, MaxFilterValues)}
	}
	sort.Strings(out)
	return out, nil
}

// Normalize fills defaults, cleans the filters and checks the ranges.
func (p Params) Normalize() (Params, error) {
	var err error
	if p.Department, err = cleanList("department", p.Department); err != nil {
		return p, err
	}
	if p.Title, err = cleanList("title", p.Title); err != nil {
		return p, err
	}
	if p.Type, err = cleanList("type", p.Type); err != nil {
		return p, err
	}
	def := func(v *int, d int) {
		if *v == 0 {
			*v = d
		}
	}
	def(&p.MinMembers, DefaultMinMembers)
	def(&p.MinEntitlements, DefaultMinEntitlements)
	def(&p.MinSimilarity, DefaultMinSimilarity)
	def(&p.MaxCandidates, DefaultMaxCandidates)
	switch {
	case p.MinMembers < 2 || p.MinMembers > 1000:
		return p, &ParamError{"min_members is 2 to 1000"}
	case p.MinEntitlements < 2 || p.MinEntitlements > 50:
		return p, &ParamError{"min_entitlements is 2 to 50"}
	case p.MinSimilarity < 30 || p.MinSimilarity > 100:
		return p, &ParamError{"min_similarity is 30 to 100 (percent)"}
	case p.MaxCandidates < 1 || p.MaxCandidates > MaxCandidates:
		return p, &ParamError{fmt.Sprintf("max_candidates is 1 to %d", MaxCandidates)}
	}
	return p, nil
}

// Person is one identity with the entitlements (group ids) it holds.
type Person struct {
	ID           int64
	Department   string // "" when unknown
	Title        string
	Type         string
	Entitlements []int64
}

// Role is an existing active role's entitlement set.
type Role struct {
	ID           string
	Entitlements []int64
}

// Input is what a run mines.
type Input struct {
	People []Person
	Roles  []Role
}

// Outlier is a covered person holding rare extra entitlements.
type Outlier struct {
	IdentityID int64   `json:"identity_id"`
	Extra      []int64 `json:"extra"`
}

// Rule is the suggested birthright rule: one attribute and the values that
// best predict coverage, with precision and recall in percent.
type Rule struct {
	Attribute string   `json:"attribute"` // department, title or type
	Values    []string `json:"values"`
	Precision int      `json:"precision"`
	Recall    int      `json:"recall"`
}

// Candidate is a suggested role.
type Candidate struct {
	Rank         int       `json:"rank"`
	Name         string    `json:"name"`
	Entitlements []int64   `json:"entitlements"`
	Members      []int64   `json:"members"` // everyone who holds all of Entitlements
	Outliers     []Outlier `json:"outliers"`
	Rule         *Rule     `json:"rule"`
	Confidence   int       `json:"confidence"` // 0 to 100
	Cohesion     int       `json:"cohesion"`   // how close the members are to the entitlement set, percent
	SimilarRole  string    `json:"similar_role"`
	Similarity   int       `json:"similarity"` // Jaccard to SimilarRole, percent
}

// Output is a run's result.
type Output struct {
	SnapshotHash    string
	Params          Params
	People          int // people mined, after filters
	Entitlements    int // distinct entitlements held
	SkippedPeople   int // held more than MaxEntitlementsPerPerson
	SkippedExisting int // candidates equal to an existing role
	Truncated       bool
	Candidates      []Candidate
}

// InputError is a run refused for its input.
type InputError struct{ Code, Msg string }

func (e *InputError) Error() string { return e.Msg }

func keyOf(ids []int64) string {
	var b strings.Builder
	for i, id := range ids {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.FormatInt(id, 10))
	}
	return b.String()
}

func sortedUnique(ids []int64) []int64 {
	out := slices.Clone(ids)
	slices.Sort(out)
	return slices.Compact(out)
}

// inter returns the sorted intersection of two sorted sets.
func inter(a, b []int64) []int64 {
	out := []int64{}
	for i, j := 0, 0; i < len(a) && j < len(b); {
		switch {
		case a[i] < b[j]:
			i++
		case a[i] > b[j]:
			j++
		default:
			out = append(out, a[i])
			i++
			j++
		}
	}
	return out
}

// jaccard is the similarity of two sorted sets in percent.
func jaccard(a, b []int64) int {
	n := len(inter(a, b))
	u := len(a) + len(b) - n
	if u == 0 {
		return 100
	}
	return n * 100 / u
}

func match(filter []string, v string) bool { return len(filter) == 0 || slices.Contains(filter, v) }

// snapshotHash covers the algorithm, the parameters and the filtered input,
// so a stored run can be checked against the data it was computed from.
func snapshotHash(p Params, people []Person, rs []Role) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\nmm=%d me=%d ms=%d mc=%d\n", Algorithm, p.MinMembers, p.MinEntitlements, p.MinSimilarity, p.MaxCandidates)
	fmt.Fprintf(h, "d=%q t=%q y=%q\n", p.Department, p.Title, p.Type)
	for _, x := range people {
		fmt.Fprintf(h, "p%d|%q|%q|%q|%s\n", x.ID, x.Department, x.Title, x.Type, keyOf(x.Entitlements))
	}
	for _, r := range rs {
		fmt.Fprintf(h, "r%s|%s\n", r.ID, keyOf(r.Entitlements))
	}
	return hex.EncodeToString(h.Sum(nil))
}

type profile struct {
	ents  []int64
	key   string
	count int
}

type cluster struct {
	leader []int64
	core   []int64
}

// Mine runs the method. It checks ctx between steps and stops with the
// context's error.
func Mine(ctx context.Context, p Params, in Input) (*Output, error) {
	p, err := p.Normalize()
	if err != nil {
		return nil, err
	}
	var people []Person
	for _, x := range in.People {
		if match(p.Department, x.Department) && match(p.Title, x.Title) && match(p.Type, x.Type) {
			x.Entitlements = sortedUnique(x.Entitlements)
			people = append(people, x)
		}
	}
	if len(people) > MaxPeople {
		return nil, &InputError{"too_many_identities", fmt.Sprintf("%d people match; a run mines at most %d, so narrow it with a filter", len(people), MaxPeople)}
	}
	slices.SortFunc(people, func(a, b Person) int {
		switch {
		case a.ID < b.ID:
			return -1
		case a.ID > b.ID:
			return 1
		}
		return 0
	})
	rs := slices.Clone(in.Roles)
	for i := range rs {
		rs[i].Entitlements = sortedUnique(rs[i].Entitlements)
	}
	slices.SortFunc(rs, func(a, b Role) int { return strings.Compare(a.ID, b.ID) })
	out := &Output{SnapshotHash: snapshotHash(p, people, rs), Params: p, People: len(people), Candidates: []Candidate{}}

	// people holding too many entitlements are admins, not a pattern
	mined := make([]Person, 0, len(people))
	for _, x := range people {
		if len(x.Entitlements) > MaxEntitlementsPerPerson {
			out.SkippedPeople++
			continue
		}
		mined = append(mined, x)
	}
	people = mined
	support := map[int64]int{}
	for _, x := range people {
		for _, e := range x.Entitlements {
			support[e]++
		}
	}
	out.Entitlements = len(support)

	// profiles over the frequent entitlements
	byKey := map[string]*profile{}
	for i := range people {
		var ents []int64
		for _, e := range people[i].Entitlements {
			if support[e] >= p.MinMembers {
				ents = append(ents, e)
			}
		}
		if len(ents) < p.MinEntitlements {
			continue
		}
		k := keyOf(ents)
		if pr := byKey[k]; pr != nil {
			pr.count++
		} else {
			byKey[k] = &profile{ents: ents, key: k, count: 1}
		}
	}
	profiles := make([]*profile, 0, len(byKey))
	for _, pr := range byKey {
		profiles = append(profiles, pr)
	}
	sort.Slice(profiles, func(i, j int) bool {
		a, b := profiles[i], profiles[j]
		if a.count != b.count {
			return a.count > b.count
		}
		if len(a.ents) != len(b.ents) {
			return len(a.ents) > len(b.ents)
		}
		return a.key < b.key
	})
	if len(profiles) > MaxProfiles {
		profiles, out.Truncated = profiles[:MaxProfiles], true
	}

	// leader clustering
	var clusters []*cluster
	work := 0
clustering:
	for i, pr := range profiles {
		if i%64 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		best, bestSim := -1, p.MinSimilarity-1
		for ci, c := range clusters {
			work += len(c.leader) + len(pr.ents)
			if work > MaxWork {
				out.Truncated = true
				break clustering
			}
			if s := jaccard(c.leader, pr.ents); s > bestSim {
				best, bestSim = ci, s
			}
		}
		if best < 0 {
			clusters = append(clusters, &cluster{leader: pr.ents, core: pr.ents})
		} else {
			clusters[best].core = inter(clusters[best].core, pr.ents)
		}
	}

	// posting lists: person index by frequent entitlement
	post := map[int64][]int{}
	for i, x := range people {
		for _, e := range x.Entitlements {
			if support[e] >= p.MinMembers {
				post[e] = append(post[e], i)
			}
		}
	}
	seen := map[string]bool{}
	var cands []Candidate
	for _, c := range clusters {
		if len(c.core) < p.MinEntitlements || seen[keyOf(c.core)] {
			continue
		}
		seen[keyOf(c.core)] = true
		cov := cover(c.core, post)
		if len(cov) < p.MinMembers {
			continue
		}
		if slices.ContainsFunc(rs, func(r Role) bool { return slices.Equal(r.Entitlements, c.core) }) {
			out.SkippedExisting++
			continue
		}
		cands = append(cands, build(c.core, cov, people, rs, p))
	}
	sort.SliceStable(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		if a.Confidence != b.Confidence {
			return a.Confidence > b.Confidence
		}
		if len(a.Members) != len(b.Members) {
			return len(a.Members) > len(b.Members)
		}
		return keyOf(a.Entitlements) < keyOf(b.Entitlements)
	})
	if len(cands) > p.MaxCandidates {
		cands = cands[:p.MaxCandidates]
	}
	for i := range cands {
		cands[i].Rank = i + 1
		if cands[i].Rule == nil {
			cands[i].Name = fmt.Sprintf("Mined role %d", i+1)
		} else {
			cands[i].Name = roleName(cands[i].Rule)
		}
	}
	if cands != nil {
		out.Candidates = cands
	}
	return out, nil
}

func roleName(r *Rule) string {
	name := r.Values[0]
	if n := len(r.Values) - 1; n > 0 {
		name += fmt.Sprintf(" (+%d)", n)
	}
	return name + " baseline"
}

// cover returns the indexes of the people holding every entitlement of core,
// starting from the rarest entitlement.
func cover(core []int64, post map[int64][]int) []int {
	lists := make([][]int, len(core))
	for i, e := range core {
		lists[i] = post[e]
	}
	sort.SliceStable(lists, func(i, j int) bool { return len(lists[i]) < len(lists[j]) })
	cur := lists[0]
	for _, l := range lists[1:] {
		next := []int{}
		for i, j := 0, 0; i < len(cur) && j < len(l); {
			switch {
			case cur[i] < l[j]:
				i++
			case cur[i] > l[j]:
				j++
			default:
				next = append(next, cur[i])
				i++
				j++
			}
		}
		cur = next
	}
	return cur
}

func build(core []int64, cov []int, people []Person, rs []Role, p Params) Candidate {
	c := Candidate{Entitlements: core, Members: make([]int64, 0, len(cov)), Outliers: []Outlier{}}
	extraCount := map[int64]int{}
	cohesion := 0
	for _, i := range cov {
		x := people[i]
		c.Members = append(c.Members, x.ID)
		cohesion += 100 * len(core) / len(x.Entitlements)
		for _, e := range x.Entitlements {
			if !slices.Contains(core, e) {
				extraCount[e]++
			}
		}
	}
	c.Cohesion = cohesion / len(cov)
	for _, i := range cov {
		var extra []int64
		for _, e := range people[i].Entitlements {
			if !slices.Contains(core, e) && extraCount[e]*100 < outlierPct*len(cov) {
				extra = append(extra, e)
			}
		}
		if len(extra) > 0 && len(c.Outliers) < MaxOutliers {
			if len(extra) > MaxOutlierExtras {
				extra = extra[:MaxOutlierExtras]
			}
			c.Outliers = append(c.Outliers, Outlier{IdentityID: people[i].ID, Extra: extra})
		}
	}
	var f1 int
	c.Rule, f1 = predictor(cov, people)
	size := min(100, len(cov)*100/(3*p.MinMembers))
	c.Confidence = (f1*40 + c.Cohesion*30 + size*30) / 100
	for _, r := range rs {
		if s := jaccard(core, r.Entitlements); s > c.Similarity {
			c.SimilarRole, c.Similarity = r.ID, s
		}
	}
	return c
}

// predictor finds the attribute whose values best predict coverage and its
// F1 in percent. No rule comes back below minRuleF1.
func predictor(cov []int, people []Person) (*Rule, int) {
	covered := map[int]bool{}
	for _, i := range cov {
		covered[i] = true
	}
	attrs := []struct {
		name string
		get  func(Person) string
	}{
		{"department", func(x Person) string { return x.Department }},
		{"title", func(x Person) string { return x.Title }},
		{"type", func(x Person) string { return x.Type }},
	}
	var best *Rule
	bestF1 := 0
	for _, a := range attrs {
		total, in := map[string]int{}, map[string]int{}
		for i, x := range people {
			v := a.get(x)
			if v == "" {
				continue
			}
			total[v]++
			if covered[i] {
				in[v]++
			}
		}
		vals := make([]string, 0, len(in))
		for v := range in {
			vals = append(vals, v)
		}
		sort.Slice(vals, func(i, j int) bool {
			if in[vals[i]] != in[vals[j]] {
				return in[vals[i]] > in[vals[j]]
			}
			return vals[i] < vals[j]
		})
		var chosen []string
		sel, tp, f1 := 0, 0, 0
		for _, v := range vals {
			ntp, nsel := tp+in[v], sel+total[v]
			if nf := 2 * ntp * 100 / (nsel + len(cov)); nf > f1 {
				chosen, tp, sel, f1 = append(chosen, v), ntp, nsel, nf
			}
		}
		if f1 > bestF1 {
			sort.Strings(chosen)
			best, bestF1 = &Rule{Attribute: a.name, Values: chosen, Precision: tp * 100 / sel, Recall: tp * 100 / len(cov)}, f1
		}
	}
	if bestF1 < minRuleF1 {
		return nil, bestF1
	}
	return best, bestF1
}
