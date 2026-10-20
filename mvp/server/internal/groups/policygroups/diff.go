package policygroups

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Simulation (design §8.5 step 2): compile a change and say who would join and
// leave each policy group, against the live effective memberships, without
// writing anything. It evaluates the policy with the evaluator of eval.go, which
// TestPolicyGroups_PDPAgreesWithEngine holds equal to what the engine will
// materialize, so the answer is what the merge will do (up to changes made
// between the simulation and the merge).

// SampleSize is how many identity ids a diff lists per side of a group.
const SampleSize = 50

// GroupDiff is the effect of a change on one policy group.
type GroupDiff struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Status  string `json:"status"` // new, changed, unchanged or removed
	Current int    `json:"current"`
	// Proposed is the member count after the change.
	Proposed      int     `json:"proposed"`
	Added         int     `json:"added"`
	Removed       int     `json:"removed"`
	AddedSample   []int64 `json:"added_sample"`
	RemovedSample []int64 `json:"removed_sample"`
}

// DiffResult is the simulation of a change.
type DiffResult struct {
	Groups []GroupDiff `json:"groups"`
	// Identities is how many identities were evaluated.
	Identities int `json:"identities"`
}

// Diff simulates applying files (as the whole repository when full).
func (a *Applier) Diff(files []SourceFile, full bool) (*DiffResult, error) {
	env := a.Env
	tx := env.Tx
	v, fs, err := Validate(env, a.Schema, files)
	if err != nil {
		return nil, err
	}
	if !v.Valid {
		return nil, &ValidationError{Diags: v.Diagnostics}
	}
	byName := map[string]*File{}
	for _, f := range fs {
		byName[strings.ToLower(f.Group)] = f
	}
	idents, err := tx.Identities()
	if err != nil {
		return nil, err
	}
	src := a.Attrs
	if src == nil {
		src = IdentityAttrs{}
	}
	members := store.MembersListID(tx.Tenant())
	resolve := resolver(tx, byName2set(byName))

	// the current members of every group the change refers to or replaces
	sets := map[string]map[int64]bool{} // group id -> members
	load := func(id store.GroupID) (map[int64]bool, error) {
		if s, ok := sets[string(id)]; ok {
			return s, nil
		}
		s := map[int64]bool{}
		for after := int64(-1 << 62); ; {
			ids, err := tx.GrpEffectiveIdentitiesAfter(id, members, after, 5000)
			if err != nil {
				return nil, err
			}
			for _, i := range ids {
				s[i] = true
			}
			if len(ids) < 5000 {
				break
			}
			after = ids[len(ids)-1]
		}
		sets[string(id)] = s
		return s, nil
	}
	refSet := map[string]map[int64]bool{} // lower-cased name -> members, for a group outside the change
	refOf := func(name string) (map[int64]bool, error) {
		k := strings.ToLower(name)
		if s, ok := refSet[k]; ok {
			return s, nil
		}
		id, err := resolve(name)
		if err != nil {
			return nil, err
		}
		s, err := load(store.GroupID(id))
		if err != nil {
			return nil, err
		}
		refSet[k] = s
		return s, nil
	}

	proposed := map[string]map[int64]bool{} // lower-cased group name -> members after the change
	for k := range byName {
		proposed[k] = map[int64]bool{}
	}
	for _, id := range idents {
		memo := map[string]bool{}
		busy := map[string]bool{}
		var decide func(k string) (bool, error)
		sub := identitySubject{id: id, src: src, schema: a.Schema}
		sub.inGroup = func(name string) (bool, error) {
			k := strings.ToLower(name)
			if _, in := byName[k]; in {
				return decide(k)
			}
			s, err := refOf(name)
			return s[id.ID], err
		}
		decide = func(k string) (bool, error) {
			if v, ok := memo[k]; ok {
				return v, nil
			}
			if busy[k] {
				return false, fmt.Errorf("policy groups refer to each other in a cycle at %q", k)
			}
			busy[k] = true
			v, err := byName[k].Decide(sub)
			delete(busy, k)
			memo[k] = v
			return v, err
		}
		for k := range byName {
			ok, err := decide(k)
			if err != nil {
				return nil, &ValidationError{Diags: []Diagnostic{{Code: CodeReferenceCycle, Msg: err.Error()}}}
			}
			if ok {
				proposed[k][id.ID] = true
			}
		}
	}

	out := &DiffResult{Identities: len(idents)}
	for _, f := range fs {
		k := strings.ToLower(f.Group)
		d := GroupDiff{Name: f.Group, Path: f.Path, Status: "new"}
		cur := map[int64]bool{}
		g, err := tx.GrpGroupByName(f.Group)
		switch {
		case err == nil && g.Status != store.GroupDeleted:
			d.Status = "changed"
			if cur, err = load(g.ID); err != nil {
				return nil, err
			}
		case err != nil && !errors.Is(err, store.ErrNotFound):
			return nil, err
		}
		fill(&d, cur, proposed[k])
		if d.Status == "changed" && d.Added == 0 && d.Removed == 0 {
			d.Status = "unchanged"
		}
		out.Groups = append(out.Groups, d)
	}
	if full {
		sources, err := tx.GrpPolicySources(store.PolicyOriginRepo)
		if err != nil {
			return nil, err
		}
		for _, s := range sources {
			g, err := tx.GrpGroup(s.GroupID)
			if err != nil {
				return nil, err
			}
			if _, in := byName[strings.ToLower(g.Name)]; in || g.Status == store.GroupDeleted {
				continue
			}
			cur, err := load(g.ID)
			if err != nil {
				return nil, err
			}
			d := GroupDiff{Name: g.Name, Path: s.Path, Status: "removed"}
			fill(&d, cur, map[int64]bool{})
			out.Groups = append(out.Groups, d)
		}
	}
	slices.SortFunc(out.Groups, func(x, y GroupDiff) int { return strings.Compare(strings.ToLower(x.Name), strings.ToLower(y.Name)) })
	return out, nil
}

func byName2set(m map[string]*File) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

// fill counts and samples the identities that join and leave.
func fill(d *GroupDiff, cur, next map[int64]bool) {
	d.Current, d.Proposed = len(cur), len(next)
	d.AddedSample, d.RemovedSample = []int64{}, []int64{}
	var added, removed []int64
	for i := range next {
		if !cur[i] {
			added = append(added, i)
		}
	}
	for i := range cur {
		if !next[i] {
			removed = append(removed, i)
		}
	}
	slices.Sort(added)
	slices.Sort(removed)
	d.Added, d.Removed = len(added), len(removed)
	d.AddedSample = append(d.AddedSample, added[:min(len(added), SampleSize)]...)
	d.RemovedSample = append(d.RemovedSample, removed[:min(len(removed), SampleSize)]...)
}
