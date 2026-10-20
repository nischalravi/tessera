package loaders

import (
	"errors"
	"slices"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/naming"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// GroupPlan is what a run does to one group. Add and Remove are identity ids,
// sorted; Size is how many members the group has after the run (of the
// subjects the source named that resolved), Current how many loader members it
// has now.
type GroupPlan struct {
	Name        string `json:"name"`
	Extension   string `json:"extension"`
	DisplayName string `json:"display_name,omitempty"`
	Description string `json:"description,omitempty"`
	GroupID     string `json:"group_id,omitempty"`
	Create      bool   `json:"create,omitempty"`
	Restore     bool   `json:"restore,omitempty"`
	// Enable: the group is disabled (by the loader, when the source stopped
	// returning it) and the source returns it again.
	Enable  bool    `json:"enable,omitempty"`
	Add     []int64 `json:"add,omitempty"`
	Remove  []int64 `json:"remove,omitempty"`
	Size    int     `json:"size"`
	Current int     `json:"current"`
	// Missing: the source no longer returns the group; Action is what the
	// loader does with it (empty, disable or delete).
	Missing bool   `json:"missing,omitempty"`
	Action  string `json:"action,omitempty"`
}

// PlanUnresolved is a subject no identity matches, and the groups that named it.
type PlanUnresolved struct {
	Source     string   `json:"source"`
	Identifier string   `json:"identifier"`
	Groups     []string `json:"groups"`
}

// Plan is what a run computed. A held run keeps it, and an approval applies it
// as it is.
type Plan struct {
	Kind        string           `json:"kind"`
	Groups      []GroupPlan      `json:"groups"`
	Unresolved  []PlanUnresolved `json:"unresolved,omitempty"`
	Counts      Counts           `json:"counts"`
	CursorAfter *string          `json:"cursor_after,omitempty"`
}

// Adds is the number of memberships the plan adds.
func (p *Plan) Adds() int {
	n := 0
	for i := range p.Groups {
		n += len(p.Groups[i].Add)
	}
	return n
}

// Removes is the number of memberships the plan removes.
func (p *Plan) Removes() int {
	n := 0
	for i := range p.Groups {
		n += len(p.Groups[i].Remove)
	}
	return n
}

// EmptiedGroups counts the groups the plan leaves empty that have members now,
// and the missing groups it disables or deletes.
func (p *Plan) EmptiedGroups() int {
	n := 0
	for i := range p.Groups {
		g := &p.Groups[i]
		switch {
		case g.Missing && (g.Action == "disable" || g.Action == "delete"):
			n++
		case g.Current > 0 && g.Size == 0:
			n++
		}
	}
	return n
}

// Empty reports whether the plan changes nothing.
func (p *Plan) Empty() bool {
	for i := range p.Groups {
		g := &p.Groups[i]
		if g.Create || g.Restore || g.Enable || len(g.Add) > 0 || len(g.Remove) > 0 || (g.Missing && g.Action != "empty") {
			return false
		}
	}
	return true
}

// planner holds what building a plan needs.
type planner struct {
	tx       *store.TenantTx
	l        *store.GrpLoader
	folder   *store.Folder
	list     store.ListID
	res      *Resolver
	andSet   map[int64]bool
	existing map[string]*store.NativeGroup // lower-case extension
	unres    map[[2]string]map[string]bool
	counts   Counts
}

func newPlanner(tx *store.TenantTx, l *store.GrpLoader) (*planner, error) {
	folder, err := tx.GrpFolder(l.TargetFolder)
	if errors.Is(err, store.ErrNotFound) {
		return nil, conflict("target_folder_missing", "the loader's target folder no longer exists")
	}
	if err != nil {
		return nil, err
	}
	res, err := NewResolver(tx)
	if err != nil {
		return nil, err
	}
	p := &planner{tx: tx, l: l, folder: folder, list: store.MembersListID(tx.Tenant()), res: res,
		existing: map[string]*store.NativeGroup{}, unres: map[[2]string]map[string]bool{}}
	groups, err := tx.GrpGroupsOfLoader(l.ID)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		p.existing[strings.ToLower(g.Extension)] = g
		if g.Status != store.GroupDeleted {
			p.counts.LoaderGroups++
		}
	}
	if l.AndGroup != nil {
		ag, err := tx.GrpGroup(*l.AndGroup)
		if errors.Is(err, store.ErrNotFound) || (err == nil && ag.Status == store.GroupDeleted) {
			return nil, conflict("and_group_missing", "the group the loader intersects with no longer exists")
		}
		if err != nil {
			return nil, err
		}
		p.andSet = map[int64]bool{}
		for after := int64(0); ; {
			ids, err := tx.GrpEffectiveIdentitiesAfter(ag.ID, p.list, after, 1000)
			if err != nil {
				return nil, err
			}
			for _, id := range ids {
				p.andSet[id] = true
			}
			if len(ids) < 1000 {
				break
			}
			after = ids[len(ids)-1]
		}
	}
	return p, nil
}

// current is the identities a group has from this loader.
func (p *planner) current(g *store.NativeGroup) (map[int64]bool, error) {
	rows, err := p.tx.GrpDirectBySource(g.ID, p.list, "loader", p.l.ID)
	if err != nil {
		return nil, err
	}
	out := map[int64]bool{}
	for _, m := range rows {
		if m.MemberType == store.MemberIdentity && m.MemberIdentity != nil {
			out[*m.MemberIdentity] = true
		}
	}
	return out, nil
}

// extension maps a source's group name to the extension of the native group.
func (p *planner) extension(name string) (string, error) {
	ext := ApplyTemplate(p.l.NameTemplate, name)
	if err := naming.ValidateExtension(ext); err != nil {
		return "", invalid("invalid_group_name", "the source names a group %q that is not a valid group name here: %v", name, err)
	}
	return ext, nil
}

// target finds the group a source group maps to, or says it must be created.
// A group that exists but is not this loader's is a conflict: a loader never
// takes over a group by name.
func (p *planner) target(ext string) (*GroupPlan, *store.NativeGroup, error) {
	name, err := naming.Join(p.folder.Name, ext)
	if err != nil {
		return nil, nil, invalid("invalid_group_name", "%v", err)
	}
	gp := &GroupPlan{Name: name, Extension: ext}
	if g := p.existing[strings.ToLower(ext)]; g != nil {
		gp.GroupID, gp.Restore, gp.Enable, gp.Name = string(g.ID), g.Status == store.GroupDeleted, g.Status == store.GroupDisabled, g.Name
		return gp, g, nil
	}
	if _, err := p.tx.GrpGroupByName(name); err == nil {
		return nil, nil, conflict("loader_name_taken", "the source names a group %q, but a group of that name exists and is not this loader's", name)
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, nil, err
	}
	if _, err := p.tx.GrpFolderByName(name); err == nil {
		return nil, nil, conflict("loader_name_taken", "the source names a group %q, but a folder of that name exists", name)
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, nil, err
	}
	if _, err := p.tx.GrpAliasByName(name); err == nil {
		return nil, nil, conflict("loader_name_taken", "the source names a group %q, but that name is reserved by a renamed group", name)
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, nil, err
	}
	gp.Create = true
	return gp, nil, nil
}

// resolve resolves refs, recording the unresolved ones against the group name.
func (p *planner) resolve(group string, refs []SubjectRef) map[int64]bool {
	out := map[int64]bool{}
	seen := map[SubjectRef]bool{}
	for _, ref := range refs {
		if seen[ref] {
			continue
		}
		seen[ref] = true
		p.counts.SourceRefs++
		id, ok := p.res.Resolve(ref)
		if !ok {
			p.counts.UnresolvedRefs++
			k := [2]string{ref.Source, ref.Identifier}
			if p.unres[k] == nil {
				p.unres[k] = map[string]bool{}
			}
			p.unres[k][group] = true
			continue
		}
		if p.andSet != nil && !p.andSet[id] {
			continue
		}
		out[id] = true
	}
	return out
}

func sortedIDs(m map[int64]bool) []int64 {
	out := make([]int64, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

func (p *planner) unresolved() []PlanUnresolved {
	out := make([]PlanUnresolved, 0, len(p.unres))
	for k, gs := range p.unres {
		u := PlanUnresolved{Source: k[0], Identifier: k[1]}
		for g := range gs {
			u.Groups = append(u.Groups, g)
		}
		sort.Strings(u.Groups)
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return out[i].Identifier < out[j].Identifier
	})
	return out
}

// BuildFull computes what a full run does: every group the source returned is
// made to hold exactly its resolved subjects (as loader members), new groups
// are created, and the loader's groups the source no longer returns get the
// loader's on_missing_group treatment.
func BuildFull(tx *store.TenantTx, l *store.GrpLoader, loaded []LoadedGroup) (*Plan, error) {
	p, err := newPlanner(tx, l)
	if err != nil {
		return nil, err
	}
	plan := &Plan{Kind: store.RunFull}
	returned := map[string]bool{}
	for _, lg := range loaded {
		ext, err := p.extension(lg.Name)
		if err != nil {
			return nil, err
		}
		if returned[strings.ToLower(ext)] {
			return nil, invalid("duplicate_group", "the source lists the group %q twice", lg.Name)
		}
		returned[strings.ToLower(ext)] = true
		gp, g, err := p.target(ext)
		if err != nil {
			return nil, err
		}
		// the source's text is for display: text the model would refuse is left out, not a reason to stop
		if naming.ValidateDisplay(lg.DisplayName) == nil {
			gp.DisplayName = lg.DisplayName
		}
		if len(lg.Description) <= model.MaxDescription {
			gp.Description = lg.Description
		}
		desired := p.resolve(gp.Name, lg.Members)
		cur := map[int64]bool{}
		if g != nil {
			if cur, err = p.current(g); err != nil {
				return nil, err
			}
		}
		for id := range desired {
			if !cur[id] {
				gp.Add = append(gp.Add, id)
			}
		}
		for id := range cur {
			if !desired[id] {
				gp.Remove = append(gp.Remove, id)
			}
		}
		slices.Sort(gp.Add)
		slices.Sort(gp.Remove)
		gp.Size, gp.Current = len(desired), len(cur)
		plan.Groups = append(plan.Groups, *gp)
	}
	var missing []*store.NativeGroup
	for ext, g := range p.existing {
		if !returned[ext] && g.Status != store.GroupDeleted {
			missing = append(missing, g)
		}
	}
	sort.Slice(missing, func(i, j int) bool { return missing[i].Name < missing[j].Name })
	for _, g := range missing {
		action := l.OnMissingGroup
		if action == "keep" {
			continue
		}
		cur, err := p.current(g)
		if err != nil {
			return nil, err
		}
		if (action == "empty" && len(cur) == 0) || (action == "disable" && len(cur) == 0 && g.Status == store.GroupDisabled) {
			continue
		}
		plan.Groups = append(plan.Groups, GroupPlan{Name: g.Name, Extension: g.Extension, GroupID: string(g.ID),
			Remove: sortedIDs(cur), Current: len(cur), Missing: true, Action: action})
	}
	plan.Unresolved = p.unresolved()
	plan.Counts = p.counts
	return plan, nil
}

// BuildIncremental computes what the changes of an incremental feed do: only
// the groups they name are touched, and the last change of a subject in a group
// wins. A subject that does not resolve is unresolved, as in a full run.
func BuildIncremental(tx *store.TenantTx, l *store.GrpLoader, changes []GroupChange) (*Plan, error) {
	p, err := newPlanner(tx, l)
	if err != nil {
		return nil, err
	}
	plan := &Plan{Kind: store.RunIncremental}
	type key struct {
		ext string
		ref SubjectRef
	}
	last := map[key]bool{} // true: remove
	var order []key
	byExt := map[string]string{} // lower ext -> ext
	for _, c := range changes {
		ext, err := p.extension(c.Group)
		if err != nil {
			return nil, err
		}
		byExt[strings.ToLower(ext)] = ext
		k := key{strings.ToLower(ext), c.Subject}
		if _, seen := last[k]; !seen {
			order = append(order, k)
		}
		last[k] = c.Remove
	}
	type pending struct{ add, remove map[int64]bool }
	groups := map[string]*pending{}
	for _, k := range order {
		ext := byExt[k.ext]
		gp, _, err := p.target(ext)
		if err != nil {
			return nil, err
		}
		pd := groups[k.ext]
		if pd == nil {
			pd = &pending{add: map[int64]bool{}, remove: map[int64]bool{}}
			groups[k.ext] = pd
		}
		ids := p.resolve(gp.Name, []SubjectRef{k.ref})
		if len(ids) == 0 {
			continue // unresolved, or filtered out by the AND group
		}
		for id := range ids {
			if last[k] {
				pd.remove[id] = true
			} else {
				pd.add[id] = true
			}
		}
	}
	exts := make([]string, 0, len(groups))
	for e := range groups {
		exts = append(exts, e)
	}
	sort.Strings(exts)
	for _, e := range exts {
		pd := groups[e]
		gp, g, err := p.target(byExt[e])
		if err != nil {
			return nil, err
		}
		cur := map[int64]bool{}
		if g != nil {
			if cur, err = p.current(g); err != nil {
				return nil, err
			}
		}
		for id := range pd.add {
			if !cur[id] {
				gp.Add = append(gp.Add, id)
			}
		}
		for id := range pd.remove {
			if cur[id] {
				gp.Remove = append(gp.Remove, id)
			}
		}
		if g == nil && len(gp.Add) == 0 {
			continue // nothing resolved: no group is made for it
		}
		gp.Enable = gp.Enable && len(gp.Add) > 0 // only an add brings a disabled group back
		slices.Sort(gp.Add)
		slices.Sort(gp.Remove)
		gp.Current = len(cur)
		gp.Size = len(cur) + len(gp.Add) - len(gp.Remove)
		plan.Groups = append(plan.Groups, *gp)
	}
	plan.Unresolved = p.unresolved()
	plan.Counts = p.counts
	return plan, nil
}
