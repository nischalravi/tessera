package model

import (
	"fmt"
	"slices"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/deleteguard"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/attrs"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Purging a soft-deleted group and deleting a folder tree (issue: groups
// cleanup). A soft delete keeps the row so the group can be restored; a purge
// removes the row and everything that points at it, and keeps the history: the
// audit ledger, the event log and the point-in-time tables are append-only.

// Limits of the recursive delete.
const (
	// RecursiveApprovalGroups is the number of groups in a folder tree above which
	// deleting it needs a second admin (it also does when any group has members).
	RecursiveApprovalGroups = 50
	// maxBlockers bounds the list a refusal carries.
	maxBlockers = 50
	maxNamed    = 20
)

// ---------------------------------------------------------------- purge group

// groupBlockers says why a deleted group cannot be purged: another group uses
// it, or configuration and history that a purge leaves alone name it. outside,
// when set, restricts "another group" to groups it does not contain (the
// groups of a folder tree that is being deleted all at once).
func (e Env) groupBlockers(g *store.NativeGroup, inTree map[store.GroupID]bool) (users []string, refs []string, err error) {
	rows, err := e.Tx.GrpGroupUsers(g.ID)
	if err != nil {
		return nil, nil, err
	}
	for _, r := range rows {
		if !inTree[r.ID] {
			users = append(users, r.Name)
		}
	}
	refs, err = e.Tx.GrpGroupRefs(g.ID)
	return users, refs, err
}

func inUse(g *store.NativeGroup, users []string) *Error {
	named := users
	if len(named) > maxNamed {
		named = named[:maxNamed]
	}
	ce := conflict("group_in_use", "group %q is still used by %d group(s) as a member or composite factor: %s; remove it from them first",
		g.Name, len(users), strings.Join(named, ", "))
	ce.Extra = map[string]any{"groups": named, "count": len(users)}
	return ce
}

func referenced(g *store.NativeGroup, refs []string) *Error {
	ce := conflict("group_referenced", "group %q is still named by %s; remove that first", g.Name, strings.Join(refs, " and "))
	ce.Extra = map[string]any{"references": refs}
	return ce
}

// PurgeGroup permanently removes a soft-deleted group: its memberships,
// nesting and composite edges, privileges (on it and held by it), rules,
// attribute assignments and aliases go with it; the audit and event history
// stay. It is refused unless the group is deleted, while another group uses it
// as a member or composite factor (409 group_in_use, naming them) and under
// the checks DeleteGroup makes.
func (e Env) PurgeGroup(id store.GroupID) error { return e.purgeOne(id) }

// purgeOne is the one purge of a group by id (the recursive delete uses purgeGroup, under the same checks).
func (e Env) purgeOne(id store.GroupID) error {
	g, err := e.Group(id)
	if err != nil {
		return err
	}
	if g.Status != store.GroupDeleted {
		return conflict("not_deleted", "only a deleted group can be purged: delete it first")
	}
	if err := e.notPolicyManaged(g); err != nil {
		return err
	}
	f, err := e.Folder(g.FolderID)
	if err != nil {
		return err
	}
	if err := writable(f); err != nil {
		return err
	}
	if held, err := e.guard(deleteguard.CatGroups, groupItem(ItemGroupPurge, g)); held || err != nil {
		return err
	}
	return e.purgeGroup(g, nil)
}

// purgeGroup removes g, whose status, privileges and folder the caller has checked.
func (e Env) purgeGroup(g *store.NativeGroup, inTree map[store.GroupID]bool) error {
	users, refs, err := e.groupBlockers(g, inTree)
	if err != nil {
		return err
	}
	if len(users) > 0 {
		return inUse(g, users)
	}
	if len(refs) > 0 {
		return referenced(g, refs)
	}
	if g.RecomputeState == "pending" {
		return conflict("recompute_pending", "group %q is still being recomputed; try again when the engine has finished", g.Name)
	}
	members, err := e.Tx.GrpDirectCount(store.GrpDirectFilter{Group: g.ID})
	if err != nil {
		return err
	}
	factors := 0
	if g.Definition != store.DefinitionBasic {
		fs, err := e.Tx.GrpFactors(g.ID)
		if err != nil {
			return err
		}
		factors = len(fs)
		if err := e.eng().ClearFactors(e.Tx, e.Now, g.ID); err != nil {
			return e.engineErr(err)
		}
	}
	if err := e.dropDirect(g.ID); err != nil {
		return e.engineErr(err)
	}
	// a deleted group is an empty set; this only makes sure no row is left to block the delete
	if err := e.Tx.DeleteGrpEffectiveOf(g.ID); err != nil {
		return err
	}
	if _, err := attrs.RemoveAllOf(e.Attrs(), attrs.Owner{Type: store.AttrOwnerGroup, ID: string(g.ID)}); err != nil {
		return err
	}
	if _, err := e.Tx.DeleteGrpRulesOf(store.RuleOwnerGroup, string(g.ID)); err != nil {
		return err
	}
	if _, err := privs.RevokeAllOf(e.privs(), privs.GroupObject(g.ID)); err != nil {
		return err
	}
	if _, err := privs.RevokeAllHeldBy(e.privs(), g.ID); err != nil {
		return err
	}
	if _, err := e.Tx.DeleteGrpAttestSettings("group", string(g.ID)); err != nil {
		return err
	}
	if err := e.Tx.DeleteGrpAliasesOf(store.AliasGroup, string(g.ID)); err != nil {
		return err
	}
	if err := e.Tx.DeleteGrpLevel(g.ID); err != nil {
		return err
	}
	if err := e.emitGroupPurged(g); err != nil {
		return err
	}
	if err := e.Tx.DeleteGrpGroup(g.ID); err != nil {
		return wrap(err)
	}
	detail := ojson.Object{{Key: "group_id", Value: string(g.ID)}, {Key: "name", Value: g.Name},
		{Key: "memberships", Value: members}, {Key: "factors", Value: factors}}
	if e.Reason != "" {
		detail = append(detail, ojson.KV{Key: "reason", Value: e.Reason})
	}
	if g.DeletedAt != nil { // who deleted it first, so the trail still says after the row is gone
		detail = append(detail, ojson.KV{Key: "deleted_by", Value: g.DeletedBy}, ojson.KV{Key: "deleted_at", Value: store.RT(*g.DeletedAt)},
			ojson.KV{Key: "deleted_reason", Value: g.DeletedReason})
	}
	if g.DeletedWithFolder != "" {
		detail = append(detail, ojson.KV{Key: "with_folder", Value: g.DeletedWithFolder})
	}
	return e.audit("groups.group.purged", "group", string(g.ID), detail)
}

// ---------------------------------------------------------------- recursive folder delete

// Blocker is one reason a folder tree cannot be deleted.
type Blocker struct {
	// Kind is folder, group or attr_def; ID and Name say which.
	Kind string `json:"kind"`
	ID   string `json:"id"`
	Name string `json:"name"`
	// Code is a stable key (not_ui_managed, policy_managed, used_outside, referenced,
	// recompute_pending, system, no_privilege) and Reason the plain-words reason.
	Code   string `json:"code"`
	Reason string `json:"reason"`
}

// DeletePlan is what deleting a folder and everything in it would remove.
type DeletePlan struct {
	Folder *store.Folder `json:"-"`
	// Subtree is the folder and every folder below it, deepest first.
	Subtree []*store.Folder `json:"-"`
	// Groups, in the order they are purged (a group before the groups it nests).
	Groups            []*store.NativeGroup `json:"-"`
	Folders           int                  `json:"folders"` // the folder and every folder below it: what the delete reports
	ActiveGroups      int                  `json:"active_groups"`
	DeletedGroups     int                  `json:"deleted_groups"`
	AttrDefs          int                  `json:"attr_defs"`
	GroupsWithMembers int                  `json:"groups_with_members"`
	Memberships       int                  `json:"memberships"`
	Blockers          []Blocker            `json:"blockers"`
	// NeedsApproval is true above RecursiveApprovalGroups groups or when any group has members.
	NeedsApproval bool `json:"needs_approval"`
	// ApprovalReason says why, in plain words ("" when none is needed).
	ApprovalReason string `json:"approval_reason,omitempty"`
}

// TotalGroups is every group of the tree, deleted ones included.
func (p *DeletePlan) TotalGroups() int { return p.ActiveGroups + p.DeletedGroups }

// Block adds a blocker (the API adds the folders the caller may not delete).
func (p *DeletePlan) Block(kind, id, name, code, format string, args ...any) {
	if len(p.Blockers) < maxBlockers {
		p.Blockers = append(p.Blockers, Blocker{Kind: kind, ID: id, Name: name, Code: code, Reason: fmt.Sprintf(format, args...)})
	}
}

func folderIn(fs []*store.Folder, id store.FolderID) *store.Folder {
	for _, f := range fs {
		if f.ID == id {
			return f
		}
	}
	return nil
}

func depth(name string) int { return strings.Count(name, ":") }

// PlanFolderDelete reads a folder tree and says what deleting it would remove
// and what stands in the way. It writes nothing. The API adds the privilege
// check on every folder of Subtree.
func (e Env) PlanFolderDelete(id store.FolderID) (*DeletePlan, error) {
	f, err := e.Folder(id)
	if err != nil {
		return nil, err
	}
	if f.ParentID == nil {
		return nil, conflict("root_folder", "the root folder cannot be renamed, moved, copied or deleted")
	}
	below, err := e.Tx.GrpFoldersBelow(f.Name)
	if err != nil {
		return nil, err
	}
	p := &DeletePlan{Folder: f, Folders: len(below) + 1}
	p.Subtree = append(below, f)
	slices.SortStableFunc(p.Subtree, func(a, b *store.Folder) int { return depth(b.Name) - depth(a.Name) })
	folders := map[store.FolderID]bool{}
	for _, sf := range p.Subtree {
		folders[sf.ID] = true
		if sf.ManagedBy != store.ManagedByUI {
			p.Block("folder", string(sf.ID), sf.Name, "not_ui_managed", "folder %q is managed by %s, not in the UI", sf.Name, sf.ManagedBy)
		}
	}
	// a loader's target folder is a foreign key: it must go (or move) first
	loaders, err := e.Tx.GrpLoaders()
	if err != nil {
		return nil, err
	}
	for _, l := range loaders {
		if sf := folderIn(p.Subtree, l.TargetFolder); sf != nil {
			p.Block("folder", string(sf.ID), sf.Name, "referenced", "folder %q is the target of the loader %q; delete the loader or point it elsewhere first", sf.Name, l.Name)
		}
	}
	groups, err := e.Tx.GrpGroupsBelow(f.Name)
	if err != nil {
		return nil, err
	}
	tree := map[store.GroupID]bool{}
	level := map[store.GroupID]int{}
	for _, g := range groups {
		tree[g.ID] = true
		if level[g.ID], err = e.Tx.GrpLevel(g.ID); err != nil {
			return nil, err
		}
	}
	// a group before the groups it nests, so each purge finds its users already gone
	slices.SortStableFunc(groups, func(a, b *store.NativeGroup) int { return level[b.ID] - level[a.ID] })
	p.Groups = groups
	for _, g := range groups {
		if !folders[g.FolderID] {
			p.Block("group", string(g.ID), g.Name, "outside", "group %q is not in the folder tree", g.Name)
			continue
		}
		if g.Status == store.GroupDeleted {
			p.DeletedGroups++
		} else {
			p.ActiveGroups++
		}
		n, err := e.Tx.GrpDirectCount(store.GrpDirectFilter{Group: g.ID})
		if err != nil {
			return nil, err
		}
		p.Memberships += n
		if n > 0 {
			p.GroupsWithMembers++
		}
		switch {
		case g.ManagedBy == store.ManagedByPolicyRepo:
			p.Block("group", string(g.ID), g.Name, "policy_managed", "group %q is managed by the policy repository", g.Name)
		case g.ManagedBy != store.ManagedByUI:
			p.Block("group", string(g.ID), g.Name, "not_ui_managed", "group %q is managed by %s, not in the UI", g.Name, g.ManagedBy)
		}
		if g.RecomputeState == "pending" {
			p.Block("group", string(g.ID), g.Name, "recompute_pending", "group %q is still being recomputed", g.Name)
		}
		users, refs, err := e.groupBlockers(g, tree)
		if err != nil {
			return nil, err
		}
		if len(users) > 0 {
			named := users
			if len(named) > 3 {
				named = named[:3]
			}
			p.Block("group", string(g.ID), g.Name, "used_outside", "group %q is used by %d group(s) outside the folder: %s",
				g.Name, len(users), strings.Join(named, ", "))
		}
		if len(refs) > 0 {
			p.Block("group", string(g.ID), g.Name, "referenced", "group %q is named by %s", g.Name, strings.Join(refs, " and "))
		}
	}
	defs, err := e.Tx.GrpAttrDefs(store.GrpAttrDefFilter{Prefix: f.Name, Limit: 5000})
	if err != nil {
		return nil, err
	}
	p.AttrDefs = len(defs)
	for _, d := range defs {
		if d.System {
			p.Block("attr_def", d.ID, d.Name(), "system", "the built-in attribute definition %q cannot be deleted", d.Name())
			continue
		}
		if err := e.defOutsideUse(p, d, folders, tree); err != nil {
			return nil, err
		}
	}
	switch {
	case p.TotalGroups() > RecursiveApprovalGroups:
		p.NeedsApproval = true
		p.ApprovalReason = fmt.Sprintf("the folder holds %d groups, more than %d", p.TotalGroups(), RecursiveApprovalGroups)
	case p.GroupsWithMembers > 0:
		p.NeedsApproval = true
		p.ApprovalReason = fmt.Sprintf("%d group(s) in the folder have members (%d memberships)", p.GroupsWithMembers, p.Memberships)
	}
	return p, nil
}

// defOutsideUse blocks the plan when an attribute definition of the tree is
// assigned to something that is not deleted with it.
func (e Env) defOutsideUse(p *DeletePlan, d *store.GrpAttrDef, folders map[store.FolderID]bool, groups map[store.GroupID]bool) error {
	for off := 0; ; {
		rows, err := e.Tx.GrpAttrAssigns(store.GrpAttrAssignFilter{DefID: d.ID, Limit: 500, Offset: off})
		if err != nil {
			return err
		}
		for _, a := range rows {
			inside := false
			switch a.OwnerType {
			case store.AttrOwnerFolder:
				inside = folders[store.FolderID(a.OwnerID)]
			case store.AttrOwnerGroup:
				inside = groups[store.GroupID(a.OwnerID)]
			case store.AttrOwnerMembership:
				if m, err := e.Tx.GrpDirectMembership(a.OwnerID); err == nil {
					inside = groups[m.GroupID]
				}
			}
			if !inside {
				p.Block("attr_def", d.ID, d.Name(), "used_outside", "attribute definition %q is assigned to something outside the folder", d.Name())
				return nil
			}
		}
		if len(rows) < 500 {
			return nil
		}
		off += len(rows)
	}
}

// BlockedError is the refusal of a folder tree that cannot be deleted.
func (p *DeletePlan) BlockedError() *Error {
	named := make([]string, 0, 3)
	for _, b := range p.Blockers {
		if len(named) < 3 {
			named = append(named, b.Reason)
		}
	}
	ce := conflict("recursive_delete_blocked", "folder %q cannot be deleted with everything in it: %s", p.Folder.Name, strings.Join(named, "; "))
	ce.Extra = map[string]any{"blockers": p.Blockers, "blocker_count": len(p.Blockers)}
	return ce
}

// DeleteResult is what a recursive delete removed.
type DeleteResult struct {
	Folders     int `json:"folders"`
	Groups      int `json:"groups"`
	AttrDefs    int `json:"attr_defs"`
	Memberships int `json:"memberships"`
	SoftDeleted int `json:"soft_deleted"`
	// Held counts the groups and folders the deletion guard held (internal/deleteguard).
	Held int `json:"held"`
}

// treeRef is the item ref of the i-th group of a recursive delete: it sorts in plan order.
func treeRef(i int, id store.GroupID) string { return fmt.Sprintf("%06d|%s", i, id) }

// DeleteFolderRecursive deletes a folder and its whole tree in the caller's
// transaction: groups are soft-deleted then purged (a group before the groups it
// nests), attribute definitions removed, then the folders deepest first. It
// refuses (409 recursive_delete_blocked, with the blockers) unless every item is
// UI-managed and writable, no group is policy-managed or used from outside the
// tree and nothing outside names an attribute definition of it. The caller has
// checked stem_admin on every folder of the plan and, when the plan needs
// approval, that a second admin gave it.
func (e Env) DeleteFolderRecursive(id store.FolderID) (*DeletePlan, *DeleteResult, error) {
	p, err := e.PlanFolderDelete(id)
	if err != nil {
		return nil, nil, err
	}
	if len(p.Blockers) > 0 {
		return p, nil, p.BlockedError()
	}
	for _, sf := range p.Subtree {
		if err := writable(sf); err != nil {
			return p, nil, err
		}
	}
	tree := make(map[store.GroupID]bool, len(p.Groups))
	for _, g := range p.Groups {
		tree[g.ID] = true
	}
	res := &DeleteResult{Memberships: p.Memberships}
	// the groups go through the deletion guard as one batch; the ref keeps the plan's order (a
	// group before the groups it nests), so what is let through is a prefix of it
	items := make([]deleteguard.Item, len(p.Groups))
	for i, g := range p.Groups {
		items[i] = deleteguard.Item{Kind: ItemGroupTree, Ref: treeRef(i, g.ID), Label: g.Name}
	}
	d, err := e.admit(deleteguard.CatGroups, items...)
	if err != nil {
		return p, nil, err
	}
	allowed := make(map[string]bool, len(d.Applied))
	for _, it := range d.Applied {
		allowed[it.Ref] = true
	}
	res.Held = len(d.Held)
	for i, g := range p.Groups {
		if !allowed[treeRef(i, g.ID)] {
			continue
		}
		if g.Status != store.GroupDeleted {
			if err := e.softDelete(g, p.Folder.Name); err != nil {
				return p, nil, err
			}
			res.SoftDeleted++
			if g, err = e.Group(g.ID); err != nil {
				return p, nil, err
			}
		}
		if err := e.purgeGroup(g, tree); err != nil {
			return p, nil, err
		}
		res.Groups++
	}
	if res.Held > 0 {
		// the tree stays (its folders and attribute definitions hold what was not deleted)
		return p, res, e.audit("groups.folder.deleted_recursive", "folder", string(p.Folder.ID), ojson.Object{
			{Key: "folder_id", Value: string(p.Folder.ID)}, {Key: "name", Value: p.Folder.Name}, {Key: "folders", Value: 0},
			{Key: "groups", Value: res.Groups}, {Key: "groups_held", Value: res.Held}, {Key: "hold_id", Value: d.HoldID},
			{Key: "memberships", Value: p.Memberships}})
	}
	defs, err := e.Tx.GrpAttrDefs(store.GrpAttrDefFilter{Prefix: p.Folder.Name, Limit: 5000})
	if err != nil {
		return p, nil, err
	}
	for _, d := range defs {
		if err := attrs.DeleteDef(e.Attrs(), d.ID); err != nil {
			return p, nil, err
		}
		res.AttrDefs++
	}
	fitems := make([]deleteguard.Item, len(p.Subtree))
	byRef := make(map[string]*store.Folder, len(p.Subtree))
	for i, sf := range p.Subtree {
		fitems[i] = folderItem(sf)
		byRef[fitems[i].Ref] = sf
	}
	fd, err := e.admit(deleteguard.CatFolders, fitems...)
	if err != nil {
		return p, nil, err
	}
	for _, it := range fd.Applied { // deepest first: the item ref sorts that way
		if err := e.removeFolder(byRef[it.Ref]); err != nil {
			return p, nil, err
		}
		res.Folders++
	}
	res.Held += len(fd.Held)
	err = e.audit("groups.folder.deleted_recursive", "folder", string(p.Folder.ID), ojson.Object{
		{Key: "folder_id", Value: string(p.Folder.ID)}, {Key: "name", Value: p.Folder.Name}, {Key: "folders", Value: res.Folders},
		{Key: "groups", Value: res.Groups}, {Key: "groups_active", Value: p.ActiveGroups}, {Key: "groups_deleted", Value: p.DeletedGroups},
		{Key: "attr_defs", Value: res.AttrDefs}, {Key: "memberships", Value: res.Memberships}, {Key: "reason", Value: e.Reason}})
	return p, res, err
}
