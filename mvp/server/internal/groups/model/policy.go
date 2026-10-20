package model

import (
	"errors"
	"slices"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/naming"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// What internal/groups/policygroups (GR-9, design §8) needs from the folder and
// group service: folder paths, a policy group's definition, and a group whose
// direct members a system job (the attribute indexer) keeps. Each writes its
// events and its audit event in the caller's transaction, like the rest of the
// service.

// Audit writes a domain audit event in the operation's transaction, for the
// policy sync's summary event.
func (e Env) Audit(action, targetType, targetID string, detail ojson.Object) error {
	return e.audit(action, targetType, targetID, detail)
}

// EnsureFolderPath returns the folder with the ':' path name, creating it and
// the folders above it as needed.
func (e Env) EnsureFolderPath(name string) (*store.Folder, error) {
	root, err := e.EnsureRoot()
	if err != nil {
		return nil, err
	}
	if name == "" {
		return root, nil
	}
	cur := root
	for _, ext := range strings.Split(name, naming.Sep) {
		next, err := naming.Join(cur.Name, ext)
		if err != nil {
			return nil, wrap(err)
		}
		f, err := e.Tx.GrpFolderByName(next)
		switch {
		case err == nil:
			cur = f
			continue
		case !errors.Is(err, store.ErrNotFound):
			return nil, err
		}
		if cur, err = e.CreateFolder(CreateFolderInput{Parent: cur.ID, Extension: ext}); err != nil {
			return nil, err
		}
	}
	return cur, nil
}

// PolicyInput is the stored definition of a policy group: its policy_ref JSON,
// its writer and its factors (allow, deny).
type PolicyInput struct {
	Ref       string
	ManagedBy store.ManagedBy
	Factors   []store.GroupID
}

// SetPolicy gives an existing policy group a new definition and recomputes its
// members. The group is changed only if its factors or reference differ.
func (e Env) SetPolicy(id store.GroupID, in PolicyInput) (*store.NativeGroup, Outcome, error) {
	g, err := e.Group(id)
	if err != nil {
		return nil, Outcome{}, err
	}
	if g.Definition != store.DefinitionPolicy {
		return nil, Outcome{}, conflict("not_policy", "group %q is not a policy group", g.Name)
	}
	if g.Status == store.GroupDeleted {
		return nil, Outcome{}, conflict("group_deleted", "the group is deleted; restore it first")
	}
	if err := e.notPolicyManaged(g); err != nil {
		return nil, Outcome{}, err
	}
	if err := e.checkFactors(g.ID, store.CompComplement, in.Factors); err != nil {
		return nil, Outcome{}, err
	}
	if err := engine.Touch(e.Tx, e.Now); err != nil {
		return nil, Outcome{}, err
	}
	old, err := e.Tx.GrpFactors(g.ID)
	if err != nil {
		return nil, Outcome{}, err
	}
	if err := e.Tx.SetGrpGroupPolicy(g.ID, in.ManagedBy, in.Ref); err != nil {
		return nil, Outcome{}, err
	}
	var out Outcome
	if !slices.Equal(old, in.Factors) {
		if err := e.eng().SetFactors(e.Tx, e.Now, g.ID, in.Factors); err != nil {
			return nil, Outcome{}, e.engineErr(err)
		}
	}
	if g, err = e.Group(g.ID); err != nil {
		return nil, Outcome{}, err
	}
	if err := e.emitGroup(events.GroupDefinitionChanged, g, nil); err != nil {
		return nil, Outcome{}, err
	}
	if !slices.Equal(old, in.Factors) {
		if out, err = e.eng().RecomputeGroup(e.Tx, e.Now, g.ID); err != nil {
			return nil, Outcome{}, e.engineErr(err)
		}
		if g, err = e.Group(g.ID); err != nil { // the recompute may have left it pending
			return nil, Outcome{}, err
		}
	}
	return g, out, e.audit("groups.policy.group.updated", "group", string(g.ID), ojson.Object{{Key: "group_id", Value: string(g.ID)},
		{Key: "name", Value: g.Name}, {Key: "factors", Value: groupIDStrings(in.Factors)}, {Key: "queued", Value: out.Queued}})
}

// SyncResult is what SyncSourceMembers changed.
type SyncResult struct {
	Added, Removed int
	Outcome        Outcome
}

// SyncSourceMembers makes the direct identity members of a basic group that
// carry source equal to want: it adds the missing ones, removes the extra ones
// and leaves rows of any other source alone. It is for groups a system job owns
// (the attribute groups of the policy indexer), so it is not privilege-gated and
// it skips the policy-managed guard. Every row change writes its event, the
// engine recomputes the changed identities (queued over the budget) and one
// audit event covers the call.
func (e Env) SyncSourceMembers(id store.GroupID, source string, want []int64) (SyncResult, error) {
	g, err := e.Group(id)
	if err != nil {
		return SyncResult{}, err
	}
	if g.Definition != store.DefinitionBasic || g.Status == store.GroupDeleted {
		return SyncResult{}, conflict("composite_no_members", "group %q takes no direct members", g.Name)
	}
	if err := engine.Touch(e.Tx, e.Now); err != nil {
		return SyncResult{}, err
	}
	list := store.MembersListID(e.Tx.Tenant())
	have := map[int64]*store.DirectMembership{}
	other := map[int64]bool{} // identities with a row of another source
	for off := 0; ; {
		rows, err := e.Tx.GrpDirect(store.GrpDirectFilter{Group: g.ID, List: list, MemberType: store.MemberIdentity, Limit: 1000, Offset: off})
		if err != nil {
			return SyncResult{}, err
		}
		for _, m := range rows {
			if m.Source == source {
				have[*m.MemberIdentity] = m
			} else {
				other[*m.MemberIdentity] = true
			}
		}
		if len(rows) < 1000 {
			break
		}
		off += len(rows)
	}
	wantSet := make(map[int64]bool, len(want))
	var changed []int64
	var res SyncResult
	for _, ident := range want {
		if wantSet[ident] {
			continue
		}
		wantSet[ident] = true
		if have[ident] != nil || other[ident] {
			continue
		}
		ident := ident
		m := &store.DirectMembership{GroupID: g.ID, ListID: list, MemberType: store.MemberIdentity, MemberIdentity: &ident,
			Source: source, CreatedBy: e.By, CreatedAt: e.Now}
		if err := e.Tx.InsertGrpDirect(m); err != nil {
			return SyncResult{}, err
		}
		if err := e.emitDirect(events.MembershipDirectAdded, m); err != nil {
			return SyncResult{}, err
		}
		changed = append(changed, ident)
		res.Added++
	}
	gone := make([]int64, 0)
	for ident := range have {
		if !wantSet[ident] {
			gone = append(gone, ident)
		}
	}
	slices.Sort(gone) // a stable event order
	for _, ident := range gone {
		m := have[ident]
		if err := e.Tx.DeleteGrpDirect(m.ID); err != nil {
			return SyncResult{}, err
		}
		if err := e.emitDirect(events.MembershipDirectRemoved, m); err != nil {
			return SyncResult{}, err
		}
		changed = append(changed, ident)
		res.Removed++
	}
	if len(changed) == 0 {
		return res, nil
	}
	if res.Outcome, err = e.eng().RecomputeSeeds(e.Tx, e.Now, g.ID, list, changed); err != nil {
		return SyncResult{}, e.engineErr(err)
	}
	detail := ojson.Object{{Key: "group_id", Value: string(g.ID)}, {Key: "name", Value: g.Name}, {Key: "source", Value: source},
		{Key: "added", Value: res.Added}, {Key: "removed", Value: res.Removed}, {Key: "queued", Value: res.Outcome.Queued}}
	if res.Outcome.Queued {
		detail = append(detail, ojson.KV{Key: "op", Value: res.Outcome.Op})
	}
	return res, e.audit("groups.members.synced", "group", string(g.ID), detail)
}
