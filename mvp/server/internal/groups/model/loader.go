package model

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/naming"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// What a loader (issue #53, GR-10; internal/groups/loaders) does to groups. A
// loader creates its own groups (managed_by 'loader') and is their only writer:
// the members routes refuse them (writableGroup). Every change here writes its
// events, with the cause "loader", in the caller's transaction; the audit event
// of the run is the loader's (one per run, not one per membership).

// NewError makes a refusal that the API maps to 404, 409 or 422 like the
// model's own.
func NewError(kind Kind, code, format string, args ...any) *Error {
	return &Error{Kind: kind, Code: code, Msg: fmt.Sprintf(format, args...)}
}

// loaderManaged is the refusal of a hand edit of what a loader owns.
func loaderManaged(g *store.NativeGroup) error {
	return conflict("group_loader_managed", "group %q is owned by a loader and changes through its source: change the source, or add an exception through the matching _allow_manual or _deny_manual group", g.Name)
}

// LoaderGroupInput names a group a loader creates in its target folder.
type LoaderGroupInput struct {
	Folder      store.FolderID
	Extension   string
	DisplayName string
	Description string
	LoaderID    string
}

// CreateLoaderGroup creates a basic group owned by a loader. The creator gets
// no privileges (nobody created it by hand; the folder's inherited privileges
// apply), the tenant's default grants do.
func (e Env) CreateLoaderGroup(in LoaderGroupInput) (*store.NativeGroup, error) {
	folder, err := e.Folder(in.Folder)
	if err != nil {
		return nil, err
	}
	if err := writable(folder); err != nil {
		return nil, err
	}
	name, err := naming.Join(folder.Name, in.Extension)
	if err != nil {
		return nil, wrap(err)
	}
	disp := in.DisplayName
	if disp == "" {
		disp = in.Extension
	}
	if err := errors.Join(wrap(naming.ValidateDisplay(disp)), checkText("description", in.Description, MaxDescription)); err != nil {
		return nil, firstErr(err)
	}
	if err := e.available(name, ""); err != nil {
		return nil, err
	}
	loader := in.LoaderID
	g := &store.NativeGroup{FolderID: folder.ID, Extension: in.Extension, DisplayExtension: disp, Name: name,
		DisplayName: displayName(folder.DisplayName, disp), Description: in.Description, Kind: store.KindGroup,
		Definition: store.DefinitionBasic, ManagedBy: store.ManagedByLoader, LoaderID: &loader, Status: store.GroupActive,
		CreatedAt: e.Now, CreatedBy: e.By}
	if err := e.Tx.InsertGrpGroup(g); err != nil {
		return nil, err
	}
	if err := e.emitGroup(events.GroupCreated, g, nil); err != nil {
		return nil, err
	}
	if err := privs.GrantDefaults(e.privs(), privs.GroupObject(g.ID)); err != nil {
		return nil, err
	}
	return g, e.audit("groups.group.created", "group", string(g.ID), ojson.Object{{Key: "group_id", Value: string(g.ID)},
		{Key: "name", Value: g.Name}, {Key: "folder_id", Value: string(folder.ID)}, {Key: "kind", Value: string(g.Kind)},
		{Key: "definition", Value: string(g.Definition)}, {Key: "loader_id", Value: loader}})
}

// SyncResult is what LoaderSync did.
type SyncResult struct {
	Added, Removed int
	// Skipped counts adds of an identity that no longer exists.
	Skipped int
	Outcome Outcome
}

// LoaderSync adds and removes direct identity members of a loader's group:
// the rows it writes carry source "loader" and the loader id as source_ref,
// and it removes only such rows (it never touches another source's). An add of
// someone already a member, and a remove of someone who is not a loader member,
// change nothing. The engine recomputes all the changed identities at once.
func (e Env) LoaderSync(g *store.NativeGroup, loaderID string, add, remove []int64) (SyncResult, error) {
	var res SyncResult
	if g.LoaderID == nil || *g.LoaderID != loaderID || g.ManagedBy != store.ManagedByLoader {
		return res, conflict("not_loader_group", "group %q is not owned by this loader", g.Name)
	}
	if g.Definition != store.DefinitionBasic {
		return res, conflict("composite_no_members", "group %q is a composite: its members come from its factors", g.Name)
	}
	list := store.MembersListID(e.Tx.Tenant())
	seen := map[int64]bool{}
	var seeds []int64
	ref := loaderID
	for _, id := range add {
		if seen[id] {
			continue
		}
		seen[id] = true
		if _, err := e.Tx.Identity(id); errors.Is(err, store.ErrNotFound) {
			res.Skipped++
			continue
		} else if err != nil {
			return res, err
		}
		_, err := e.Tx.GrpDirectFind(g.ID, list, store.MemberIdentity, strconv.FormatInt(id, 10))
		if err == nil {
			continue // already a member, by whatever source
		}
		if !errors.Is(err, store.ErrNotFound) {
			return res, err
		}
		ident := id
		m := &store.DirectMembership{GroupID: g.ID, ListID: list, MemberType: store.MemberIdentity, MemberIdentity: &ident,
			Source: "loader", SourceRef: &ref, CreatedBy: e.By, CreatedAt: e.Now}
		if err := e.Tx.InsertGrpDirect(m); err != nil {
			return res, err
		}
		if err := e.emitDirect(events.MembershipDirectAdded, m); err != nil {
			return res, err
		}
		seeds, res.Added = append(seeds, id), res.Added+1
	}
	for _, id := range remove {
		if seen[id] {
			continue
		}
		seen[id] = true
		m, err := e.Tx.GrpDirectFind(g.ID, list, store.MemberIdentity, strconv.FormatInt(id, 10))
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return res, err
		}
		if m.Source != "loader" || m.SourceRef == nil || *m.SourceRef != loaderID {
			continue
		}
		if err := e.Tx.DeleteGrpDirect(m.ID); err != nil {
			return res, err
		}
		if err := e.emitDirect(events.MembershipDirectRemoved, m); err != nil {
			return res, err
		}
		seeds, res.Removed = append(seeds, id), res.Removed+1
	}
	if len(seeds) == 0 {
		return res, nil
	}
	out, err := e.eng().RecomputeSeeds(e.Tx, e.Now, g.ID, list, seeds)
	if err != nil {
		return res, e.engineErr(err)
	}
	res.Outcome = out
	return res, nil
}
