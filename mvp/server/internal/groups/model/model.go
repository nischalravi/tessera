// Package model is the folder and group service of native groups (design
// docs/design/groups-grouper-parity.md §5.4): create, rename, move, copy and
// soft delete, with the naming rules of internal/groups/naming, and (GR-2) the
// direct-membership and composite operations on top of the membership engine.
// Every change writes its domain audit event in the same transaction.
package model

import (
	"errors"
	"slices"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/attrs"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/naming"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Limits on free text and on one copy.
const (
	MaxDescription = 4096
	MaxOwner       = 255
	MaxCopy        = 2000
)

// Env is one operation's context: the tenant transaction (which scopes every
// query), the clock reading and the acting platform user. Engine is the
// membership engine (its synchronous budget); nil uses the default.
//
// ByIdentity is the identity behind the acting user (it receives the creator
// privileges of what the operation creates) and TenantAdmin says the user holds
// an active tenant_admin role (GR-4). The model does not check privileges: the
// API does, before it calls the model.
type Env struct {
	Tx          *store.TenantTx
	Now         time.Time
	By          *string
	Engine      *engine.Engine
	ByIdentity  *int64
	TenantAdmin bool
}

var defaultEngine = engine.New(0)

func (e Env) privs() privs.Env {
	return privs.Env{Tx: e.Tx, Now: e.Now, By: e.By, ByIdentity: e.ByIdentity, TenantAdmin: e.TenantAdmin}
}

// Privs is the same operation context for the privilege model.
func (e Env) Privs() privs.Env { return e.privs() }

func (e Env) eng() *engine.Engine {
	if e.Engine != nil {
		return e.Engine
	}
	return defaultEngine
}

// index adapts the store to naming.Index. Folders and groups share one name
// space; ids of both kinds are UUIDs, so they cannot collide.
type index struct{ tx *store.TenantTx }

func (ix index) Live(name string) (string, bool, error) {
	if f, err := ix.tx.GrpFolderByName(name); err == nil {
		return string(f.ID), true, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return "", false, err
	}
	if g, err := ix.tx.GrpGroupByName(name); err == nil {
		return string(g.ID), true, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return "", false, err
	}
	return "", false, nil
}

func (ix index) Alias(name string) (string, bool, error) {
	a, err := ix.tx.GrpAliasByName(name)
	if errors.Is(err, store.ErrNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return a.ObjectID, true, nil
}

func (e Env) available(name, self string) error {
	return wrap(naming.CheckAvailable(index{e.Tx}, name, self))
}

// EnsureRoot returns the tenant's root folder, creating it (and the built-in
// members list) on first use. There is exactly one root per tenant: a unique
// index backs it.
func (e Env) EnsureRoot() (*store.Folder, error) {
	root, err := e.Tx.GrpRootFolder()
	if err == nil {
		return root, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	root = &store.Folder{Extension: "", DisplayExtension: "", Name: "", DisplayName: "", ManagedBy: store.ManagedByUI,
		CreatedAt: e.Now, CreatedBy: e.By}
	if err := e.Tx.InsertGrpFolder(root); err != nil {
		return nil, err
	}
	if _, err := e.Tx.EnsureGrpMembersList(); err != nil {
		return nil, err
	}
	return root, e.emitFolder(events.FolderCreated, root, nil)
}

func (e Env) audit(action, targetType, targetID string, detail ojson.Object) error {
	_, err := e.Tx.RecordAudit(store.AuditRecord{At: e.Now, Action: action, LegacyActor: "groups",
		TargetType: targetType, TargetID: targetID, Detail: detail})
	return err
}

func writable(f *store.Folder) error {
	if f.ManagedBy == store.ManagedByGrouperMirror {
		return conflict("folder_mirrored", "folder %q is mirrored from Grouper and is read-only here", f.Name)
	}
	return nil
}

func checkText(field, s string, max int) error {
	if len(s) > max {
		return invalid("invalid_"+field, "%s is at most %d characters", field, max)
	}
	return nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ownerPtr turns "" into nil (no owner).
func ownerPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func displayName(parentDisplay, ext string) string {
	if parentDisplay == "" {
		return ext
	}
	return parentDisplay + naming.Sep + ext
}

// ---------------------------------------------------------------- reads

// Folder returns a folder or a not-found Error.
func (e Env) Folder(id store.FolderID) (*store.Folder, error) {
	f, err := e.Tx.GrpFolder(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("no such folder")
	}
	return f, err
}

// Group returns a group (any status) or a not-found Error.
func (e Env) Group(id store.GroupID) (*store.NativeGroup, error) {
	g, err := e.Tx.GrpGroup(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("no such group")
	}
	return g, err
}

// FolderQuery selects folders; Scope is "one" (default) or "sub".
type FolderQuery struct {
	Parent store.FolderID
	Scope  string
	Q      string
	Limit  int
	Offset int
}

// ListFolders lists folders by name. With a Parent, scope one lists its
// children and scope sub everything below it.
func (e Env) ListFolders(q FolderQuery) ([]*store.Folder, error) {
	f := store.GrpFolderFilter{Q: q.Q, Limit: q.Limit, Offset: q.Offset}
	if q.Parent != "" {
		p, err := e.Folder(q.Parent)
		if err != nil {
			return nil, err
		}
		switch q.Scope {
		case "", "one":
			f.ParentID = p.ID
		case "sub":
			if p.Name == "" {
				f.ExcludeRoot = true
			}
			f.Prefix = p.Name
		default:
			return nil, invalid("invalid_scope", "scope is one or sub")
		}
	}
	return e.Tx.GrpFolders(f)
}

// GroupQuery selects groups; Scope is "one" (default) or "sub" and applies to Folder.
type GroupQuery struct {
	Folder         store.FolderID
	Scope          string
	Q              string
	Kind           store.GroupKind
	IncludeDeleted bool
	Limit          int
	Offset         int
}

// ListGroups lists groups by name.
func (e Env) ListGroups(q GroupQuery) ([]*store.NativeGroup, error) {
	f := store.GrpGroupFilter{Q: q.Q, Kind: q.Kind, IncludeDeleted: q.IncludeDeleted, Limit: q.Limit, Offset: q.Offset}
	if q.Kind != "" && q.Kind != store.KindGroup && q.Kind != store.KindRole {
		return nil, invalid("invalid_type", "type is group or role")
	}
	if q.Folder != "" {
		p, err := e.Folder(q.Folder)
		if err != nil {
			return nil, err
		}
		switch q.Scope {
		case "", "one":
			f.FolderID = p.ID
		case "sub":
			f.Prefix = p.Name
		default:
			return nil, invalid("invalid_scope", "scope is one or sub")
		}
	}
	return e.Tx.GrpGroups(f)
}

// ---------------------------------------------------------------- create

// CreateFolderInput creates a folder under Parent (the root when empty).
type CreateFolderInput struct {
	Parent           store.FolderID
	Extension        string
	DisplayExtension string
	Description      string
	DataOwner        string
}

// CreateFolder creates a folder. 409 name_taken, name_reserved_by_alias or
// folder_mirrored; 404 for an unknown parent.
func (e Env) CreateFolder(in CreateFolderInput) (*store.Folder, error) {
	root, err := e.EnsureRoot()
	if err != nil {
		return nil, err
	}
	parent := root
	if in.Parent != "" {
		if parent, err = e.Folder(in.Parent); err != nil {
			return nil, err
		}
	}
	if err := writable(parent); err != nil {
		return nil, err
	}
	name, err := naming.Join(parent.Name, in.Extension)
	if err != nil {
		return nil, wrap(err)
	}
	disp := in.DisplayExtension
	if disp == "" {
		disp = in.Extension
	}
	if err := errors.Join(wrap(naming.ValidateDisplay(disp)), checkText("description", in.Description, MaxDescription),
		checkText("data_owner", in.DataOwner, MaxOwner)); err != nil {
		return nil, firstErr(err)
	}
	if err := e.available(name, ""); err != nil {
		return nil, err
	}
	pid := parent.ID
	f := &store.Folder{ParentID: &pid, Extension: in.Extension, DisplayExtension: disp, Name: name,
		DisplayName: displayName(parent.DisplayName, disp), Description: in.Description, DataOwner: ownerPtr(in.DataOwner),
		ManagedBy: store.ManagedByUI, CreatedAt: e.Now, CreatedBy: e.By}
	if err := e.Tx.InsertGrpFolder(f); err != nil {
		return nil, err
	}
	if err := e.emitFolder(events.FolderCreated, f, nil); err != nil {
		return nil, err
	}
	if err := privs.GrantCreator(e.privs(), privs.FolderObject(f.ID)); err != nil {
		return nil, err
	}
	return f, e.audit("groups.folder.created", "folder", string(f.ID), ojson.Object{
		{Key: "folder_id", Value: string(f.ID)}, {Key: "name", Value: f.Name}, {Key: "parent_id", Value: string(parent.ID)}})
}

// firstErr returns the first non-nil error of a joined error.
func firstErr(err error) error {
	type multi interface{ Unwrap() []error }
	if m, ok := err.(multi); ok {
		for _, e := range m.Unwrap() {
			if e != nil {
				return e
			}
		}
	}
	return err
}

// CreateGroupInput creates a group in Folder: basic by default, or a composite
// (Definition composite with Op and Factors). Policy groups arrive with GR-9.
type CreateGroupInput struct {
	Folder            store.FolderID
	Extension         string
	DisplayExtension  string
	Description       string
	Kind              store.GroupKind
	DataOwner         string
	MemberDescription string
	Requestable       bool
	Definition        store.Definition
	Op                store.CompositeOp
	Factors           []store.GroupID
}

// CreateGroup creates a basic or composite group.
func (e Env) CreateGroup(in CreateGroupInput) (*store.NativeGroup, error) {
	if _, err := e.EnsureRoot(); err != nil {
		return nil, err
	}
	folder, err := e.Folder(in.Folder)
	if err != nil {
		return nil, err
	}
	if err := writable(folder); err != nil {
		return nil, err
	}
	if in.Kind == "" {
		in.Kind = store.KindGroup
	}
	if in.Kind != store.KindGroup && in.Kind != store.KindRole {
		return nil, invalid("invalid_type", "type is group or role")
	}
	name, err := naming.Join(folder.Name, in.Extension)
	if err != nil {
		return nil, wrap(err)
	}
	disp := in.DisplayExtension
	if disp == "" {
		disp = in.Extension
	}
	if err := errors.Join(wrap(naming.ValidateDisplay(disp)), checkText("description", in.Description, MaxDescription),
		checkText("data_owner", in.DataOwner, MaxOwner), checkText("member_description", in.MemberDescription, MaxDescription)); err != nil {
		return nil, firstErr(err)
	}
	if err := e.available(name, ""); err != nil {
		return nil, err
	}
	def := in.Definition
	if def == "" {
		def = store.DefinitionBasic
	}
	var op *store.CompositeOp
	switch def {
	case store.DefinitionBasic:
		if in.Op != "" || len(in.Factors) > 0 {
			return nil, invalid("invalid_composite", "op and factors are only for a composite group")
		}
	case store.DefinitionComposite:
		if err := e.checkFactors("", in.Op, in.Factors); err != nil {
			return nil, err
		}
		o := in.Op
		op = &o
	default:
		return nil, invalid("invalid_definition", "definition is basic or composite (policy groups arrive with GR-9)")
	}
	g := &store.NativeGroup{FolderID: folder.ID, Extension: in.Extension, DisplayExtension: disp, Name: name,
		DisplayName: displayName(folder.DisplayName, disp), Description: in.Description, Kind: in.Kind,
		Definition: def, CompositeOp: op, ManagedBy: store.ManagedByUI, DataOwner: ownerPtr(in.DataOwner),
		MemberDescription: ownerPtr(in.MemberDescription), Requestable: in.Requestable, Status: store.GroupActive,
		CreatedAt: e.Now, CreatedBy: e.By}
	if err := e.Tx.InsertGrpGroup(g); err != nil {
		return nil, err
	}
	if err := e.emitGroup(events.GroupCreated, g, nil); err != nil {
		return nil, err
	}
	if err := privs.GrantCreator(e.privs(), privs.GroupObject(g.ID)); err != nil {
		return nil, err
	}
	detail := ojson.Object{{Key: "group_id", Value: string(g.ID)}, {Key: "name", Value: g.Name},
		{Key: "folder_id", Value: string(folder.ID)}, {Key: "kind", Value: string(g.Kind)},
		{Key: "definition", Value: string(def)}}
	if def == store.DefinitionComposite {
		if err := e.eng().SetFactors(e.Tx, e.Now, g.ID, in.Factors); err != nil {
			return nil, e.engineErr(err)
		}
		if err := e.emitGroup(events.GroupDefinitionChanged, g, nil); err != nil {
			return nil, err
		}
		if _, err := e.eng().RecomputeGroup(e.Tx, e.Now, g.ID); err != nil {
			return nil, e.engineErr(err)
		}
		detail = append(detail, ojson.KV{Key: "op", Value: string(in.Op)}, ojson.KV{Key: "factors", Value: groupIDStrings(in.Factors)})
		if g, err = e.Group(g.ID); err != nil { // the recompute may have left it pending
			return nil, err
		}
	}
	return g, e.audit("groups.group.created", "group", string(g.ID), detail)
}

// ---------------------------------------------------------------- rename and move

// setName gives an object its new name (and display name), keeping the old
// name as an alias unless only the case changed. The object's own alias for
// the new name, if any, is dropped: it has taken the name back.
func (e Env) setName(objectType, id, oldName, newName string) error {
	if err := e.Tx.DeleteGrpAlias(objectType, id, newName); err != nil {
		return err
	}
	if oldName == "" || naming.Equal(oldName, newName) {
		return nil
	}
	return e.Tx.InsertGrpAlias(&store.GrpAlias{ObjectType: objectType, ObjectID: id, OldName: oldName, CreatedAt: e.Now})
}

// relocate renames folder f to newExt under newParent: f, its subfolders and
// every group below it (deleted ones too) get new names and aliases for the
// old ones. It returns the number of descendants renamed.
func (e Env) relocate(f *store.Folder, newParent *store.Folder, newExt, newDisp string) (int, error) {
	if f.ParentID == nil {
		return 0, conflict("root_folder", "the root folder cannot be renamed, moved, copied or deleted")
	}
	if naming.IsWithin(newParent.Name, f.Name) {
		return 0, conflict("move_into_self", "a folder cannot be moved into itself or its own subfolders")
	}
	newName, err := naming.Join(newParent.Name, newExt)
	if err != nil {
		return 0, wrap(err)
	}
	if err := errors.Join(writable(f), writable(newParent)); err != nil {
		return 0, firstErr(err)
	}
	oldName, oldDisplay := f.Name, f.DisplayName
	newDisplay := displayName(newParent.DisplayName, newDisp)
	subFolders, err := e.Tx.GrpFoldersBelow(oldName)
	if err != nil {
		return 0, err
	}
	subGroups, err := e.Tx.GrpGroupsBelow(oldName)
	if err != nil {
		return 0, err
	}
	if err := e.available(newName, string(f.ID)); err != nil {
		return 0, err
	}
	// validate the whole subtree before the first write
	type target struct{ name, display string }
	nameOf := func(name, display string) (target, error) {
		n, _ := naming.Rebase(name, oldName, newName)
		if _, err := naming.Parse(n); err != nil {
			return target{}, wrap(err)
		}
		d, _ := naming.Rebase(display, oldDisplay, newDisplay)
		return target{n, d}, nil
	}
	fT := make([]target, len(subFolders))
	gT := make([]target, len(subGroups))
	for i, s := range subFolders {
		if err := writable(s); err != nil {
			return 0, err
		}
		if fT[i], err = nameOf(s.Name, s.DisplayName); err != nil {
			return 0, err
		}
		if err := e.available(fT[i].name, string(s.ID)); err != nil {
			return 0, err
		}
	}
	for i, g := range subGroups {
		if gT[i], err = nameOf(g.Name, g.DisplayName); err != nil {
			return 0, err
		}
		if err := e.available(gT[i].name, string(g.ID)); err != nil {
			return 0, err
		}
	}
	for i, s := range subFolders {
		if err := e.setName(store.AliasFolder, string(s.ID), s.Name, fT[i].name); err != nil {
			return 0, err
		}
		oldSub := s.Name
		s.Name, s.DisplayName = fT[i].name, fT[i].display
		if err := e.Tx.UpdateGrpFolder(s); err != nil {
			return 0, wrap(err)
		}
		if err := e.emitFolder(events.FolderRenamed, s, map[string]any{"old_name": oldSub, "via": "ancestor"}); err != nil {
			return 0, err
		}
	}
	for i, g := range subGroups {
		if err := e.setName(store.AliasGroup, string(g.ID), g.Name, gT[i].name); err != nil {
			return 0, err
		}
		oldSub := g.Name
		g.Name, g.DisplayName = gT[i].name, gT[i].display
		if err := e.Tx.UpdateGrpGroup(g); err != nil {
			return 0, wrap(err)
		}
		if err := e.emitGroup(events.GroupRenamed, g, map[string]any{"old_name": oldSub, "via": "ancestor"}); err != nil {
			return 0, err
		}
	}
	if err := e.setName(store.AliasFolder, string(f.ID), oldName, newName); err != nil {
		return 0, err
	}
	pid := newParent.ID
	f.ParentID, f.Extension, f.DisplayExtension, f.Name, f.DisplayName = &pid, newExt, newDisp, newName, newDisplay
	if err := e.Tx.UpdateGrpFolder(f); err != nil {
		return 0, wrap(err)
	}
	return len(subFolders) + len(subGroups), nil
}

// UpdateFolderInput changes a folder; nil fields are left alone. An empty
// DataOwner clears it. Version, when set, must match (409 version_conflict).
type UpdateFolderInput struct {
	Extension        *string
	DisplayExtension *string
	Description      *string
	DataOwner        *string
	Version          *int64
}

// UpdateFolder renames a folder (a new Extension renames the subtree and keeps
// the old names as aliases) or edits its descriptive fields.
func (e Env) UpdateFolder(id store.FolderID, in UpdateFolderInput) (*store.Folder, error) {
	f, err := e.Folder(id)
	if err != nil {
		return nil, err
	}
	if in.Version != nil && *in.Version != f.Version {
		return nil, wrap(store.ErrVersionConflict)
	}
	if f.ParentID == nil {
		return nil, conflict("root_folder", "the root folder cannot be changed")
	}
	if err := writable(f); err != nil {
		return nil, err
	}
	desc, owner := f.Description, deref(f.DataOwner)
	if in.Description != nil {
		desc = *in.Description
	}
	if in.DataOwner != nil {
		owner = *in.DataOwner
	}
	if err := errors.Join(checkText("description", desc, MaxDescription), checkText("data_owner", owner, MaxOwner)); err != nil {
		return nil, firstErr(err)
	}
	ext, disp := f.Extension, f.DisplayExtension
	if in.Extension != nil {
		ext = *in.Extension
		if in.DisplayExtension == nil && naming.Equal(disp, f.Extension) {
			disp = ext // the display name followed the extension; keep it that way
		}
	}
	if in.DisplayExtension != nil {
		disp = *in.DisplayExtension
		if disp == "" {
			disp = ext
		}
	}
	if err := wrap(naming.ValidateDisplay(disp)); err != nil {
		return nil, err
	}
	old := f.Name
	f.Description, f.DataOwner = desc, ownerPtr(owner)
	descendants := 0
	if ext != f.Extension || disp != f.DisplayExtension {
		parent, err := e.Folder(*f.ParentID)
		if err != nil {
			return nil, err
		}
		if descendants, err = e.relocate(f, parent, ext, disp); err != nil {
			return nil, err
		}
	} else if err := e.Tx.UpdateGrpFolder(f); err != nil {
		return nil, wrap(err)
	}
	action, evType := "groups.folder.updated", events.FolderUpdated
	if f.Name != old {
		action, evType = "groups.folder.renamed", events.FolderRenamed
	}
	if err := e.emitFolder(evType, f, map[string]any{"old_name": old}); err != nil {
		return nil, err
	}
	return f, e.audit(action, "folder", string(f.ID), ojson.Object{{Key: "folder_id", Value: string(f.ID)},
		{Key: "old_name", Value: old}, {Key: "name", Value: f.Name}, {Key: "descendants", Value: descendants}})
}

// MoveFolder moves a folder under a new parent, keeping its extension. The
// old names of the folder and everything below it stay as aliases. Moving to
// the current parent changes nothing.
func (e Env) MoveFolder(id store.FolderID, parent store.FolderID) (*store.Folder, error) {
	f, err := e.Folder(id)
	if err != nil {
		return nil, err
	}
	p, err := e.Folder(parent)
	if err != nil {
		return nil, err
	}
	if f.ParentID != nil && *f.ParentID == p.ID {
		return f, nil
	}
	old := f.Name
	n, err := e.relocate(f, p, f.Extension, f.DisplayExtension)
	if err != nil {
		return nil, err
	}
	if err := e.emitFolder(events.FolderMoved, f, map[string]any{"old_name": old}); err != nil {
		return nil, err
	}
	return f, e.audit("groups.folder.moved", "folder", string(f.ID), ojson.Object{{Key: "folder_id", Value: string(f.ID)},
		{Key: "old_name", Value: old}, {Key: "name", Value: f.Name}, {Key: "parent_id", Value: string(p.ID)},
		{Key: "descendants", Value: n}})
}

// UpdateGroupInput changes a group; nil fields are left alone. An empty
// DataOwner or MemberDescription clears it. Status is active or disabled.
// EnabledFrom and DisabledAt set the group's own dates (a group is empty
// outside them, design §6.1); the Clear flags remove one.
type UpdateGroupInput struct {
	Extension         *string
	DisplayExtension  *string
	Description       *string
	DataOwner         *string
	MemberDescription *string
	Requestable       *bool
	Status            *string
	EnabledFrom       *time.Time
	DisabledAt        *time.Time
	ClearEnabledFrom  bool
	ClearDisabledAt   bool
	Version           *int64
}

func sameTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

func (e Env) liveGroup(id store.GroupID) (*store.NativeGroup, *store.Folder, error) {
	g, err := e.Group(id)
	if err != nil {
		return nil, nil, err
	}
	if g.Status == store.GroupDeleted {
		return nil, nil, conflict("group_deleted", "the group is deleted; restore it first")
	}
	f, err := e.Folder(g.FolderID)
	if err != nil {
		return nil, nil, err
	}
	return g, f, writable(f)
}

// UpdateGroup renames a group (keeping the old name as an alias) or edits its
// descriptive fields, status (active or disabled) and requestable flag.
func (e Env) UpdateGroup(id store.GroupID, in UpdateGroupInput) (*store.NativeGroup, error) {
	g, folder, err := e.liveGroup(id)
	if err != nil {
		return nil, err
	}
	if in.Version != nil && *in.Version != g.Version {
		return nil, wrap(store.ErrVersionConflict)
	}
	if g.ManagedBy == store.ManagedByGrouperMirror {
		return nil, conflict("folder_mirrored", "group %q is mirrored from Grouper and is read-only here", g.Name)
	}
	old := g.Name
	before := *g
	if in.Description != nil {
		g.Description = *in.Description
	}
	if in.DataOwner != nil {
		g.DataOwner = ownerPtr(*in.DataOwner)
	}
	if in.MemberDescription != nil {
		g.MemberDescription = ownerPtr(*in.MemberDescription)
	}
	if in.Requestable != nil {
		g.Requestable = *in.Requestable
	}
	if in.Status != nil {
		if *in.Status != store.GroupActive && *in.Status != store.GroupDisabled {
			return nil, invalid("invalid_status", "status is active or disabled (use DELETE to delete)")
		}
		g.Status = *in.Status
	}
	// status and dates decide whether the group has members: the engine recomputes it
	oldStatus, oldFrom, oldTo := before.Status, before.EnabledFrom, before.DisabledAt
	if in.ClearEnabledFrom {
		g.EnabledFrom = nil
	}
	if in.EnabledFrom != nil {
		g.EnabledFrom = in.EnabledFrom
	}
	if in.ClearDisabledAt {
		g.DisabledAt = nil
	}
	if in.DisabledAt != nil {
		g.DisabledAt = in.DisabledAt
	}
	if g.EnabledFrom != nil && g.DisabledAt != nil && !g.DisabledAt.After(*g.EnabledFrom) {
		return nil, invalid("invalid_dates", "disabled_at must be after enabled_from")
	}
	membershipChanged := g.Status != oldStatus || !sameTime(g.EnabledFrom, oldFrom) || !sameTime(g.DisabledAt, oldTo)
	if err := errors.Join(checkText("description", g.Description, MaxDescription), checkText("data_owner", deref(g.DataOwner), MaxOwner),
		checkText("member_description", deref(g.MemberDescription), MaxDescription)); err != nil {
		return nil, firstErr(err)
	}
	if in.Extension != nil {
		g.Extension = *in.Extension
	}
	if in.DisplayExtension != nil {
		g.DisplayExtension = *in.DisplayExtension
		if g.DisplayExtension == "" {
			g.DisplayExtension = g.Extension
		}
	} else if in.Extension != nil && naming.Equal(g.DisplayExtension, extOf(old)) {
		g.DisplayExtension = g.Extension
	}
	if err := wrap(naming.ValidateDisplay(g.DisplayExtension)); err != nil {
		return nil, err
	}
	if err := e.placeGroup(g, folder); err != nil {
		return nil, err
	}
	evType := events.GroupUpdated
	switch {
	case g.Name != old:
		evType = events.GroupRenamed
	case g.Status == store.GroupDisabled && oldStatus != store.GroupDisabled:
		evType = events.GroupDisabled
	case g.Status == store.GroupActive && oldStatus != store.GroupActive:
		evType = events.GroupEnabled
	}
	if err := e.emitGroup(evType, g, map[string]any{"old_name": old, "old_status": oldStatus}); err != nil {
		return nil, err
	}
	if membershipChanged {
		if _, err := e.eng().RecomputeGroup(e.Tx, e.Now, g.ID); err != nil {
			return nil, e.engineErr(err)
		}
		if g, err = e.Group(g.ID); err != nil { // the recompute may have left it pending
			return nil, err
		}
	}
	action := "groups.group.updated"
	if g.Name != old {
		action = "groups.group.renamed"
	}
	return g, e.audit(action, "group", string(g.ID), ojson.Object{{Key: "group_id", Value: string(g.ID)},
		{Key: "old_name", Value: old}, {Key: "name", Value: g.Name}, {Key: "status", Value: g.Status}})
}

func extOf(name string) string { _, ext := naming.Split(name); return ext }

// placeGroup recomputes g's name from its folder and extension, aliases the
// old name when it changed and saves g.
func (e Env) placeGroup(g *store.NativeGroup, folder *store.Folder) error {
	newName, err := naming.Join(folder.Name, g.Extension)
	if err != nil {
		return wrap(err)
	}
	if newName != g.Name {
		if err := e.available(newName, string(g.ID)); err != nil {
			return err
		}
		if err := e.setName(store.AliasGroup, string(g.ID), g.Name, newName); err != nil {
			return err
		}
	}
	g.FolderID, g.Name, g.DisplayName = folder.ID, newName, displayName(folder.DisplayName, g.DisplayExtension)
	return wrap(e.Tx.UpdateGrpGroup(g))
}

// MoveGroup moves a group to another folder, keeping its extension; the old
// name stays as an alias. Moving to the current folder changes nothing.
func (e Env) MoveGroup(id store.GroupID, folder store.FolderID) (*store.NativeGroup, error) {
	g, _, err := e.liveGroup(id)
	if err != nil {
		return nil, err
	}
	dest, err := e.Folder(folder)
	if err != nil {
		return nil, err
	}
	if err := writable(dest); err != nil {
		return nil, err
	}
	if g.FolderID == dest.ID {
		return g, nil
	}
	old := g.Name
	if err := e.placeGroup(g, dest); err != nil {
		return nil, err
	}
	if err := e.emitGroup(events.GroupMoved, g, map[string]any{"old_name": old}); err != nil {
		return nil, err
	}
	return g, e.audit("groups.group.moved", "group", string(g.ID), ojson.Object{{Key: "group_id", Value: string(g.ID)},
		{Key: "old_name", Value: old}, {Key: "name", Value: g.Name}, {Key: "folder_id", Value: string(dest.ID)}})
}

// ---------------------------------------------------------------- copy

// CopyInput names the copy's parent folder and, optionally, its extension
// (default: the source's).
type CopyInput struct {
	Parent    store.FolderID
	Extension string
}

// CopyGroup copies a group's definition and descriptive fields into a folder.
// Memberships are not copied (the engine, GR-2, owns them).
func (e Env) CopyGroup(id store.GroupID, in CopyInput) (*store.NativeGroup, error) {
	src, err := e.Group(id)
	if err != nil {
		return nil, err
	}
	if src.Status == store.GroupDeleted {
		return nil, conflict("group_deleted", "the group is deleted; restore it first")
	}
	dest, err := e.Folder(in.Parent)
	if err != nil {
		return nil, err
	}
	if err := writable(dest); err != nil {
		return nil, err
	}
	ext := in.Extension
	disp := src.DisplayExtension
	if ext == "" {
		ext = src.Extension
	} else if ext != src.Extension {
		disp = ext
	}
	name, err := naming.Join(dest.Name, ext)
	if err != nil {
		return nil, wrap(err)
	}
	if err := e.available(name, ""); err != nil {
		return nil, err
	}
	cp := copyGroup(src, dest, name, ext, disp, e)
	if err := e.Tx.InsertGrpGroup(cp); err != nil {
		return nil, err
	}
	if err := e.emitGroup(events.GroupCreated, cp, map[string]any{"copied_from": string(src.ID)}); err != nil {
		return nil, err
	}
	if err := privs.GrantCreator(e.privs(), privs.GroupObject(cp.ID)); err != nil {
		return nil, err
	}
	if err := e.copyObjectTypes(attrs.Owner{Type: store.AttrOwnerGroup, ID: string(src.ID)},
		attrs.Owner{Type: store.AttrOwnerGroup, ID: string(cp.ID)}); err != nil {
		return nil, err
	}
	return cp, e.audit("groups.group.copied", "group", string(cp.ID), ojson.Object{{Key: "group_id", Value: string(cp.ID)},
		{Key: "source_id", Value: string(src.ID)}, {Key: "name", Value: cp.Name}, {Key: "folder_id", Value: string(dest.ID)}})
}

func copyGroup(src *store.NativeGroup, dest *store.Folder, name, ext, disp string, e Env) *store.NativeGroup {
	return &store.NativeGroup{FolderID: dest.ID, Extension: ext, DisplayExtension: disp, Name: name,
		DisplayName: displayName(dest.DisplayName, disp), Description: src.Description, Kind: src.Kind,
		Definition: store.DefinitionBasic, ManagedBy: store.ManagedByUI, ObjectTypes: slices.Clone(src.ObjectTypes),
		DataOwner: src.DataOwner, MemberDescription: src.MemberDescription, Requestable: src.Requestable,
		Status: src.Status, CreatedAt: e.Now, CreatedBy: e.By}
}

// CopyFolder copies a folder with its subfolders and its non-deleted groups
// under another folder. Memberships and privileges are not copied. Nothing is
// written unless every new name is free; at most MaxCopy objects are copied.
func (e Env) CopyFolder(id store.FolderID, in CopyInput) (*store.Folder, error) {
	src, err := e.Folder(id)
	if err != nil {
		return nil, err
	}
	if src.ParentID == nil {
		return nil, conflict("root_folder", "the root folder cannot be renamed, moved, copied or deleted")
	}
	dest, err := e.Folder(in.Parent)
	if err != nil {
		return nil, err
	}
	if naming.IsWithin(dest.Name, src.Name) {
		return nil, conflict("copy_into_self", "a folder cannot be copied into itself or its own subfolders")
	}
	if err := writable(dest); err != nil {
		return nil, err
	}
	ext, disp := in.Extension, src.DisplayExtension
	if ext == "" {
		ext = src.Extension
	} else if ext != src.Extension {
		disp = ext
	}
	newName, err := naming.Join(dest.Name, ext)
	if err != nil {
		return nil, wrap(err)
	}
	newDisplay := displayName(dest.DisplayName, disp)
	subFolders, err := e.Tx.GrpFoldersBelow(src.Name)
	if err != nil {
		return nil, err
	}
	allGroups, err := e.Tx.GrpGroupsBelow(src.Name) // includes the source folder's own groups
	if err != nil {
		return nil, err
	}
	var groups []*store.NativeGroup
	for _, g := range allGroups {
		if g.Status != store.GroupDeleted {
			groups = append(groups, g)
		}
	}
	if n := 1 + len(subFolders) + len(groups); n > MaxCopy {
		return nil, invalid("copy_too_large", "a copy is at most %d objects; this one has %d", MaxCopy, n)
	}
	check := func(name string) error {
		n, _ := naming.Rebase(name, src.Name, newName)
		if _, err := naming.Parse(n); err != nil {
			return wrap(err)
		}
		return e.available(n, "")
	}
	if err := e.available(newName, ""); err != nil {
		return nil, err
	}
	for _, s := range subFolders {
		if err := check(s.Name); err != nil {
			return nil, err
		}
	}
	for _, g := range groups {
		if err := check(g.Name); err != nil {
			return nil, err
		}
	}
	// parents sort before their children (a name is a prefix of theirs)
	did := dest.ID
	top := &store.Folder{ParentID: &did, Extension: ext, DisplayExtension: disp, Name: newName, DisplayName: newDisplay,
		Description: src.Description, ObjectTypes: slices.Clone(src.ObjectTypes), DataOwner: src.DataOwner,
		ManagedBy: store.ManagedByUI, CreatedAt: e.Now, CreatedBy: e.By}
	if err := e.Tx.InsertGrpFolder(top); err != nil {
		return nil, err
	}
	if err := e.emitFolder(events.FolderCreated, top, map[string]any{"copied_from": string(src.ID)}); err != nil {
		return nil, err
	}
	// the copier administers the copy; what is below it gets the defaults only
	if err := privs.GrantCreator(e.privs(), privs.FolderObject(top.ID)); err != nil {
		return nil, err
	}
	if err := e.copyObjectTypes(attrs.Owner{Type: store.AttrOwnerFolder, ID: string(src.ID)},
		attrs.Owner{Type: store.AttrOwnerFolder, ID: string(top.ID)}); err != nil {
		return nil, err
	}
	newID := map[store.FolderID]store.FolderID{src.ID: top.ID}
	for _, s := range subFolders {
		n, d := rebased(s.Name, s.DisplayName, src, newName, newDisplay)
		pid := newID[*s.ParentID]
		c := &store.Folder{ParentID: &pid, Extension: s.Extension, DisplayExtension: s.DisplayExtension, Name: n, DisplayName: d,
			Description: s.Description, ObjectTypes: slices.Clone(s.ObjectTypes), DataOwner: s.DataOwner,
			ManagedBy: store.ManagedByUI, CreatedAt: e.Now, CreatedBy: e.By}
		if err := e.Tx.InsertGrpFolder(c); err != nil {
			return nil, err
		}
		if err := e.emitFolder(events.FolderCreated, c, map[string]any{"copied_from": string(s.ID)}); err != nil {
			return nil, err
		}
		if err := privs.GrantDefaults(e.privs(), privs.FolderObject(c.ID)); err != nil {
			return nil, err
		}
		if err := e.copyObjectTypes(attrs.Owner{Type: store.AttrOwnerFolder, ID: string(s.ID)},
			attrs.Owner{Type: store.AttrOwnerFolder, ID: string(c.ID)}); err != nil {
			return nil, err
		}
		newID[s.ID] = c.ID
	}
	copied := 0
	for _, g := range groups {
		n, d := rebased(g.Name, g.DisplayName, src, newName, newDisplay)
		cp := copyGroup(g, &store.Folder{ID: newID[g.FolderID]}, n, g.Extension, g.DisplayExtension, e)
		cp.DisplayName = d
		if err := e.Tx.InsertGrpGroup(cp); err != nil {
			return nil, err
		}
		if err := e.emitGroup(events.GroupCreated, cp, map[string]any{"copied_from": string(g.ID)}); err != nil {
			return nil, err
		}
		if err := privs.GrantDefaults(e.privs(), privs.GroupObject(cp.ID)); err != nil {
			return nil, err
		}
		if err := e.copyObjectTypes(attrs.Owner{Type: store.AttrOwnerGroup, ID: string(g.ID)},
			attrs.Owner{Type: store.AttrOwnerGroup, ID: string(cp.ID)}); err != nil {
			return nil, err
		}
		copied++
	}
	return top, e.audit("groups.folder.copied", "folder", string(top.ID), ojson.Object{{Key: "folder_id", Value: string(top.ID)},
		{Key: "source_id", Value: string(src.ID)}, {Key: "name", Value: top.Name}, {Key: "folders", Value: len(subFolders)},
		{Key: "groups", Value: copied}})
}

func rebased(name, display string, src *store.Folder, newName, newDisplay string) (string, string) {
	n, _ := naming.Rebase(name, src.Name, newName)
	d, _ := naming.Rebase(display, src.DisplayName, newDisplay)
	return n, d
}

// ---------------------------------------------------------------- delete

// DeleteFolder removes an empty folder (no subfolders, no groups, deleted
// ones included: they can be restored and need their folder). Its aliases go
// with it, which frees its old names.
func (e Env) DeleteFolder(id store.FolderID) error {
	f, err := e.Folder(id)
	if err != nil {
		return err
	}
	if f.ParentID == nil {
		return conflict("root_folder", "the root folder cannot be renamed, moved, copied or deleted")
	}
	if err := writable(f); err != nil {
		return err
	}
	folders, groups, err := e.Tx.GrpFolderChildCounts(f.ID)
	if err != nil {
		return err
	}
	defs, err := e.Tx.GrpAttrDefCountIn(f.ID)
	if err != nil {
		return err
	}
	if folders+groups+defs > 0 {
		ce := conflict("folder_not_empty", "the folder still holds %d subfolder(s), %d group(s) and %d attribute definition(s)", folders, groups, defs)
		ce.Extra = map[string]any{"folders": folders, "groups": groups, "attr_defs": defs}
		return ce
	}
	if err := e.Tx.DeleteGrpAliasesOf(store.AliasFolder, string(f.ID)); err != nil {
		return err
	}
	// the folder's attribute assignments end with it
	if _, err := attrs.RemoveAllOf(e.Attrs(), attrs.Owner{Type: store.AttrOwnerFolder, ID: string(f.ID)}); err != nil {
		return err
	}
	// the folder's privileges end with it; a row on a folder names no foreign key
	if _, err := privs.RevokeAllOf(e.privs(), privs.FolderObject(f.ID)); err != nil {
		return err
	}
	if err := e.Tx.DeleteGrpFolder(f.ID); err != nil {
		return err
	}
	if err := e.emitFolder(events.FolderDeleted, f, map[string]any{"name": f.Name}); err != nil {
		return err
	}
	return e.audit("groups.folder.deleted", "folder", string(f.ID), ojson.Object{{Key: "folder_id", Value: string(f.ID)},
		{Key: "name", Value: f.Name}})
}

// DeleteGroup soft-deletes a group: it keeps its row and name, is hidden from
// listings and is an empty set. Deleting a deleted group changes nothing.
func (e Env) DeleteGroup(id store.GroupID) error {
	g, err := e.Group(id)
	if err != nil {
		return err
	}
	if g.Status == store.GroupDeleted {
		return nil
	}
	f, err := e.Folder(g.FolderID)
	if err != nil {
		return err
	}
	if err := writable(f); err != nil {
		return err
	}
	g.Status = store.GroupDeleted
	if err := e.Tx.UpdateGrpGroup(g); err != nil {
		return wrap(err)
	}
	if err := e.emitGroup(events.GroupDeleted, g, nil); err != nil {
		return err
	}
	// a deleted group is an empty set: its members leave it and everything it feeds
	if _, err := e.eng().RecomputeGroup(e.Tx, e.Now, g.ID); err != nil {
		return e.engineErr(err)
	}
	return e.audit("groups.group.deleted", "group", string(g.ID), ojson.Object{{Key: "group_id", Value: string(g.ID)},
		{Key: "name", Value: g.Name}})
}

// RestoreGroup brings a soft-deleted group back as active.
func (e Env) RestoreGroup(id store.GroupID) (*store.NativeGroup, error) {
	g, err := e.Group(id)
	if err != nil {
		return nil, err
	}
	if g.Status != store.GroupDeleted {
		return nil, conflict("not_deleted", "the group is not deleted")
	}
	f, err := e.Folder(g.FolderID)
	if err != nil {
		return nil, err
	}
	if err := writable(f); err != nil {
		return nil, err
	}
	g.Status = store.GroupActive
	if err := e.Tx.UpdateGrpGroup(g); err != nil {
		return nil, wrap(err)
	}
	if err := e.emitGroup(events.GroupRestored, g, nil); err != nil {
		return nil, err
	}
	if _, err := e.eng().RecomputeGroup(e.Tx, e.Now, g.ID); err != nil {
		return nil, e.engineErr(err)
	}
	if g, err = e.Group(g.ID); err != nil { // the recompute may have left it pending
		return nil, err
	}
	return g, e.audit("groups.group.restored", "group", string(g.ID), ojson.Object{{Key: "group_id", Value: string(g.ID)},
		{Key: "name", Value: g.Name}})
}
