package attrs

import (
	"errors"
	"slices"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/naming"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Def returns an attribute definition or a not-found Error.
func Def(tx *store.TenantTx, id string) (*store.GrpAttrDef, error) {
	d, err := tx.GrpAttrDef(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("no such attribute definition")
	}
	return d, err
}

// Name returns an attribute name or a not-found Error.
func Name(tx *store.TenantTx, id string) (*store.GrpAttrName, error) {
	n, err := tx.GrpAttrName(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("no such attribute name")
	}
	return n, err
}

// Action returns an attribute action or a not-found Error.
func Action(tx *store.TenantTx, id string) (*store.GrpAttrAction, error) {
	a, err := tx.GrpAttrAction(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("no such attribute action")
	}
	return a, err
}

// DefByName finds a definition by its full name ("etc:objectTypes").
func DefByName(tx *store.TenantTx, name string) (*store.GrpAttrDef, error) {
	parent, ext := naming.Split(name)
	f := (*store.Folder)(nil)
	var err error
	if parent == "" {
		f, err = tx.GrpRootFolder()
	} else {
		f, err = tx.GrpFolderByName(parent)
	}
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("no such attribute definition")
	}
	if err != nil {
		return nil, err
	}
	d, err := tx.GrpAttrDefByExtension(f.ID, ext)
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("no such attribute definition")
	}
	return d, err
}

// NameFullName is the full name of an attribute name: its definition's name,
// ':' and its extension.
func NameFullName(d *store.GrpAttrDef, n *store.GrpAttrName) string {
	return d.Name() + naming.Sep + n.Extension
}

// writableFolder returns the folder of a definition, refusing a mirrored one
// (K11: a mirrored folder has one writer).
func writableFolder(tx *store.TenantTx, id store.FolderID) (*store.Folder, error) {
	f, err := tx.GrpFolder(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("no such folder")
	}
	if err != nil {
		return nil, err
	}
	if f.ManagedBy == store.ManagedByGrouperMirror {
		return nil, conflict("folder_mirrored", "folder %q is mirrored from Grouper and is read-only here", f.Name)
	}
	return f, nil
}

// normalizeAssignTo validates the owner types a definition may be assigned to
// and returns them in vocabulary order.
func normalizeAssignTo(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, invalid("invalid_assign_to", "assign_to names at least one owner type (%v)", OwnerTypes)
	}
	for _, t := range in {
		if !slices.Contains(OwnerTypes, t) {
			return nil, invalid("invalid_assign_to", "%q is not an owner type (%v)", t, OwnerTypes)
		}
	}
	out := make([]string, 0, len(in))
	for _, t := range OwnerTypes {
		if slices.Contains(in, t) {
			out = append(out, t)
		}
	}
	return out, nil
}

// DefInput creates a definition in Folder. AttrType defaults to attr and
// ValueType to marker (an assignment with no value).
type DefInput struct {
	Folder           store.FolderID
	Extension        string
	DisplayExtension string
	Description      string
	AttrType         string
	ValueType        string
	MultiAssign      bool
	MultiValued      bool
	AssignTo         []string
	// System marks the built-in definition (the object types).
	System bool
}

func defDetail(d *store.GrpAttrDef) ojson.Object {
	return ojson.Object{{Key: "def_id", Value: d.ID}, {Key: "name", Value: d.Name()}, {Key: "folder_id", Value: string(d.FolderID)},
		{Key: "attr_type", Value: d.AttrType}, {Key: "value_type", Value: d.ValueType}, {Key: "multi_assign", Value: d.MultiAssign},
		{Key: "multi_valued", Value: d.MultiValued}, {Key: "assign_to", Value: slices.Clone(d.AssignTo)}}
}

// CreateDef creates a definition with its default action, and gives its creator
// attr_admin on it (and the tenant's default privileges to everyone). 409
// name_taken for a definition of the same name in the folder, 409
// folder_mirrored, 404 for an unknown folder, 422 for an invalid field.
func CreateDef(e Env, in DefInput) (*store.GrpAttrDef, error) {
	if in.AttrType == "" {
		in.AttrType = store.AttrTypeAttr
	}
	if in.ValueType == "" {
		in.ValueType = store.AttrValueMarker
	}
	switch {
	case !slices.Contains(AttrTypes, in.AttrType):
		return nil, invalid("invalid_attr_type", "attr_type is one of %v", AttrTypes)
	case !slices.Contains(ValueTypes, in.ValueType):
		return nil, invalid("invalid_value_type", "value_type is one of %v", ValueTypes)
	case in.ValueType == store.AttrValueMarker && in.MultiValued:
		return nil, invalid("invalid_multi_valued", "a marker attribute has no values")
	}
	assignTo, err := normalizeAssignTo(in.AssignTo)
	if err != nil {
		return nil, err
	}
	folder, err := writableFolder(e.Tx, in.Folder)
	if err != nil {
		return nil, err
	}
	name, err := naming.Join(folder.Name, in.Extension)
	if err != nil {
		return nil, wrap(err)
	}
	disp := in.DisplayExtension
	if disp == "" {
		disp = in.Extension
	}
	if err := errors.Join(wrap(naming.ValidateDisplay(disp)), checkText("description", in.Description, MaxDescription)); err != nil {
		return nil, firstErr(err)
	}
	if _, err := e.Tx.GrpAttrDefByExtension(folder.ID, in.Extension); err == nil {
		return nil, conflict("name_taken", "the attribute definition %q already exists", name)
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	d := &store.GrpAttrDef{FolderID: folder.ID, FolderName: folder.Name, Extension: in.Extension, DisplayExtension: disp,
		Description: in.Description, AttrType: in.AttrType, ValueType: in.ValueType, MultiAssign: in.MultiAssign,
		MultiValued: in.MultiValued, AssignTo: assignTo, System: in.System, CreatedAt: e.Now, CreatedBy: e.By}
	if err := e.Tx.InsertGrpAttrDef(d); err != nil {
		return nil, err
	}
	if err := e.Tx.InsertGrpAttrAction(&store.GrpAttrAction{DefID: d.ID, Name: DefaultAction, CreatedAt: e.Now}); err != nil {
		return nil, err
	}
	if err := privs.GrantCreator(e.privs(), privs.AttrDefObject(d.ID)); err != nil {
		return nil, err
	}
	return d, e.audit("groups.attr_def.created", "attr_def", d.ID, defDetail(d))
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

// DefUpdate changes a definition; nil fields are left alone. The types of a
// definition never change. Version, when set, must match (409 version_conflict).
type DefUpdate struct {
	DisplayExtension *string
	Description      *string
	MultiAssign      *bool
	MultiValued      *bool
	AssignTo         *[]string
	Version          *int64
}

// UpdateDef edits a definition. Narrowing it is refused while assignments need
// the wider form: single-assign while an owner has the same name twice,
// single-valued while an assignment has two values, and an assign_to without an
// owner type that has assignments. The built-in definition cannot be edited.
func UpdateDef(e Env, id string, in DefUpdate) (*store.GrpAttrDef, error) {
	d, err := Def(e.Tx, id)
	if err != nil {
		return nil, err
	}
	if in.Version != nil && *in.Version != d.Version {
		return nil, wrap(store.ErrVersionConflict)
	}
	if d.System {
		return nil, conflict("system_attr_def", "the built-in attribute definition %q cannot be changed", d.Name())
	}
	if _, err := writableFolder(e.Tx, d.FolderID); err != nil {
		return nil, err
	}
	before := *d
	if in.DisplayExtension != nil {
		d.DisplayExtension = *in.DisplayExtension
		if d.DisplayExtension == "" {
			d.DisplayExtension = d.Extension
		}
	}
	if in.Description != nil {
		d.Description = *in.Description
	}
	if in.MultiAssign != nil {
		d.MultiAssign = *in.MultiAssign
	}
	if in.MultiValued != nil {
		d.MultiValued = *in.MultiValued
	}
	if in.AssignTo != nil {
		if d.AssignTo, err = normalizeAssignTo(*in.AssignTo); err != nil {
			return nil, err
		}
	}
	if err := errors.Join(wrap(naming.ValidateDisplay(d.DisplayExtension)), checkText("description", d.Description, MaxDescription)); err != nil {
		return nil, firstErr(err)
	}
	if d.ValueType == store.AttrValueMarker && d.MultiValued {
		return nil, invalid("invalid_multi_valued", "a marker attribute has no values")
	}
	if err := e.checkNarrowing(&before, d); err != nil {
		return nil, err
	}
	if err := e.Tx.UpdateGrpAttrDef(d); err != nil {
		return nil, wrap(err)
	}
	return d, e.audit("groups.attr_def.updated", "attr_def", d.ID, defDetail(d))
}

// checkNarrowing refuses a change of flags that existing assignments contradict.
func (e Env) checkNarrowing(before, after *store.GrpAttrDef) error {
	narrowAssign := before.MultiAssign && !after.MultiAssign
	narrowValues := before.MultiValued && !after.MultiValued
	var dropped []string
	for _, t := range before.AssignTo {
		if !slices.Contains(after.AssignTo, t) {
			dropped = append(dropped, t)
		}
	}
	if !narrowAssign && !narrowValues && len(dropped) == 0 {
		return nil
	}
	seen := map[string]bool{}
	for off := 0; ; {
		rows, err := e.Tx.GrpAttrAssigns(store.GrpAttrAssignFilter{DefID: before.ID, Limit: 500, Offset: off})
		if err != nil {
			return err
		}
		for _, a := range rows {
			if slices.Contains(dropped, a.OwnerType) {
				return conflict("attr_def_in_use", "an assignment sits on a %s, which assign_to would no longer allow", a.OwnerType)
			}
			if narrowAssign {
				k := a.OwnerType + "/" + a.OwnerID + "/" + a.NameID + "/" + a.ActionID
				if seen[k] {
					return conflict("attr_def_in_use", "an owner has the same name assigned twice; remove one before making the definition single-assign")
				}
				seen[k] = true
			}
			if narrowValues {
				vs, err := e.Tx.GrpAttrValuesOf(a.ID)
				if err != nil {
					return err
				}
				if len(vs) > 1 {
					return conflict("attr_def_in_use", "an assignment has %d values; reduce it to one before making the definition single-valued", len(vs))
				}
			}
		}
		if len(rows) < 500 {
			return nil
		}
		off += len(rows)
	}
}

// DeleteDef removes a definition with its names, actions, closures and the
// assignments on it, and revokes the privileges held on it. It is refused (409
// attr_def_in_use) while any assignment of its names exists, and for the
// built-in definition.
func DeleteDef(e Env, id string) error {
	d, err := Def(e.Tx, id)
	if err != nil {
		return err
	}
	if d.System {
		return conflict("system_attr_def", "the built-in attribute definition %q cannot be deleted", d.Name())
	}
	if _, err := writableFolder(e.Tx, d.FolderID); err != nil {
		return err
	}
	n, err := e.Tx.GrpAttrAssignCount(d.ID, "", "")
	if err != nil {
		return err
	}
	if n > 0 {
		return withExtra(conflict("attr_def_in_use", "the definition still has %d assignment(s); remove them first", n), "assignments", n)
	}
	if _, err := RemoveAllOf(e, Owner{store.AttrOwnerAttrDef, d.ID}); err != nil {
		return err
	}
	if _, err := privs.RevokeAllOf(e.privs(), privs.AttrDefObject(d.ID)); err != nil {
		return err
	}
	for _, kind := range []string{store.ImpliesNames, store.ImpliesActions} {
		if err := e.Tx.ReplaceGrpAttrImplies(kind, d.ID, nil); err != nil {
			return err
		}
	}
	for off := 0; ; {
		names, err := e.Tx.GrpAttrNames(d.ID, "", 500, off)
		if err != nil {
			return err
		}
		for _, nm := range names {
			if err := e.Tx.DeleteGrpAttrName(nm.ID); err != nil {
				return err
			}
		}
		if len(names) < 500 {
			break
		}
	}
	actions, err := e.Tx.GrpAttrActionsOf(d.ID)
	if err != nil {
		return err
	}
	for _, a := range actions {
		if err := e.Tx.DeleteGrpAttrAction(a.ID); err != nil {
			return err
		}
	}
	if err := e.Tx.DeleteGrpAttrDef(d.ID); err != nil {
		return err
	}
	return e.audit("groups.attr_def.deleted", "attr_def", d.ID, defDetail(d))
}
