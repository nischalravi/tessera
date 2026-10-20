package attrs

import (
	"encoding/json"
	"errors"
	"slices"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/naming"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Object types (G-05, design §10.9): the built-in attribute definition
// etc:objectTypes, whose one name etc:objectTypes:objectType carries the types of
// a folder or group as string values. They drive the UI badges and the lint
// rules (lint.go). The vocabulary is the Deployment Guide's, split by what the
// type describes: a group is a ref, basis, policy, bundle, manual or
// intermediate group, and a folder an etc, org, test, service, app or security
// folder.
//
// data_owner and member_description, which the design lists beside the types,
// are columns of the folder and group (GR-1), so they have no attribute name here.

// Names of the built-in definition.
const (
	ObjectTypesFolder = "etc"
	ObjectTypesDef    = "objectTypes"
	ObjectTypeName    = "objectType"
	// ObjectTypesFullName is the definition's full name.
	ObjectTypesFullName = ObjectTypesFolder + naming.Sep + ObjectTypesDef
)

// Object types of a group and of a folder.
var (
	GroupObjectTypes  = []string{"ref", "basis", "policy", "bundle", "manual", "intermediate"}
	FolderObjectTypes = []string{"etc", "org", "test", "service", "app", "security"}
)

// The types lint and services read.
const (
	TypePolicy  = "policy"
	TypeBundle  = "bundle"
	TypeService = "service"
)

// ObjectTypeVocabulary lists the object types an owner of the type may have (nil
// for an owner type that has none).
func ObjectTypeVocabulary(ownerType string) []string {
	switch ownerType {
	case store.AttrOwnerGroup:
		return slices.Clone(GroupObjectTypes)
	case store.AttrOwnerFolder:
		return slices.Clone(FolderObjectTypes)
	}
	return nil
}

// IsBuiltin reports whether the definition is the object types definition.
func IsBuiltin(d *store.GrpAttrDef) bool {
	return d.System && d.Extension == ObjectTypesDef && d.FolderName == ObjectTypesFolder
}

// checkBuiltin applies the object types vocabulary to the values of an
// assignment of the built-in definition.
func (e Env) checkBuiltin(d *store.GrpAttrDef, o Owner, values []*store.GrpAttrValue) error {
	if !IsBuiltin(d) {
		return nil
	}
	vocab := ObjectTypeVocabulary(o.Type)
	for _, v := range values {
		if v.ValueString == nil || !slices.Contains(vocab, *v.ValueString) {
			return invalid("invalid_object_type", "an object type of a %s is one of %v", o.Type, vocab)
		}
	}
	return nil
}

// Builtin returns the object types definition and its name, or nil, nil while the
// tenant has not created them (the first change of an object type does).
func Builtin(tx *store.TenantTx) (*store.GrpAttrDef, *store.GrpAttrName, error) {
	f, err := tx.GrpFolderByName(ObjectTypesFolder)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	d, err := tx.GrpAttrDefByExtension(f.ID, ObjectTypesDef)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if !d.System {
		return nil, nil, conflict("object_types_unavailable", "%s exists and is not the built-in definition", ObjectTypesFullName)
	}
	n, err := tx.GrpAttrNameByExtension(d.ID, ObjectTypeName)
	if errors.Is(err, store.ErrNotFound) {
		return d, nil, nil
	}
	return d, n, err
}

// CreateBuiltin creates the object types definition and its name in the folder
// (the model layer makes the etc folder and calls this). It is idempotent. The
// definition has no creator privileges: the caller sets ByIdentity to nil.
func CreateBuiltin(e Env, folder store.FolderID) (*store.GrpAttrDef, *store.GrpAttrName, error) {
	d, n, err := Builtin(e.Tx)
	if err != nil {
		return nil, nil, err
	}
	if d == nil {
		d, err = CreateDef(e, DefInput{Folder: folder, Extension: ObjectTypesDef, DisplayExtension: ObjectTypesDef,
			Description: "Object types of folders and groups (drives badges and lint rules)", AttrType: store.AttrTypeType,
			ValueType: store.AttrValueString, MultiValued: true,
			AssignTo: []string{store.AttrOwnerFolder, store.AttrOwnerGroup}, System: true})
		if err != nil {
			return nil, nil, err
		}
	}
	if n == nil {
		n, err = CreateName(e, NameInput{Def: d.ID, Extension: ObjectTypeName, Description: "The object type"})
		if err != nil {
			return nil, nil, err
		}
	}
	return d, n, nil
}

// ObjectTypesOf returns the object types of a folder or group, in vocabulary
// order (none before the built-in definition exists).
func ObjectTypesOf(tx *store.TenantTx, o Owner) ([]string, error) {
	_, n, err := Builtin(tx)
	if err != nil || n == nil {
		return nil, err
	}
	as, err := tx.GrpAttrAssigns(store.GrpAttrAssignFilter{OwnerType: o.Type, OwnerID: o.ID, NameID: n.ID, Limit: 1})
	if err != nil || len(as) == 0 {
		return nil, err
	}
	vs, err := tx.GrpAttrValuesOf(as[0].ID)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, v := range vs {
		if v.ValueString != nil {
			out = append(out, *v.ValueString)
		}
	}
	vocab := ObjectTypeVocabulary(o.Type)
	slices.SortFunc(out, func(a, b string) int { return slices.Index(vocab, a) - slices.Index(vocab, b) })
	return out, nil
}

// SetObjectTypes replaces the object types of a folder or group. The built-in
// definition must exist (CreateBuiltin). An empty list removes the assignment.
// It reports whether anything changed.
func SetObjectTypes(e Env, o Owner, types []string) (bool, error) {
	vocab := ObjectTypeVocabulary(o.Type)
	if vocab == nil {
		return false, invalid("invalid_owner_type", "object types are for folders and groups")
	}
	var want []string
	for _, t := range types {
		if !slices.Contains(vocab, t) {
			return false, invalid("invalid_object_type", "an object type of a %s is one of %v", o.Type, vocab)
		}
		if !slices.Contains(want, t) {
			want = append(want, t)
		}
	}
	slices.SortFunc(want, func(a, b string) int { return slices.Index(vocab, a) - slices.Index(vocab, b) })
	_, n, err := Builtin(e.Tx)
	if err != nil {
		return false, err
	}
	if n == nil {
		return false, conflict("object_types_unavailable", "the built-in object types definition has not been created")
	}
	have, err := ObjectTypesOf(e.Tx, o)
	if err != nil {
		return false, err
	}
	if slices.Equal(have, want) || (len(have) == 0 && len(want) == 0) {
		return false, nil
	}
	existing, err := e.Tx.GrpAttrAssigns(store.GrpAttrAssignFilter{OwnerType: o.Type, OwnerID: o.ID, NameID: n.ID, Limit: 1})
	if err != nil {
		return false, err
	}
	raws := make([]json.RawMessage, len(want))
	for i, t := range want {
		raws[i], _ = json.Marshal(t) // a string always marshals
	}
	switch {
	case len(want) == 0:
		_, err = Unassign(e, existing[0].ID)
	case len(existing) == 0:
		_, err = Assign(e, AssignInput{Name: n.ID, Owner: o, Values: raws})
	default:
		_, err = SetValues(e, existing[0].ID, raws)
	}
	return err == nil, err
}
