package attrs

import (
	"errors"
	"slices"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/naming"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// nameIDs lists the ids of a definition's names.
func nameIDs(tx *store.TenantTx, def string) (map[string]bool, error) {
	out := map[string]bool{}
	for off := 0; ; {
		rows, err := tx.GrpAttrNames(def, "", 500, off)
		if err != nil {
			return nil, err
		}
		for _, n := range rows {
			out[n.ID] = true
		}
		if len(rows) < 500 {
			return out, nil
		}
		off += len(rows)
	}
}

// NameByFullName finds an attribute name by its full name
// ("etc:objectTypes:objectType").
func NameByFullName(tx *store.TenantTx, full string) (*store.GrpAttrName, error) {
	parent, ext := naming.Split(full)
	if parent == "" {
		return nil, notFound("no such attribute name")
	}
	d, err := DefByName(tx, parent)
	if err != nil {
		return nil, err
	}
	n, err := tx.GrpAttrNameByExtension(d.ID, ext)
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("no such attribute name")
	}
	return n, err
}

// NameInput creates a name under a definition.
type NameInput struct {
	Def              string
	Extension        string
	DisplayExtension string
	Description      string
}

func nameDetail(d *store.GrpAttrDef, n *store.GrpAttrName) ojson.Object {
	return ojson.Object{{Key: "name_id", Value: n.ID}, {Key: "def_id", Value: d.ID}, {Key: "name", Value: NameFullName(d, n)}}
}

// CreateName adds a name to a definition. 409 name_taken for a name of the same
// extension under the definition, 409 folder_mirrored, 422 for an invalid field.
func CreateName(e Env, in NameInput) (*store.GrpAttrName, error) {
	d, err := Def(e.Tx, in.Def)
	if err != nil {
		return nil, err
	}
	if _, err := writableFolder(e.Tx, d.FolderID); err != nil {
		return nil, err
	}
	if _, err := naming.Join(d.Name(), in.Extension); err != nil {
		return nil, wrap(err)
	}
	disp := in.DisplayExtension
	if disp == "" {
		disp = in.Extension
	}
	if err := errors.Join(wrap(naming.ValidateDisplay(disp)), checkText("description", in.Description, MaxDescription)); err != nil {
		return nil, firstErr(err)
	}
	if _, err := e.Tx.GrpAttrNameByExtension(d.ID, in.Extension); err == nil {
		return nil, conflict("name_taken", "the attribute name %q already exists", d.Name()+naming.Sep+in.Extension)
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	n := &store.GrpAttrName{DefID: d.ID, Extension: in.Extension, DisplayExtension: disp, Description: in.Description,
		CreatedAt: e.Now, CreatedBy: e.By}
	if err := e.Tx.InsertGrpAttrName(n); err != nil {
		return nil, err
	}
	return n, e.audit("groups.attr_name.created", "attr_name", n.ID, nameDetail(d, n))
}

// UpdateName edits a name's display name and description (nil leaves a field).
func UpdateName(e Env, id string, display, description *string) (*store.GrpAttrName, error) {
	n, err := Name(e.Tx, id)
	if err != nil {
		return nil, err
	}
	d, err := Def(e.Tx, n.DefID)
	if err != nil {
		return nil, err
	}
	if _, err := writableFolder(e.Tx, d.FolderID); err != nil {
		return nil, err
	}
	if display != nil {
		n.DisplayExtension = *display
		if n.DisplayExtension == "" {
			n.DisplayExtension = n.Extension
		}
	}
	if description != nil {
		n.Description = *description
	}
	if err := errors.Join(wrap(naming.ValidateDisplay(n.DisplayExtension)), checkText("description", n.Description, MaxDescription)); err != nil {
		return nil, firstErr(err)
	}
	if err := e.Tx.UpdateGrpAttrName(n); err != nil {
		return nil, err
	}
	return n, e.audit("groups.attr_name.updated", "attr_name", n.ID, nameDetail(d, n))
}

// SetNameImplies makes the name directly imply exactly the names given (all of
// its definition's) and rebuilds the definition's closure. 409 cycle with the
// path when an implication would loop.
func SetNameImplies(e Env, id string, implied []string) (*store.GrpAttrName, error) {
	n, err := Name(e.Tx, id)
	if err != nil {
		return nil, err
	}
	d, err := Def(e.Tx, n.DefID)
	if err != nil {
		return nil, err
	}
	if _, err := writableFolder(e.Tx, d.FolderID); err != nil {
		return nil, err
	}
	members, err := nameIDs(e.Tx, d.ID)
	if err != nil {
		return nil, err
	}
	if err := e.setEdges(store.ImpliesNames, d.ID, n.ID, implied, members); err != nil {
		return nil, err
	}
	direct, all, err := Implied(e.Tx, store.ImpliesNames, n.ID)
	if err != nil {
		return nil, err
	}
	return n, e.audit("groups.attr_name.implies_changed", "attr_name", n.ID,
		append(nameDetail(d, n), ojson.KV{Key: "implies", Value: direct}, ojson.KV{Key: "closure_size", Value: len(all)}))
}

// DeleteName removes a name and its implication rows. 409 attr_name_in_use
// while an assignment of the name exists.
func DeleteName(e Env, id string) error {
	n, err := Name(e.Tx, id)
	if err != nil {
		return err
	}
	d, err := Def(e.Tx, n.DefID)
	if err != nil {
		return err
	}
	if d.System {
		return conflict("system_attr_def", "the names of the built-in attribute definition %q cannot be deleted", d.Name())
	}
	if _, err := writableFolder(e.Tx, d.FolderID); err != nil {
		return err
	}
	cnt, err := e.Tx.GrpAttrAssignCount("", n.ID, "")
	if err != nil {
		return err
	}
	if cnt > 0 {
		return withExtra(conflict("attr_name_in_use", "the name still has %d assignment(s); remove them first", cnt), "assignments", cnt)
	}
	if err := e.dropNode(store.ImpliesNames, d.ID, n.ID); err != nil {
		return err
	}
	if err := e.Tx.DeleteGrpAttrName(n.ID); err != nil {
		return err
	}
	return e.audit("groups.attr_name.deleted", "attr_name", n.ID, nameDetail(d, n))
}

// EffectiveNameIDs returns the names an assignment of name gives: the name and
// every name it implies, sorted.
func EffectiveNameIDs(tx *store.TenantTx, name string) ([]string, error) {
	_, all, err := Implied(tx, store.ImpliesNames, name)
	if err != nil {
		return nil, err
	}
	out := append([]string{name}, all...)
	slices.Sort(out)
	return out, nil
}
