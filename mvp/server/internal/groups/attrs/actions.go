package attrs

import (
	"errors"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/naming"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func actionDetail(d *store.GrpAttrDef, a *store.GrpAttrAction) ojson.Object {
	return ojson.Object{{Key: "action_id", Value: a.ID}, {Key: "def_id", Value: d.ID}, {Key: "def", Value: d.Name()},
		{Key: "action", Value: a.Name}}
}

func actionIDs(tx *store.TenantTx, def string) (map[string]bool, error) {
	rows, err := tx.GrpAttrActionsOf(def)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(rows))
	for _, a := range rows {
		out[a.ID] = true
	}
	return out, nil
}

// CreateAction adds an action (G-45) to a definition. 409 name_taken for the
// same name in the definition, 409 folder_mirrored, 422 for an invalid name
// (1 to 64 characters from [A-Za-z0-9_.-]).
func CreateAction(e Env, def, name, description string) (*store.GrpAttrAction, error) {
	d, err := Def(e.Tx, def)
	if err != nil {
		return nil, err
	}
	if _, err := writableFolder(e.Tx, d.FolderID); err != nil {
		return nil, err
	}
	if err := naming.ValidateExtension(name); err != nil {
		return nil, wrap(err)
	}
	if len(name) > maxActionName {
		return nil, invalid("invalid_name", "an action name is at most %d characters", maxActionName)
	}
	if err := checkText("description", description, MaxDescription); err != nil {
		return nil, err
	}
	if _, err := e.Tx.GrpAttrActionByName(d.ID, name); err == nil {
		return nil, conflict("name_taken", "the action %q already exists on %q", name, d.Name())
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	a := &store.GrpAttrAction{DefID: d.ID, Name: name, Description: description, CreatedAt: e.Now}
	if err := e.Tx.InsertGrpAttrAction(a); err != nil {
		return nil, err
	}
	return a, e.audit("groups.attr_action.created", "attr_action", a.ID, actionDetail(d, a))
}

// SetActionImplies makes the action directly imply exactly the actions given
// (all of its definition's) and rebuilds the definition's action closure.
func SetActionImplies(e Env, id string, implied []string) (*store.GrpAttrAction, error) {
	a, err := Action(e.Tx, id)
	if err != nil {
		return nil, err
	}
	d, err := Def(e.Tx, a.DefID)
	if err != nil {
		return nil, err
	}
	if _, err := writableFolder(e.Tx, d.FolderID); err != nil {
		return nil, err
	}
	members, err := actionIDs(e.Tx, d.ID)
	if err != nil {
		return nil, err
	}
	if err := e.setEdges(store.ImpliesActions, d.ID, a.ID, implied, members); err != nil {
		return nil, err
	}
	direct, all, err := Implied(e.Tx, store.ImpliesActions, a.ID)
	if err != nil {
		return nil, err
	}
	return a, e.audit("groups.attr_action.implies_changed", "attr_action", a.ID,
		append(actionDetail(d, a), ojson.KV{Key: "implies", Value: direct}, ojson.KV{Key: "closure_size", Value: len(all)}))
}

// DeleteAction removes an action and its implication rows. The default action
// stays (409 default_action), and 409 attr_action_in_use while an assignment
// uses the action.
func DeleteAction(e Env, id string) error {
	a, err := Action(e.Tx, id)
	if err != nil {
		return err
	}
	d, err := Def(e.Tx, a.DefID)
	if err != nil {
		return err
	}
	if _, err := writableFolder(e.Tx, d.FolderID); err != nil {
		return err
	}
	if a.Name == DefaultAction {
		return conflict("default_action", "the %q action of a definition cannot be deleted", DefaultAction)
	}
	n, err := e.Tx.GrpAttrAssignCount("", "", a.ID)
	if err != nil {
		return err
	}
	if n > 0 {
		return withExtra(conflict("attr_action_in_use", "the action still has %d assignment(s); remove them first", n), "assignments", n)
	}
	if err := e.dropNode(store.ImpliesActions, d.ID, a.ID); err != nil {
		return err
	}
	if err := e.Tx.DeleteGrpAttrAction(a.ID); err != nil {
		return err
	}
	return e.audit("groups.attr_action.deleted", "attr_action", a.ID, actionDetail(d, a))
}
