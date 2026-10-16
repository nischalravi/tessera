package attrs

import (
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/pit"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Owner names what an assignment sits on. For an identity the id is its decimal
// text; for a membership it is the direct membership's id; for an assignment, the
// other assignment's id.
type Owner struct {
	Type string
	ID   string
}

// AssignByID returns an assignment or a not-found Error.
func AssignByID(tx *store.TenantTx, id string) (*store.GrpAttrAssign, error) {
	a, err := tx.GrpAttrAssign(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("no such attribute assignment")
	}
	return a, err
}

// OwnerOf is an assignment's owner.
func OwnerOf(a *store.GrpAttrAssign) Owner { return Owner{a.OwnerType, a.OwnerID} }

// Active reports whether the assignment counts at now: inside its dates and not
// a disallow.
func Active(a *store.GrpAttrAssign, now time.Time) bool {
	return !a.Disallowed && InDates(a, now)
}

// InDates reports whether now is inside the assignment's dates.
func InDates(a *store.GrpAttrAssign, now time.Time) bool {
	return (a.EnabledFrom == nil || !now.Before(*a.EnabledFrom)) && (a.DisabledAt == nil || now.Before(*a.DisabledAt))
}

// resolved is an owner that exists, with what the checks need to know about it.
type resolved struct {
	owner Owner
	// folder is the folder whose writer owns the owner, nil for an identity.
	folder *store.Folder
	// depth is the number of assignments in the owner's chain, itself included
	// when it is one.
	depth int
	// mirroredGroup names the group of the owner when that group is mirrored
	// from Grouper (K11), whatever its folder says.
	mirroredGroup string
}

// readOnly is the refusal of an owner whose writer is the Grouper mirror (K11).
func (r resolved) readOnly() error {
	if r.folder != nil && r.folder.ManagedBy == store.ManagedByGrouperMirror {
		return conflict("folder_mirrored", "folder %q is mirrored from Grouper and is read-only here", r.folder.Name)
	}
	if r.mirroredGroup != "" {
		return conflict("folder_mirrored", "group %q is mirrored from Grouper and is read-only here", r.mirroredGroup)
	}
	return nil
}

// resolveOwner checks that the owner exists (404 owner_not_found), is not a
// deleted group (409), and finds its folder and nesting depth.
func resolveOwner(tx *store.TenantTx, o Owner) (resolved, error) {
	r := resolved{owner: o}
	missing := func() error { return notFound("no such %s to assign to", o.Type) }
	folderOf := func(id store.FolderID) error {
		f, err := tx.GrpFolder(id)
		if errors.Is(err, store.ErrNotFound) {
			return missing()
		}
		r.folder = f
		return err
	}
	switch o.Type {
	case store.AttrOwnerFolder:
		if err := folderOf(store.FolderID(o.ID)); err != nil {
			return r, err
		}
	case store.AttrOwnerGroup, store.AttrOwnerMembership:
		gid := store.GroupID(o.ID)
		if o.Type == store.AttrOwnerMembership {
			m, err := tx.GrpDirectMembership(o.ID)
			if errors.Is(err, store.ErrNotFound) {
				return r, missing()
			}
			if err != nil {
				return r, err
			}
			gid = m.GroupID
		}
		g, err := tx.GrpGroup(gid)
		if errors.Is(err, store.ErrNotFound) {
			return r, missing()
		}
		if err != nil {
			return r, err
		}
		if g.Status == store.GroupDeleted {
			return r, conflict("group_deleted", "the group is deleted; restore it first")
		}
		if g.ManagedBy == store.ManagedByGrouperMirror {
			r.mirroredGroup = g.Name
		}
		if err := folderOf(g.FolderID); err != nil {
			return r, err
		}
	case store.AttrOwnerIdentity:
		id, err := parseID(o.ID)
		if err != nil {
			return r, missing()
		}
		if _, err := tx.Identity(id); errors.Is(err, store.ErrNotFound) {
			return r, missing()
		} else if err != nil {
			return r, err
		}
	case store.AttrOwnerAttrDef:
		d, err := tx.GrpAttrDef(o.ID)
		if errors.Is(err, store.ErrNotFound) {
			return r, missing()
		}
		if err != nil {
			return r, err
		}
		if err := folderOf(d.FolderID); err != nil {
			return r, err
		}
	case store.AttrOwnerAssignment:
		parent, err := tx.GrpAttrAssign(o.ID)
		if errors.Is(err, store.ErrNotFound) {
			return r, missing()
		}
		if err != nil {
			return r, err
		}
		up, err := resolveOwner(tx, OwnerOf(parent))
		if err != nil {
			return r, err
		}
		r.folder, r.depth, r.mirroredGroup = up.folder, up.depth+1, up.mirroredGroup
	default:
		return r, invalid("invalid_owner_type", "owner_type is one of %v", OwnerTypes)
	}
	return r, nil
}

func parseID(s string) (int64, error) {
	var n int64
	if s == "" || len(s) > 18 {
		return 0, errors.New("not an id")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("not an id")
		}
		n = n*10 + int64(c-'0')
	}
	return n, nil
}

// AssignInput is one assignment. Action is an action id of the name's definition
// ("" is its default action); Values are the raw JSON values, typed by the
// definition.
type AssignInput struct {
	Name        string
	Action      string
	Owner       Owner
	Disallowed  bool
	EnabledFrom *time.Time
	DisabledAt  *time.Time
	Values      []json.RawMessage
}

// Assigned is an assignment with its values.
type Assigned struct {
	Assign *store.GrpAttrAssign
	Values []*store.GrpAttrValue
}

func assignSnapshot(a *store.GrpAttrAssign, values []string) map[string]any {
	var from, to any
	if a.EnabledFrom != nil {
		from = store.RT(*a.EnabledFrom)
	}
	if a.DisabledAt != nil {
		to = store.RT(*a.DisabledAt)
	}
	return map[string]any{"assign_id": a.ID, "def_id": a.DefID, "name_id": a.NameID, "action_id": a.ActionID,
		"owner_type": a.OwnerType, "owner_id": a.OwnerID, "disallowed": a.Disallowed, "enabled_from": from,
		"disabled_at": to, "values": values}
}

// emit writes the change event of an assignment (design §10.1) in the
// caller's transaction.
func (e Env) emit(typ string, a *store.GrpAttrAssign, values []string) error {
	ev := events.New(typ, a.ID, e.Now, store.CauseAPI)
	ev.Data = events.Data(assignSnapshot(a, values))
	return pit.Emit(e.Tx, ev)
}

func assignDetail(a *store.GrpAttrAssign, values []string) ojson.Object {
	d := ojson.Object{{Key: "assign_id", Value: a.ID}, {Key: "def_id", Value: a.DefID}, {Key: "name_id", Value: a.NameID},
		{Key: "action_id", Value: a.ActionID}, {Key: "owner_type", Value: a.OwnerType}, {Key: "owner_id", Value: a.OwnerID},
		{Key: "disallowed", Value: a.Disallowed}, {Key: "values", Value: values}}
	if a.EnabledFrom != nil {
		d = append(d, ojson.KV{Key: "enabled_from", Value: store.RT(*a.EnabledFrom)})
	}
	if a.DisabledAt != nil {
		d = append(d, ojson.KV{Key: "disabled_at", Value: store.RT(*a.DisabledAt)})
	}
	return d
}

func checkDates(from, to *time.Time) error {
	if from != nil && to != nil && !to.After(*from) {
		return invalid("invalid_dates", "disabled_at must be after enabled_from")
	}
	return nil
}

// defaultAction finds a definition's default action.
func defaultAction(tx *store.TenantTx, def string) (*store.GrpAttrAction, error) {
	a, err := tx.GrpAttrActionByName(def, DefaultAction)
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("the definition has no %q action", DefaultAction)
	}
	return a, err
}

// Assign gives an owner an attribute name, with an action, dates and values.
//
// Rules: the owner must exist and be of a type the definition lists in
// assign_to (an effective membership is read-only and never is); a folder or
// group that is mirrored from Grouper refuses it (K11); an assignment on an
// assignment may go three deep; a single-assign definition takes one assignment
// of a name and action per owner (409 already_assigned); disallow is for perm
// definitions only; and the values fit the definition's type and limits.
func Assign(e Env, in AssignInput) (*Assigned, error) {
	name, err := Name(e.Tx, in.Name)
	if err != nil {
		return nil, err
	}
	d, err := Def(e.Tx, name.DefID)
	if err != nil {
		return nil, err
	}
	if in.Owner.Type == store.AttrOwnerEffectiveMembership {
		return nil, invalid("effective_membership_read_only",
			"an effective membership is derived from direct memberships and groups: assign to the direct membership instead")
	}
	if !slices.Contains(d.AssignTo, in.Owner.Type) {
		return nil, invalid("owner_type_not_allowed", "the attribute %q cannot be assigned to a %s (it allows %v)", d.Name(),
			in.Owner.Type, d.AssignTo)
	}
	own, err := resolveOwner(e.Tx, in.Owner)
	if err != nil {
		return nil, err
	}
	if err := own.readOnly(); err != nil {
		return nil, err
	}
	if own.depth+1 > MaxAssignDepth { // the new assignment is one level below its owner's chain
		return nil, invalid("assignment_too_deep", "an assignment may sit on at most %d levels of assignments", MaxAssignDepth)
	}
	if in.Disallowed && d.AttrType != store.AttrTypePerm {
		return nil, invalid("disallow_not_allowed", "only a perm attribute has disallowed assignments")
	}
	if err := checkDates(in.EnabledFrom, in.DisabledAt); err != nil {
		return nil, err
	}
	var action *store.GrpAttrAction
	if in.Action == "" {
		action, err = defaultAction(e.Tx, d.ID)
	} else if action, err = Action(e.Tx, in.Action); err == nil && action.DefID != d.ID {
		return nil, invalid("unknown_action", "the action is not one of %q", d.Name())
	}
	if err != nil {
		return nil, err
	}
	values, err := ParseValues(e.Tx, d, in.Values)
	if err != nil {
		return nil, err
	}
	if err := e.checkBuiltin(d, in.Owner, values); err != nil {
		return nil, err
	}
	if !d.MultiAssign {
		have, err := e.Tx.GrpAttrAssigns(store.GrpAttrAssignFilter{OwnerType: in.Owner.Type, OwnerID: in.Owner.ID, NameID: name.ID, Limit: 500})
		if err != nil {
			return nil, err
		}
		for _, h := range have {
			if h.ActionID == action.ID {
				return nil, withExtra(conflict("already_assigned", "the owner already has %q assigned", NameFullName(d, name)), "assignment", h.ID)
			}
		}
	}
	a := &store.GrpAttrAssign{DefID: d.ID, NameID: name.ID, ActionID: action.ID, OwnerType: in.Owner.Type, OwnerID: in.Owner.ID,
		Disallowed: in.Disallowed, EnabledFrom: in.EnabledFrom, DisabledAt: in.DisabledAt, CreatedAt: e.Now, CreatedBy: e.By}
	if err := e.Tx.InsertGrpAttrAssign(a); err != nil {
		return nil, err
	}
	if err := e.storeValues(a, values); err != nil {
		return nil, err
	}
	keys := Keys(values)
	if err := e.emit(events.AttributeAssigned, a, keys); err != nil {
		return nil, err
	}
	return &Assigned{a, values}, e.audit("groups.attr.assigned", "attr_assignment", a.ID, assignDetail(a, keys))
}

func (e Env) storeValues(a *store.GrpAttrAssign, values []*store.GrpAttrValue) error {
	for _, v := range values {
		v.AssignID, v.CreatedAt = a.ID, e.Now
		if err := e.Tx.InsertGrpAttrValue(v); err != nil {
			return err
		}
	}
	return nil
}

// AssignUpdate changes an assignment's flag and dates; nil leaves a field, and
// the Clear flags remove a date. Version, when set, must match.
type AssignUpdate struct {
	Disallowed       *bool
	EnabledFrom      *time.Time
	DisabledAt       *time.Time
	ClearEnabledFrom bool
	ClearDisabledAt  bool
	Version          *int64
}

// UpdateAssign edits an assignment's dates and disallow flag.
func UpdateAssign(e Env, id string, in AssignUpdate) (*Assigned, error) {
	a, d, err := e.writableAssign(id)
	if err != nil {
		return nil, err
	}
	if in.Version != nil && *in.Version != a.Version {
		return nil, wrap(store.ErrVersionConflict)
	}
	if in.Disallowed != nil {
		if *in.Disallowed && d.AttrType != store.AttrTypePerm {
			return nil, invalid("disallow_not_allowed", "only a perm attribute has disallowed assignments")
		}
		a.Disallowed = *in.Disallowed
	}
	if in.ClearEnabledFrom {
		a.EnabledFrom = nil
	}
	if in.EnabledFrom != nil {
		a.EnabledFrom = in.EnabledFrom
	}
	if in.ClearDisabledAt {
		a.DisabledAt = nil
	}
	if in.DisabledAt != nil {
		a.DisabledAt = in.DisabledAt
	}
	if err := checkDates(a.EnabledFrom, a.DisabledAt); err != nil {
		return nil, err
	}
	if err := e.Tx.UpdateGrpAttrAssign(a); err != nil {
		return nil, wrap(err)
	}
	values, err := e.Tx.GrpAttrValuesOf(a.ID)
	if err != nil {
		return nil, err
	}
	keys := Keys(values)
	if err := e.emit(events.AttributeValueChanged, a, keys); err != nil {
		return nil, err
	}
	return &Assigned{a, values}, e.audit("groups.attr.updated", "attr_assignment", a.ID, assignDetail(a, keys))
}

// SetValues replaces the values of an assignment.
func SetValues(e Env, id string, raws []json.RawMessage) (*Assigned, error) {
	a, d, err := e.writableAssign(id)
	if err != nil {
		return nil, err
	}
	values, err := ParseValues(e.Tx, d, raws)
	if err != nil {
		return nil, err
	}
	if err := e.checkBuiltin(d, OwnerOf(a), values); err != nil {
		return nil, err
	}
	if _, err := e.Tx.DeleteGrpAttrValuesOf(a.ID); err != nil {
		return nil, err
	}
	if err := e.storeValues(a, values); err != nil {
		return nil, err
	}
	keys := Keys(values)
	if err := e.emit(events.AttributeValueChanged, a, keys); err != nil {
		return nil, err
	}
	return &Assigned{a, values}, e.audit("groups.attr.values_set", "attr_assignment", a.ID, assignDetail(a, keys))
}

// writableAssign loads an assignment and its definition and refuses a change
// under a mirrored folder.
func (e Env) writableAssign(id string) (*store.GrpAttrAssign, *store.GrpAttrDef, error) {
	a, err := AssignByID(e.Tx, id)
	if err != nil {
		return nil, nil, err
	}
	d, err := Def(e.Tx, a.DefID)
	if err != nil {
		return nil, nil, err
	}
	if own, err := resolveOwner(e.Tx, OwnerOf(a)); err == nil {
		if err := own.readOnly(); err != nil {
			return nil, nil, err
		}
	}
	return a, d, nil
}

// Unassign removes an assignment, with its values and the assignments on it
// (deepest first). Each removal writes its change event and audit event. It
// returns the number of assignments removed.
func Unassign(e Env, id string) (int, error) {
	a, _, err := e.writableAssign(id)
	if err != nil {
		return 0, err
	}
	return e.remove(a, 0)
}

func (e Env) remove(a *store.GrpAttrAssign, depth int) (int, error) {
	if depth > MaxAssignDepth+1 {
		return 0, errors.New("attrs: assignment chain is deeper than the limit")
	}
	n, err := e.removeChildren(Owner{store.AttrOwnerAssignment, a.ID}, depth+1)
	if err != nil {
		return 0, err
	}
	values, err := e.Tx.GrpAttrValuesOf(a.ID)
	if err != nil {
		return 0, err
	}
	if _, err := e.Tx.DeleteGrpAttrValuesOf(a.ID); err != nil {
		return 0, err
	}
	if err := e.Tx.DeleteGrpAttrAssign(a.ID); err != nil {
		return 0, err
	}
	keys := Keys(values)
	if err := e.emit(events.AttributeRemoved, a, keys); err != nil {
		return 0, err
	}
	return n + 1, e.audit("groups.attr.removed", "attr_assignment", a.ID, assignDetail(a, keys))
}

func (e Env) removeChildren(o Owner, depth int) (int, error) {
	total := 0
	for {
		rows, err := e.Tx.GrpAttrAssigns(store.GrpAttrAssignFilter{OwnerType: o.Type, OwnerID: o.ID, Limit: 200})
		if err != nil {
			return 0, err
		}
		for _, a := range rows {
			n, err := e.remove(a, depth)
			if err != nil {
				return 0, err
			}
			total += n
		}
		if len(rows) < 200 {
			return total, nil
		}
	}
}

// RemoveAllOf removes every assignment that sits on the owner, and the
// assignments on those: an owner that is deleted (a folder, a definition, a
// direct membership) takes its attributes with it. Each removal writes its
// event, so the history shows when the attributes ended.
func RemoveAllOf(e Env, o Owner) (int, error) {
	return e.removeChildren(o, 0)
}

// EffectiveName is a name an owner has, by an assignment of it or of a name that
// implies it.
type EffectiveName struct {
	NameID string `json:"name_id"`
	// Via is the assignment that gives the name.
	Via string `json:"via"`
	// Implied is true when the name comes from an implication, not from an
	// assignment of the name itself.
	Implied bool `json:"implied"`
}

// Effective lists the names an owner has at now: those assigned to it (inside
// their dates, not disallowed) and every name they imply (G-44).
func Effective(tx *store.TenantTx, o Owner, now time.Time) ([]EffectiveName, error) {
	var out []EffectiveName
	seen := map[string]bool{}
	for off := 0; ; {
		rows, err := tx.GrpAttrAssigns(store.GrpAttrAssignFilter{OwnerType: o.Type, OwnerID: o.ID, Limit: 500, Offset: off})
		if err != nil {
			return nil, err
		}
		for _, a := range rows {
			if !Active(a, now) {
				continue
			}
			ids, err := EffectiveNameIDs(tx, a.NameID)
			if err != nil {
				return nil, err
			}
			for _, id := range ids {
				if !seen[id] {
					seen[id] = true
					out = append(out, EffectiveName{NameID: id, Via: a.ID, Implied: id != a.NameID})
				}
			}
		}
		if len(rows) < 500 {
			break
		}
		off += len(rows)
	}
	slices.SortFunc(out, func(a, b EffectiveName) int {
		switch {
		case a.NameID < b.NameID:
			return -1
		case a.NameID > b.NameID:
			return 1
		}
		return 0
	})
	return out, nil
}
