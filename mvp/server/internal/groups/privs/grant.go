package privs

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/pit"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Holder is who a privilege is granted to.
type Holder struct {
	Type     string // identity | group | everyone
	Identity int64
	Group    store.GroupID
}

// IdentityHolder, GroupHolder and Everyone build a Holder.
func IdentityHolder(id int64) Holder { return Holder{Type: store.HolderIdentity, Identity: id} }

// GroupHolder names a group: every effective member holds the privilege.
func GroupHolder(id store.GroupID) Holder { return Holder{Type: store.HolderGroup, Group: id} }

// Everyone is every subject of the tenant.
func Everyone() Holder { return Holder{Type: store.HolderEveryone} }

// GrantInput is one grant. AppliesTo "" or "self" puts the privilege on the
// object itself; "groups", "folders" or "attr_defs" (on a folder) makes it
// inherited by those objects below the folder, Scope one for its children and
// sub for everything below.
type GrantInput struct {
	Object    Object
	Privilege Privilege
	Holder    Holder
	AppliesTo string
	Scope     string
	Source    string // default api
}

// snapshot is what the PIT keeps of a privilege row.
func snapshot(r *store.GrpPrivilege) json.RawMessage {
	return events.Data(map[string]any{"id": r.ID, "object_type": r.ObjectType, "object_id": r.ObjectID,
		"privilege": r.Privilege, "holder_type": r.HolderType, "holder_identity_id": r.HolderIdentity,
		"holder_group_id": r.HolderGroup, "applies_to": r.AppliesTo, "scope": r.Scope, "source": r.Source,
		"created_by": r.CreatedBy, "created_at": store.RT(r.CreatedAt)})
}

func (e Env) emit(typ string, r *store.GrpPrivilege) error {
	cause := e.Cause
	if cause == "" {
		cause = store.CauseAPI
	}
	ev := events.New(typ, r.ID, e.Now, cause)
	ev.CauseRef = e.CauseRef
	ev.Data = pit.ObjectData(snapshot(r), map[string]any{"privilege_id": r.ID})
	return pit.Emit(e.Tx, ev)
}

func rowDetail(r *store.GrpPrivilege) ojson.Object {
	d := ojson.Object{{Key: "privilege_id", Value: r.ID}, {Key: "object_type", Value: r.ObjectType},
		{Key: "object_id", Value: r.ObjectID}, {Key: "privilege", Value: r.Privilege},
		{Key: "holder_type", Value: r.HolderType}, {Key: "applies_to", Value: r.AppliesTo}, {Key: "scope", Value: r.Scope},
		{Key: "source", Value: r.Source}}
	switch {
	case r.HolderIdentity != nil:
		d = append(d, ojson.KV{Key: "holder_identity_id", Value: *r.HolderIdentity})
	case r.HolderGroup != nil:
		d = append(d, ojson.KV{Key: "holder_group_id", Value: string(*r.HolderGroup)})
	}
	return d
}

// folderOf returns the folder whose writer owns o: the folder itself, or a
// group's folder.
func (e Env) folderOf(o Object) (*store.Folder, error) {
	switch o.Type {
	case Folder:
		f, err := e.Tx.GrpFolder(store.FolderID(o.ID))
		if errors.Is(err, store.ErrNotFound) {
			return nil, notFound("no such folder")
		}
		return f, err
	case Group:
		g, err := e.Tx.GrpGroup(store.GroupID(o.ID))
		if errors.Is(err, store.ErrNotFound) {
			return nil, notFound("no such group")
		}
		if err != nil {
			return nil, err
		}
		if g.Status == store.GroupDeleted {
			return nil, conflict("group_deleted", "the group is deleted; restore it first")
		}
		f, err := e.Tx.GrpFolder(g.FolderID)
		if errors.Is(err, store.ErrNotFound) {
			return nil, notFound("no such folder")
		}
		return f, err
	case AttrDef:
		d, err := e.Tx.GrpAttrDef(o.ID)
		if errors.Is(err, store.ErrNotFound) {
			return nil, notFound("no such attribute definition")
		}
		if err != nil {
			return nil, err
		}
		f, err := e.Tx.GrpFolder(d.FolderID)
		if errors.Is(err, store.ErrNotFound) {
			return nil, notFound("no such folder")
		}
		return f, err
	}
	return nil, invalid("invalid_object", "privileges are granted on folders, groups and attribute definitions")
}

// Grant gives the holder a privilege. It returns the row and whether it was
// created: repeating an existing grant returns that row. The privilege row, its
// change event and its audit event are written in the caller's transaction.
//
// Rules: the privilege must belong to the object's type (or, for an inherited
// row, to the type it applies to); a mirrored folder refuses grants (K11);
// the holder must exist; and granting to everyone needs the tenant_admin role
// and a privilege the tenant's everyone policy allows.
func Grant(e Env, in GrantInput) (*store.GrpPrivilege, bool, error) {
	if in.AppliesTo == "" {
		in.AppliesTo = "self"
	}
	if in.Scope == "" {
		in.Scope = "sub"
		if in.AppliesTo == "self" {
			in.Scope = "self"
		}
	}
	if in.Source == "" {
		in.Source = store.PrivSourceAPI
	}
	if !Valid(in.Privilege) {
		return nil, false, invalid("invalid_privilege", "%q is not a privilege", in.Privilege)
	}
	switch in.AppliesTo {
	case "self":
		if in.Scope != "self" {
			return nil, false, invalid("invalid_scope", "a privilege on the object itself has scope self")
		}
		if ObjectOf(in.Privilege) != in.Object.Type {
			return nil, false, invalid("invalid_privilege", "%s is not a %s privilege", in.Privilege, in.Object.Type)
		}
	case "groups", "folders", "attr_defs":
		if in.Object.Type != Folder {
			return nil, false, invalid("invalid_applies_to", "only a folder's privileges are inherited")
		}
		if in.Scope != "one" && in.Scope != "sub" {
			return nil, false, invalid("invalid_scope", "scope is one or sub for an inherited privilege")
		}
		if ObjectOf(in.Privilege).AppliesTo() != in.AppliesTo {
			return nil, false, invalid("invalid_privilege", "%s cannot be inherited by %s", in.Privilege, in.AppliesTo)
		}
	default:
		return nil, false, invalid("invalid_applies_to", "applies_to is self, groups, folders or attr_defs")
	}
	f, err := e.folderOf(in.Object)
	if err != nil {
		return nil, false, err
	}
	if f.ManagedBy == store.ManagedByGrouperMirror && in.Source != store.PrivSourceGrouperImport {
		return nil, false, conflict("folder_mirrored", "folder %q is mirrored from Grouper and is read-only here", f.Name)
	}
	row := &store.GrpPrivilege{ObjectType: string(in.Object.Type), ObjectID: in.Object.ID, Privilege: string(in.Privilege),
		HolderType: in.Holder.Type, AppliesTo: in.AppliesTo, Scope: in.Scope, Source: in.Source, CreatedBy: e.By, CreatedAt: e.Now}
	switch in.Holder.Type {
	case store.HolderIdentity:
		if _, err := e.Tx.Identity(in.Holder.Identity); errors.Is(err, store.ErrNotFound) {
			return nil, false, notFound("no such identity")
		} else if err != nil {
			return nil, false, err
		}
		id := in.Holder.Identity
		row.HolderIdentity = &id
	case store.HolderGroup:
		g, err := e.Tx.GrpGroup(in.Holder.Group)
		if errors.Is(err, store.ErrNotFound) {
			return nil, false, notFound("no such group")
		}
		if err != nil {
			return nil, false, err
		}
		if g.Status == store.GroupDeleted {
			return nil, false, conflict("group_deleted", "the holder group is deleted")
		}
		gid := g.ID
		row.HolderGroup = &gid
	case store.HolderEveryone:
		if in.Source != store.PrivSourceCreatorDefault && !e.TenantAdmin {
			return nil, false, forbidden("everyone_requires_tenant_admin", "only a tenant admin grants a privilege to everyone")
		}
		s, err := LoadSettings(e.Tx)
		if err != nil {
			return nil, false, err
		}
		if !s.Allowed(in.Privilege) {
			return nil, false, invalid("everyone_not_allowed", "the tenant's everyone policy does not allow %s to be granted to everyone", in.Privilege)
		}
	default:
		return nil, false, invalid("invalid_holder", "holder is an identity, a group or everyone")
	}
	if have, err := e.Tx.FindGrpPrivilege(row); err == nil {
		return have, false, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, false, err
	}
	if err := e.Tx.InsertGrpPrivilege(row); err != nil {
		return nil, false, err
	}
	if err := e.emit(events.PrivilegeGranted, row); err != nil {
		return nil, false, err
	}
	return row, true, e.audit("groups.privilege.granted", "group_privilege", row.ID, rowDetail(row))
}

// Revoke removes a privilege row (not found if this tenant has no such row).
// The change event and the audit event are written in the same transaction.
func Revoke(e Env, id string) (*store.GrpPrivilege, error) {
	row, err := e.Tx.GrpPrivilege(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("no such privilege")
	}
	if err != nil {
		return nil, err
	}
	if f, err := e.folderOfRow(row); err == nil && f != nil &&
		f.ManagedBy == store.ManagedByGrouperMirror && row.Source != store.PrivSourceGrouperImport {
		return nil, conflict("folder_mirrored", "folder %q is mirrored from Grouper and is read-only here", f.Name)
	}
	if err := e.Tx.DeleteGrpPrivilege(id); err != nil {
		return nil, err
	}
	if err := e.emit(events.PrivilegeRevoked, row); err != nil {
		return nil, err
	}
	return row, e.audit("groups.privilege.revoked", "group_privilege", row.ID, rowDetail(row))
}

// folderOfRow is the folder that owns a row's object (nil if it has none).
func (e Env) folderOfRow(r *store.GrpPrivilege) (*store.Folder, error) {
	switch ObjectType(r.ObjectType) {
	case Folder:
		return e.Tx.GrpFolder(store.FolderID(r.ObjectID))
	case Group:
		g, err := e.Tx.GrpGroup(store.GroupID(r.ObjectID))
		if err != nil {
			return nil, err
		}
		return e.Tx.GrpFolder(g.FolderID)
	case AttrDef:
		d, err := e.Tx.GrpAttrDef(r.ObjectID)
		if err != nil {
			return nil, err
		}
		return e.Tx.GrpFolder(d.FolderID)
	}
	return nil, nil
}

// RevokeAllOf removes every row that sits on the object: a deleted folder takes
// its privileges with it. Each removal writes its event, so the history shows
// when the privileges ended.
func RevokeAllOf(e Env, o Object) (int, error) {
	rows, err := e.Tx.GrpPrivilegesOf(string(o.Type), o.ID)
	if err != nil {
		return 0, err
	}
	for _, r := range rows {
		if err := e.Tx.DeleteGrpPrivilege(r.ID); err != nil {
			return 0, err
		}
		if err := e.emit(events.PrivilegeRevoked, r); err != nil {
			return 0, err
		}
		if err := e.audit("groups.privilege.revoked", "group_privilege", r.ID, append(rowDetail(r),
			ojson.KV{Key: "reason", Value: "object_deleted"})); err != nil {
			return 0, err
		}
	}
	return len(rows), nil
}

// RevokeAllHeldBy removes every row that names the group as its holder: a
// purged group can no longer hold a privilege. Each removal writes its event.
func RevokeAllHeldBy(e Env, g store.GroupID) (int, error) {
	rows, err := e.Tx.GrpPrivilegesOfHolderGroup(g)
	if err != nil {
		return 0, err
	}
	for _, r := range rows {
		if err := e.Tx.DeleteGrpPrivilege(r.ID); err != nil {
			return 0, err
		}
		if err := e.emit(events.PrivilegeRevoked, r); err != nil {
			return 0, err
		}
		if err := e.audit("groups.privilege.revoked", "group_privilege", r.ID, append(rowDetail(r),
			ojson.KV{Key: "reason", Value: "holder_purged"})); err != nil {
			return 0, err
		}
	}
	return len(rows), nil
}

// creatorPrivilege is what the creator of an object is given: admin of a group,
// stem_admin of a folder, attr_admin of an attribute definition (Grouper's
// creator privileges, G-40).
var creatorPrivilege = map[ObjectType]Privilege{Group: Admin, Folder: StemAdmin, AttrDef: AttrAdmin}

// GrantCreator makes the creator of a new folder or group its admin and grants
// the tenant's default privileges (settings.Defaults) to everyone. The creator
// is the acting user's identity; a user without an identity link (and a machine
// client) gets no row, and a tenant_admin needs none.
func GrantCreator(e Env, o Object) error {
	if p, ok := creatorPrivilege[o.Type]; ok && e.ByIdentity != nil {
		if _, _, err := Grant(e, GrantInput{Object: o, Privilege: p, Holder: IdentityHolder(*e.ByIdentity),
			Source: store.PrivSourceCreatorDefault}); err != nil {
			return fmt.Errorf("privs: creator privilege: %w", err)
		}
	}
	return GrantDefaults(e, o)
}

// GrantDefaults grants the tenant's default privileges to everyone on a new
// object. Defaults the everyone policy no longer allows are skipped.
func GrantDefaults(e Env, o Object) error {
	s, err := LoadSettings(e.Tx)
	if err != nil {
		return err
	}
	for _, d := range s.Defaults {
		if d.ObjectType != o.Type || !s.Allowed(d.Privilege) {
			continue
		}
		if _, _, err := Grant(e, GrantInput{Object: o, Privilege: d.Privilege, Holder: Everyone(),
			Source: store.PrivSourceCreatorDefault}); err != nil {
			return fmt.Errorf("privs: default privilege: %w", err)
		}
	}
	return nil
}
