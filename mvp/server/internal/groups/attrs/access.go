package attrs

import (
	"errors"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Privileges of the attribute framework (design §7.1, §10.9). An attribute
// definition holds the eight attr_* privileges (GR-4 defines them and their
// implications; this file only asks them). An assignment is two-sided: the
// caller needs a privilege on the definition and one on the owner.
//
//	assign, change or unassign    attr_update on the definition, and on the owner:
//	                                folder      stem_attr_update
//	                                group       group_attr_update
//	                                membership  update on its group
//	                                attr_def    attr_def_attr_update on that definition
//	                                assignment  attr_update on that assignment's definition
//	                                identity    nothing more
//	read assignments              attr_read on the definition, and on the owner the
//	                              matching read privilege (stem_attr_read, group_attr_read,
//	                              read, attr_def_attr_read, attr_read)
//	a person on themselves        attr_optin (assign) or attr_optout (remove) on the
//	                              definition replaces both of the above when the owner is
//	                              the caller's own identity or one of its memberships
//	see a definition, its names   attr_view
//	edit a definition, its names, attr_admin
//	actions and their implications
//
// tenant_admin holds every privilege, auditor the read ones, viewer the view
// ones (privs.Subject).

// RequireView requires attr_view on the definition.
func RequireView(ck *privs.Checker, d *store.GrpAttrDef) error {
	return ck.Require(privs.AttrDefObject(d.ID), privs.AttrView)
}

// RequireAdmin requires attr_admin on the definition: editing or deleting it and
// its names and actions, and its privileges.
func RequireAdmin(ck *privs.Checker, d *store.GrpAttrDef) error {
	return ck.Require(privs.AttrDefObject(d.ID), privs.AttrAdmin)
}

// ownerSide is the object and privilege the owner asks for; ok is false when the
// owner type asks for none.
func ownerSide(tx *store.TenantTx, o Owner, write bool) (obj privs.Object, p privs.Privilege, ok bool, err error) {
	pick := func(w, r privs.Privilege) privs.Privilege {
		if write {
			return w
		}
		return r
	}
	switch o.Type {
	case store.AttrOwnerFolder:
		return privs.FolderObject(store.FolderID(o.ID)), pick(privs.StemAttrUpdate, privs.StemAttrRead), true, nil
	case store.AttrOwnerGroup:
		return privs.GroupObject(store.GroupID(o.ID)), pick(privs.GroupAttrUpdate, privs.GroupAttrRead), true, nil
	case store.AttrOwnerMembership:
		m, err := tx.GrpDirectMembership(o.ID)
		if errors.Is(err, store.ErrNotFound) {
			return obj, "", false, nil
		}
		if err != nil {
			return obj, "", false, err
		}
		return privs.GroupObject(m.GroupID), pick(privs.Update, privs.Read), true, nil
	case store.AttrOwnerAttrDef:
		return privs.AttrDefObject(o.ID), pick(privs.AttrDefAttrUpdate, privs.AttrDefAttrRead), true, nil
	case store.AttrOwnerAssignment:
		a, err := tx.GrpAttrAssign(o.ID)
		if errors.Is(err, store.ErrNotFound) {
			return obj, "", false, nil
		}
		if err != nil {
			return obj, "", false, err
		}
		return privs.AttrDefObject(a.DefID), pick(privs.AttrUpdate, privs.AttrRead), true, nil
	}
	return obj, "", false, nil // an identity has no object privileges
}

// ownedByCaller reports whether the owner is the caller's own identity or one
// of the caller's own direct memberships (the opt-in and opt-out cases).
func ownedByCaller(tx *store.TenantTx, ck *privs.Checker, o Owner) (bool, error) {
	me := ck.Subject().Identity
	if me == nil {
		return false, nil
	}
	switch o.Type {
	case store.AttrOwnerIdentity:
		id, err := parseID(o.ID)
		return err == nil && id == *me, nil
	case store.AttrOwnerMembership:
		m, err := tx.GrpDirectMembership(o.ID)
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}
		return err == nil && m.MemberIdentity != nil && *m.MemberIdentity == *me, err
	}
	return false, nil
}

func requireWrite(ck *privs.Checker, tx *store.TenantTx, d *store.GrpAttrDef, o Owner, self privs.Privilege) error {
	def := privs.AttrDefObject(d.ID)
	if self != "" {
		if mine, err := ownedByCaller(tx, ck, o); err != nil {
			return err
		} else if mine {
			if ok, err := ck.Has(def, self); err != nil {
				return err
			} else if ok {
				return nil
			}
		}
	}
	if err := ck.Require(def, privs.AttrUpdate); err != nil {
		return err
	}
	obj, p, ok, err := ownerSide(tx, o, true)
	if err != nil || !ok {
		return err
	}
	return ck.Require(obj, p)
}

// RequireAssign checks that the caller may assign the definition to the owner
// (or to themselves, with attr_optin). It returns a *privs.DeniedError.
func RequireAssign(ck *privs.Checker, tx *store.TenantTx, d *store.GrpAttrDef, o Owner) error {
	return requireWrite(ck, tx, d, o, privs.AttrOptin)
}

// RequireChange checks that the caller may change an assignment's dates or
// values: the assign requirement, without the opt-in route.
func RequireChange(ck *privs.Checker, tx *store.TenantTx, d *store.GrpAttrDef, o Owner) error {
	return requireWrite(ck, tx, d, o, "")
}

// RequireUnassign checks that the caller may remove an assignment (or remove it
// from themselves, with attr_optout).
func RequireUnassign(ck *privs.Checker, tx *store.TenantTx, d *store.GrpAttrDef, o Owner) error {
	return requireWrite(ck, tx, d, o, privs.AttrOptout)
}

// CanRead reports whether the caller may read the assignments of the definition
// on the owner.
func CanRead(ck *privs.Checker, tx *store.TenantTx, d *store.GrpAttrDef, o Owner) (bool, error) {
	ok, err := ck.Has(privs.AttrDefObject(d.ID), privs.AttrRead)
	if err != nil || !ok {
		return false, err
	}
	obj, p, side, err := ownerSide(tx, o, false)
	if err != nil || !side {
		return err == nil, err
	}
	return ck.Has(obj, p)
}

// RequireRead is CanRead as a *privs.DeniedError (naming the definition's
// attr_read first, then the owner's privilege).
func RequireRead(ck *privs.Checker, tx *store.TenantTx, d *store.GrpAttrDef, o Owner) error {
	if err := ck.Require(privs.AttrDefObject(d.ID), privs.AttrRead); err != nil {
		return err
	}
	obj, p, side, err := ownerSide(tx, o, false)
	if err != nil || !side {
		return err
	}
	return ck.Require(obj, p)
}
