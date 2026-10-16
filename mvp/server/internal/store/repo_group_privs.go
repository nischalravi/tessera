package store

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// Group privilege repository (schema/0285_group_privs.sql, issue #47, GR-4).
// The rules of the privilege model live in internal/groups/privs; this file is
// only its statements, all bound to the transaction's tenant.

const privCols = `p.id, p.tenant_id, p.object_type, p.object_id, p.privilege, p.holder_type, p.holder_identity_id,
	p.holder_group_id, p.applies_to, p.scope, p.source, p.created_by, p.created_at`

var (
	grpPrivInsert = tq("grp_privileges.insert", `
		INSERT INTO grp_privileges (id, tenant_id, object_type, object_id, privilege, holder_type, holder_identity_id,
			holder_group_id, applies_to, scope, source, created_by, created_at)
		VALUES (@id, @tenant, @object_type, @object_id, @privilege, @holder_type, @holder_identity_id,
			@holder_group_id, @applies_to, @scope, @source, @created_by, @created_at)`)
	grpPrivGet = tq("grp_privileges.get", `SELECT `+privCols+` FROM grp_privileges p
		WHERE p.tenant_id = @tenant AND p.id = @id`)
	grpPrivOfObject = tq("grp_privileges.of_object", `SELECT `+privCols+` FROM grp_privileges p
		WHERE p.tenant_id = @tenant AND p.object_type = @object_type AND p.object_id = @object_id
		ORDER BY p.created_at, p.id`)
	// the one row a grant would repeat (the partial unique indexes of 0285)
	grpPrivFind = tq("grp_privileges.find", `SELECT `+privCols+` FROM grp_privileges p
		WHERE p.tenant_id = @tenant AND p.object_type = @object_type AND p.object_id = @object_id
		  AND p.privilege = @privilege AND p.applies_to = @applies_to AND p.scope = @scope
		  AND p.holder_type = @holder_type AND COALESCE(p.holder_identity_id, 0) = @holder_identity_id
		  AND COALESCE(p.holder_group_id, '') = @holder_group_id`)
	grpPrivDelete = tq("grp_privileges.delete", `DELETE FROM grp_privileges WHERE tenant_id = @tenant AND id = @id`)
	// the rows that name a group as their holder, so a group's privileges can be reviewed
	grpPrivOfHolderGroup = tq("grp_privileges.of_holder_group", `SELECT `+privCols+` FROM grp_privileges p
		WHERE p.tenant_id = @tenant AND p.holder_group_id = @holder_group_id ORDER BY p.created_at, p.id`)
	grpPrivOfHolderIdentity = tq("grp_privileges.of_holder_identity", `SELECT `+privCols+` FROM grp_privileges p
		WHERE p.tenant_id = @tenant AND p.holder_identity_id = @holder_identity_id ORDER BY p.created_at, p.id`)

	grpPrivSettingsGet = tq("grp_priv_settings.get", `SELECT s.body, s.updated_at, s.updated_by FROM grp_priv_settings s
		WHERE s.tenant_id = @tenant`)
	grpPrivSettingsSet = tq("grp_priv_settings.set", `
		INSERT INTO grp_priv_settings (tenant_id, body, updated_at, updated_by)
		VALUES (@tenant, @body, @updated_at, @updated_by)
		ON CONFLICT (tenant_id) DO UPDATE SET body = excluded.body, updated_at = excluded.updated_at, updated_by = excluded.updated_by`)

	usersSetIdentity = tq("platform_users.set_identity", `
		UPDATE platform_users SET identity_id = @identity_id WHERE tenant_id = @tenant AND id = @id`)
)

func scanGrpPriv(s scanner) (*GrpPrivilege, error) {
	var p GrpPrivilege
	var tenant, created string
	var ident sql.NullInt64
	var group, by sql.NullString
	if err := s.Scan(&p.ID, &tenant, &p.ObjectType, &p.ObjectID, &p.Privilege, &p.HolderType, &ident, &group, &p.AppliesTo,
		&p.Scope, &p.Source, &by, &created); err != nil {
		return nil, err
	}
	var err error
	if p.TenantID, err = tenantOf(tenant); err != nil {
		return nil, err
	}
	p.HolderIdentity, p.CreatedBy = intp(ident), strp(by)
	if group.Valid {
		g := GroupID(group.String)
		p.HolderGroup = &g
	}
	p.CreatedAt, err = ParseRT(created)
	return &p, err
}

// holderArgs are the two holder columns as the statements compare them: 0 and
// "" stand for NULL.
func holderArgs(p *GrpPrivilege) (identity int64, group string) {
	if p.HolderIdentity != nil {
		identity = *p.HolderIdentity
	}
	if p.HolderGroup != nil {
		group = string(*p.HolderGroup)
	}
	return identity, group
}

// InsertGrpPrivilege adds a privilege row (a zero ID gets a fresh one). Repeating
// an existing grant is a unique-index error: FindGrpPrivilege first.
func (tx *TenantTx) InsertGrpPrivilege(p *GrpPrivilege) error {
	if err := tx.own(p.TenantID); err != nil {
		return err
	}
	if p.ID == "" {
		p.ID = uuid.NewString()
	}
	var group any
	if p.HolderGroup != nil {
		group = string(*p.HolderGroup)
	}
	_, err := tx.exec(grpPrivInsert, sql.Named("id", p.ID), sql.Named("object_type", p.ObjectType),
		sql.Named("object_id", p.ObjectID), sql.Named("privilege", p.Privilege), sql.Named("holder_type", p.HolderType),
		sql.Named("holder_identity_id", IP(p.HolderIdentity)), sql.Named("holder_group_id", group),
		sql.Named("applies_to", p.AppliesTo), sql.Named("scope", p.Scope), sql.Named("source", p.Source),
		sql.Named("created_by", SP(p.CreatedBy)), sql.Named("created_at", RT(p.CreatedAt)))
	if err == nil {
		p.TenantID = tx.tenant
	}
	return err
}

// GrpPrivilege returns one privilege row or ErrNotFound.
func (tx *TenantTx) GrpPrivilege(id string) (*GrpPrivilege, error) {
	return one(tx, scanGrpPriv, grpPrivGet, sql.Named("id", id))
}

// GrpPrivilegesOf lists the rows that sit on one object, oldest first.
func (tx *TenantTx) GrpPrivilegesOf(objectType, objectID string) ([]*GrpPrivilege, error) {
	return collect(tx, scanGrpPriv, grpPrivOfObject, sql.Named("object_type", objectType), sql.Named("object_id", objectID))
}

// FindGrpPrivilege returns the row a grant like p would repeat, or ErrNotFound.
func (tx *TenantTx) FindGrpPrivilege(p *GrpPrivilege) (*GrpPrivilege, error) {
	identity, group := holderArgs(p)
	return one(tx, scanGrpPriv, grpPrivFind, sql.Named("object_type", p.ObjectType), sql.Named("object_id", p.ObjectID),
		sql.Named("privilege", p.Privilege), sql.Named("applies_to", p.AppliesTo), sql.Named("scope", p.Scope),
		sql.Named("holder_type", p.HolderType), sql.Named("holder_identity_id", identity), sql.Named("holder_group_id", group))
}

// DeleteGrpPrivilege removes one row (ErrNotFound if this tenant has none).
func (tx *TenantTx) DeleteGrpPrivilege(id string) error {
	return tx.execOne(grpPrivDelete, sql.Named("id", id))
}

// GrpPrivilegesOfHolderGroup lists the rows whose holder is the group.
func (tx *TenantTx) GrpPrivilegesOfHolderGroup(g GroupID) ([]*GrpPrivilege, error) {
	return collect(tx, scanGrpPriv, grpPrivOfHolderGroup, sql.Named("holder_group_id", string(g)))
}

// GrpPrivilegesOfHolderIdentity lists the rows whose holder is the identity.
func (tx *TenantTx) GrpPrivilegesOfHolderIdentity(identity int64) ([]*GrpPrivilege, error) {
	return collect(tx, scanGrpPriv, grpPrivOfHolderIdentity, sql.Named("holder_identity_id", identity))
}

// GrpPrivSettings returns the tenant's privilege settings, or ErrNotFound while
// it has never saved any (the defaults apply).
func (tx *TenantTx) GrpPrivSettings() (*GrpPrivSettings, error) {
	return one(tx, func(s scanner) (*GrpPrivSettings, error) {
		var v GrpPrivSettings
		var at string
		var by sql.NullString
		if err := s.Scan(&v.Body, &at, &by); err != nil {
			return nil, err
		}
		v.UpdatedBy = strp(by)
		var err error
		v.UpdatedAt, err = ParseRT(at)
		return &v, err
	}, grpPrivSettingsGet)
}

// SetGrpPrivSettings stores the tenant's privilege settings.
func (tx *TenantTx) SetGrpPrivSettings(body string, at time.Time, by *string) error {
	_, err := tx.exec(grpPrivSettingsSet, sql.Named("body", body), sql.Named("updated_at", RT(at)), sql.Named("updated_by", SP(by)))
	return err
}

// SetPlatformUserIdentity links a platform user to the identity whose group
// memberships give it its group privileges (nil removes the link). The
// guard triggers refuse another tenant's identity; ErrNotFound if this tenant
// has no such user.
func (tx *TenantTx) SetPlatformUserIdentity(user uuid.UUID, identity *int64) error {
	return tx.execOne(usersSetIdentity, sql.Named("identity_id", IP(identity)), sql.Named("id", user.String()))
}
