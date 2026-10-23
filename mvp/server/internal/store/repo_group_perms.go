package store

import "database/sql"

// Permission and limit reads (issue #62, GR-19). A permission is an assignment
// of a definition of type perm on a role (a group) or on a role's membership; a
// limit is an assignment of a definition of type limit on a permission
// assignment. The rules live in internal/groups/perms; these are only the
// statements, all bound to the transaction's tenant, and they read the tables of
// schema/0287_group_attrs.sql.

var (
	permAssigns = tq("grp_perms.assigns", `SELECT `+attrAssignCols+` FROM grp_attr_assigns a
		JOIN grp_attr_defs d ON d.tenant_id = a.tenant_id AND d.id = a.def_id
		WHERE a.tenant_id = @tenant AND d.tenant_id = @tenant AND d.attr_type = 'perm'
		  AND a.owner_type IN ('group','membership')
		ORDER BY a.created_at, a.id`)
	permLimitAssigns = tq("grp_perms.limit_assigns", `SELECT `+attrAssignCols+` FROM grp_attr_assigns a
		JOIN grp_attr_defs d ON d.tenant_id = a.tenant_id AND d.id = a.def_id
		WHERE a.tenant_id = @tenant AND d.tenant_id = @tenant AND d.attr_type = 'limit' AND a.owner_type = 'assignment'
		ORDER BY a.created_at, a.id`)
	permLimitValues = tq("grp_perms.limit_values", `SELECT `+attrValueCols+` FROM grp_attr_values v
		JOIN grp_attr_assigns a ON a.tenant_id = v.tenant_id AND a.id = v.assign_id
		JOIN grp_attr_defs d ON d.tenant_id = a.tenant_id AND d.id = a.def_id
		WHERE v.tenant_id = @tenant AND a.tenant_id = @tenant AND d.tenant_id = @tenant
		  AND d.attr_type = 'limit' AND a.owner_type = 'assignment'
		ORDER BY v.assign_id, v.position, v.id`)
	permDirectsOf = tq("grp_perms.directs_of", `SELECT `+dmCols+` FROM grp_direct_memberships d
		WHERE d.tenant_id = @tenant AND d.list_id = @list_id AND d.member_type = 'identity' AND d.member_identity_id = @identity
		ORDER BY d.created_at, d.id`)
)

// GrpPermAssigns lists every permission assignment of the tenant on a role or on
// a role's membership, oldest first.
func (tx *TenantTx) GrpPermAssigns() ([]*GrpAttrAssign, error) {
	return collect(tx, scanGrpAttrAssign, permAssigns)
}

// GrpLimitAssigns lists every limit assignment of the tenant (each sits on a
// permission assignment), oldest first.
func (tx *TenantTx) GrpLimitAssigns() ([]*GrpAttrAssign, error) {
	return collect(tx, scanGrpAttrAssign, permLimitAssigns)
}

// GrpLimitValues lists the values of every limit assignment, in assignment and
// position order.
func (tx *TenantTx) GrpLimitValues() ([]*GrpAttrValue, error) {
	return collect(tx, scanGrpAttrValue, permLimitValues)
}

// GrpDirectsOfIdentity lists the direct memberships an identity holds in any
// group's list, oldest first.
func (tx *TenantTx) GrpDirectsOfIdentity(identity int64, list ListID) ([]*DirectMembership, error) {
	return collect(tx, scanGrpDirect, permDirectsOf, sql.Named("identity", identity), sql.Named("list_id", string(list)))
}
