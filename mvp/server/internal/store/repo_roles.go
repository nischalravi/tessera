package store

import (
	"database/sql"
	"time"
)

// Business roles (schema/0206_business_roles.sql, issue #161).

// BusinessRole is a bundle of entitlements with its metadata.
type BusinessRole struct {
	ID              string
	Name            string
	Description     string
	OwnerIdentityID *int64
	Risk            string // low, medium, high
	Requestable     bool
	Birthright      *string // JSON rule; nil: no rule
	Status          string  // active, retired
	Version         int
	CreatedAt       time.Time
	UpdatedBy       *string
	UpdatedAt       time.Time
}

// Business role statuses.
const (
	RoleActive  = "active"
	RoleRetired = "retired"
)

// RoleEntitlement is one group a role grants.
type RoleEntitlement struct {
	RoleID  string
	GroupID int64
}

// RoleVersion is a snapshot of one saved change of a role.
type RoleVersion struct {
	ID        int64
	RoleID    string
	Version   int
	Snapshot  string // JSON
	Note      *string
	ChangedBy *string
	Actor     string
	ChangedAt time.Time
}

// RoleMember is a person holding a role.
type RoleMember struct {
	ID         int64
	RoleID     string
	IdentityID int64
	Source     string // rule, request, manual
	AssignedBy *string
	AssignedAt time.Time
	RequestID  *string
}

// Role member sources.
const (
	MemberRule    = "rule"
	MemberRequest = "request"
	MemberManual  = "manual"
)

// RoleRequest is a request for a role.
type RoleRequest struct {
	ID             string
	RoleID         string
	BeneficiaryID  int64
	RequestedBy    string
	Justification  string
	Status         string // pending, approved, denied, cancelled (the Request* constants)
	RequestedAt    time.Time
	DecidedBy      *string
	DecidedAt      *time.Time
	DecisionReason *string
}

// RoleRequestFilter selects role requests; zero fields match everything.
type RoleRequestFilter struct {
	Status            string
	RoleID            string
	InvolvingUser     string // requested by this user ...
	InvolvingIdentity int64  // ... or for this identity
}

const brCols = `r.id, r.name, r.description, r.owner_identity_id, r.risk, r.requestable, r.birthright, r.status, r.version,
	r.created_at, r.updated_by, r.updated_at`

const rrCols = `q.id, q.role_id, q.beneficiary_id, q.requested_by, q.justification, q.status, q.requested_at,
	q.decided_by, q.decided_at, q.decision_reason`

const rmCols = `m.id, m.role_id, m.identity_id, m.source, m.assigned_by, m.assigned_at, m.request_id`

var (
	brList = tq("business_roles.list", `
		SELECT `+brCols+` FROM business_roles r WHERE r.tenant_id = @tenant ORDER BY r.name, r.id`)
	brGet = tq("business_roles.get", `
		SELECT `+brCols+` FROM business_roles r WHERE r.tenant_id = @tenant AND r.id = @id`)
	brByName = tq("business_roles.by_name", `
		SELECT `+brCols+` FROM business_roles r WHERE r.tenant_id = @tenant AND r.name = @name`)
	brInsert = tq("business_roles.insert", `
		INSERT INTO business_roles (id, tenant_id, name, description, owner_identity_id, risk, requestable, birthright,
			status, version, created_at, updated_by, updated_at)
		VALUES (@id, @tenant, @name, @description, @owner_identity_id, @risk, @requestable, @birthright, @status,
			@version, @created_at, @updated_by, @updated_at)`)
	brSave = tq("business_roles.save", `
		UPDATE business_roles SET name = @name, description = @description, owner_identity_id = @owner_identity_id,
			risk = @risk, requestable = @requestable, birthright = @birthright, status = @status, version = @version,
			updated_by = @updated_by, updated_at = @updated_at
		WHERE tenant_id = @tenant AND id = @id AND version = @from_version`)

	reList = tq("business_role_entitlements.list", `
		SELECT e.role_id, e.group_id FROM business_role_entitlements e WHERE e.tenant_id = @tenant
		ORDER BY e.role_id, e.group_id`)
	reForRole = tq("business_role_entitlements.for_role", `
		SELECT e.role_id, e.group_id FROM business_role_entitlements e WHERE e.tenant_id = @tenant AND e.role_id = @role_id
		ORDER BY e.group_id`)
	reClear = tq("business_role_entitlements.clear", `
		DELETE FROM business_role_entitlements WHERE tenant_id = @tenant AND role_id = @role_id`)
	reInsert = tq("business_role_entitlements.insert", `
		INSERT INTO business_role_entitlements (tenant_id, role_id, group_id) VALUES (@tenant, @role_id, @group_id)`)

	rvInsert = tq("business_role_versions.insert", `
		INSERT INTO business_role_versions (tenant_id, role_id, version, snapshot, note, changed_by, actor, changed_at)
		VALUES (@tenant, @role_id, @version, @snapshot, @note, @changed_by, @actor, @changed_at)`)
	rvForRole = tq("business_role_versions.for_role", `
		SELECT v.id, v.role_id, v.version, v.snapshot, v.note, v.changed_by, v.actor, v.changed_at
		FROM business_role_versions v WHERE v.tenant_id = @tenant AND v.role_id = @role_id ORDER BY v.version DESC`)

	rmList = tq("business_role_members.list", `
		SELECT `+rmCols+` FROM business_role_members m WHERE m.tenant_id = @tenant ORDER BY m.role_id, m.identity_id`)
	rmForRole = tq("business_role_members.for_role", `
		SELECT `+rmCols+` FROM business_role_members m WHERE m.tenant_id = @tenant AND m.role_id = @role_id
		ORDER BY m.identity_id`)
	rmForIdentity = tq("business_role_members.for_identity", `
		SELECT `+rmCols+` FROM business_role_members m WHERE m.tenant_id = @tenant AND m.identity_id = @identity_id
		ORDER BY m.role_id`)
	rmInsert = tq("business_role_members.insert", `
		INSERT INTO business_role_members (tenant_id, role_id, identity_id, source, assigned_by, assigned_at, request_id)
		VALUES (@tenant, @role_id, @identity_id, @source, @assigned_by, @assigned_at, @request_id)`)
	rmDelete = tq("business_role_members.delete", `
		DELETE FROM business_role_members WHERE tenant_id = @tenant AND role_id = @role_id AND identity_id = @identity_id`)

	rrInsert = tq("business_role_requests.insert", `
		INSERT INTO business_role_requests (id, tenant_id, role_id, beneficiary_id, requested_by, justification, status,
			requested_at)
		VALUES (@id, @tenant, @role_id, @beneficiary_id, @requested_by, @justification, 'pending', @requested_at)`)
	rrGet = tq("business_role_requests.get", `
		SELECT `+rrCols+` FROM business_role_requests q WHERE q.tenant_id = @tenant AND q.id = @id`)
	rrFiltered = tq("business_role_requests.filtered", `
		SELECT `+rrCols+` FROM business_role_requests q WHERE q.tenant_id = @tenant
			AND (@status = '' OR q.status = @status)
			AND (@role_id = '' OR q.role_id = @role_id)
			AND ((@inv_user = '' AND @inv_identity = 0) OR q.requested_by = @inv_user OR q.beneficiary_id = @inv_identity)
		ORDER BY q.requested_at DESC, q.id LIMIT 500`)
	rrSave = tq("business_role_requests.save", `
		UPDATE business_role_requests SET status = @status, decided_by = @decided_by, decided_at = @decided_at,
			decision_reason = @decision_reason
		WHERE tenant_id = @tenant AND id = @id AND status = @from`)

	edgesTo = tq("grant_edges.to", `
		SELECT `+edgeCols+` FROM grant_edges e WHERE e.tenant_id = @tenant AND e.dst = @dst ORDER BY e.id`)
	edgesDeleteRole = tq("grant_edges.delete_role", `
		DELETE FROM grant_edges WHERE tenant_id = @tenant AND id = @id AND source = 'role'`)
)

func scanBusinessRole(s scanner) (*BusinessRole, error) {
	var r BusinessRole
	var owner sql.NullInt64
	var req int
	var birth, by sql.NullString
	var created, updated nullTime
	if err := s.Scan(&r.ID, &r.Name, &r.Description, &owner, &r.Risk, &req, &birth, &r.Status, &r.Version, &created,
		&by, &updated); err != nil {
		return nil, err
	}
	r.OwnerIdentityID, r.Requestable, r.Birthright, r.UpdatedBy = intp(owner), req != 0, strp(birth), strp(by)
	var err error
	if r.CreatedAt, err = created.val(); err != nil {
		return nil, err
	}
	r.UpdatedAt, err = updated.val()
	return &r, err
}

func scanRoleEntitlement(s scanner) (*RoleEntitlement, error) {
	var e RoleEntitlement
	return &e, s.Scan(&e.RoleID, &e.GroupID)
}

func scanRoleVersion(s scanner) (*RoleVersion, error) {
	var v RoleVersion
	var note, by sql.NullString
	var at nullTime
	if err := s.Scan(&v.ID, &v.RoleID, &v.Version, &v.Snapshot, &note, &by, &v.Actor, &at); err != nil {
		return nil, err
	}
	v.Note, v.ChangedBy = strp(note), strp(by)
	var err error
	v.ChangedAt, err = at.val()
	return &v, err
}

func scanRoleMember(s scanner) (*RoleMember, error) {
	var m RoleMember
	var by, req sql.NullString
	var at nullTime
	if err := s.Scan(&m.ID, &m.RoleID, &m.IdentityID, &m.Source, &by, &at, &req); err != nil {
		return nil, err
	}
	m.AssignedBy, m.RequestID = strp(by), strp(req)
	var err error
	m.AssignedAt, err = at.val()
	return &m, err
}

func scanRoleRequest(s scanner) (*RoleRequest, error) {
	var q RoleRequest
	var at, decAt nullTime
	var decBy, reason sql.NullString
	if err := s.Scan(&q.ID, &q.RoleID, &q.BeneficiaryID, &q.RequestedBy, &q.Justification, &q.Status, &at, &decBy,
		&decAt, &reason); err != nil {
		return nil, err
	}
	q.DecidedBy, q.DecisionReason = strp(decBy), strp(reason)
	var err error
	if q.RequestedAt, err = at.val(); err != nil {
		return nil, err
	}
	q.DecidedAt, err = decAt.ptr()
	return &q, err
}

// BusinessRoles returns every role, by name.
func (tx *TenantTx) BusinessRoles() ([]*BusinessRole, error) {
	return collect(tx, scanBusinessRole, brList)
}

// BusinessRole returns one role, or ErrNotFound.
func (tx *TenantTx) BusinessRole(id string) (*BusinessRole, error) {
	return one(tx, scanBusinessRole, brGet, sql.Named("id", id))
}

// BusinessRoleByName returns the role with the name, or ErrNotFound.
func (tx *TenantTx) BusinessRoleByName(name string) (*BusinessRole, error) {
	return one(tx, scanBusinessRole, brByName, sql.Named("name", name))
}

func roleArgs(r *BusinessRole) []sql.NamedArg {
	return []sql.NamedArg{sql.Named("id", r.ID), sql.Named("name", r.Name), sql.Named("description", r.Description),
		sql.Named("owner_identity_id", IP(r.OwnerIdentityID)), sql.Named("risk", r.Risk),
		sql.Named("requestable", B(r.Requestable)), sql.Named("birthright", SP(r.Birthright)),
		sql.Named("status", r.Status), sql.Named("version", r.Version), sql.Named("updated_by", SP(r.UpdatedBy)),
		sql.Named("updated_at", T(r.UpdatedAt))}
}

// InsertBusinessRole creates a role.
func (tx *TenantTx) InsertBusinessRole(r *BusinessRole) error {
	_, err := tx.exec(brInsert, append(roleArgs(r), sql.Named("created_at", T(r.CreatedAt)))...)
	return err
}

// SaveBusinessRole updates a role that is still at version from;
// ErrNotFound if it moved on (a concurrent change) or does not exist.
func (tx *TenantTx) SaveBusinessRole(r *BusinessRole, from int) error {
	res, err := tx.exec(brSave, append(roleArgs(r), sql.Named("from_version", from))...)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

// AllRoleEntitlements returns every role's entitlements.
func (tx *TenantTx) AllRoleEntitlements() ([]*RoleEntitlement, error) {
	return collect(tx, scanRoleEntitlement, reList)
}

// RoleEntitlements returns the group ids a role grants, ascending.
func (tx *TenantTx) RoleEntitlements(roleID string) ([]int64, error) {
	es, err := collect(tx, scanRoleEntitlement, reForRole, sql.Named("role_id", roleID))
	out := make([]int64, len(es))
	for i, e := range es {
		out[i] = e.GroupID
	}
	return out, err
}

// SetRoleEntitlements replaces a role's entitlements.
func (tx *TenantTx) SetRoleEntitlements(roleID string, groups []int64) error {
	if _, err := tx.exec(reClear, sql.Named("role_id", roleID)); err != nil {
		return err
	}
	for _, g := range groups {
		if _, err := tx.exec(reInsert, sql.Named("role_id", roleID), sql.Named("group_id", g)); err != nil {
			return err
		}
	}
	return nil
}

// AddRoleVersion appends a version snapshot.
func (tx *TenantTx) AddRoleVersion(v *RoleVersion) error {
	_, err := tx.exec(rvInsert, sql.Named("role_id", v.RoleID), sql.Named("version", v.Version),
		sql.Named("snapshot", v.Snapshot), sql.Named("note", SP(v.Note)), sql.Named("changed_by", SP(v.ChangedBy)),
		sql.Named("actor", v.Actor), sql.Named("changed_at", T(v.ChangedAt)))
	return err
}

// RoleVersions returns a role's versions, newest first.
func (tx *TenantTx) RoleVersions(roleID string) ([]*RoleVersion, error) {
	return collect(tx, scanRoleVersion, rvForRole, sql.Named("role_id", roleID))
}

// AllRoleMembers returns every membership.
func (tx *TenantTx) AllRoleMembers() ([]*RoleMember, error) {
	return collect(tx, scanRoleMember, rmList)
}

// RoleMembers returns a role's members, by identity id.
func (tx *TenantTx) RoleMembers(roleID string) ([]*RoleMember, error) {
	return collect(tx, scanRoleMember, rmForRole, sql.Named("role_id", roleID))
}

// IdentityRoles returns the roles a person holds.
func (tx *TenantTx) IdentityRoles(identityID int64) ([]*RoleMember, error) {
	return collect(tx, scanRoleMember, rmForIdentity, sql.Named("identity_id", identityID))
}

// AddRoleMember assigns a role.
func (tx *TenantTx) AddRoleMember(m *RoleMember) error {
	_, err := tx.exec(rmInsert, sql.Named("role_id", m.RoleID), sql.Named("identity_id", m.IdentityID),
		sql.Named("source", m.Source), sql.Named("assigned_by", SP(m.AssignedBy)),
		sql.Named("assigned_at", T(m.AssignedAt)), sql.Named("request_id", SP(m.RequestID)))
	return err
}

// DeleteRoleMember removes a membership (no error if there is none).
func (tx *TenantTx) DeleteRoleMember(roleID string, identityID int64) error {
	_, err := tx.exec(rmDelete, sql.Named("role_id", roleID), sql.Named("identity_id", identityID))
	return err
}

// InsertRoleRequest files a pending role request.
func (tx *TenantTx) InsertRoleRequest(q *RoleRequest) error {
	_, err := tx.exec(rrInsert, sql.Named("id", q.ID), sql.Named("role_id", q.RoleID),
		sql.Named("beneficiary_id", q.BeneficiaryID), sql.Named("requested_by", q.RequestedBy),
		sql.Named("justification", q.Justification), sql.Named("requested_at", T(q.RequestedAt)))
	return err
}

// RoleRequest returns one role request, or ErrNotFound.
func (tx *TenantTx) RoleRequest(id string) (*RoleRequest, error) {
	return one(tx, scanRoleRequest, rrGet, sql.Named("id", id))
}

// RoleRequests returns the role requests matching f, newest first (at most 500).
func (tx *TenantTx) RoleRequests(f RoleRequestFilter) ([]*RoleRequest, error) {
	return collect(tx, scanRoleRequest, rrFiltered, sql.Named("status", f.Status), sql.Named("role_id", f.RoleID),
		sql.Named("inv_user", f.InvolvingUser), sql.Named("inv_identity", f.InvolvingIdentity))
}

// SaveRoleRequest moves a request from status from to q's state;
// ErrNotFound if it is no longer in from.
func (tx *TenantTx) SaveRoleRequest(q *RoleRequest, from string) error {
	res, err := tx.exec(rrSave, sql.Named("id", q.ID), sql.Named("from", from), sql.Named("status", q.Status),
		sql.Named("decided_by", SP(q.DecidedBy)), sql.Named("decided_at", TP(q.DecidedAt)),
		sql.Named("decision_reason", SP(q.DecisionReason)))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

// EdgesTo returns the grant edges into a node.
func (tx *TenantTx) EdgesTo(dst string) ([]*GrantEdge, error) {
	return collect(tx, scanEdge, edgesTo, sql.Named("dst", dst))
}

// DeleteRoleEdge deletes a grant edge if it was granted by a role.
func (tx *TenantTx) DeleteRoleEdge(id int64) error {
	res, err := tx.exec(edgesDeleteRole, sql.Named("id", id))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return err
	}
	return tx.closeEdgeIntent(id, CloseRoleRemoved, nowUTC())
}
