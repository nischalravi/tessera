package store

import (
	"database/sql"
	"time"
)

// Role memberships in access reviews (schema/0340_review_role_memberships.sql,
// issue #214): the birthright exclusion list, review items that certify a
// membership, and the roles a review schedule is scoped to.

// RoleExclusion is a person a birthright rule must not assign. Version is the
// role's exclusion-list version the add created; RemovedVersion the one the
// removal created. Active while RemovedAt is nil.
type RoleExclusion struct {
	ID            int64
	RoleID        string
	IdentityID    int64
	Reason        string
	Version       int
	ExcludedBy    *string
	ExcludedActor string
	ExcludedAt    time.Time
	ReviewItemID  *int64

	RemovedAt      *time.Time
	RemovedVersion *int
	RemovedBy      *string
	RemovedReason  *string
}

// Active reports whether the exclusion still applies.
func (e *RoleExclusion) Active() bool { return e.RemovedAt == nil }

// Review item resolutions of a membership.
const (
	ResolveUnassign = "unassign"
	ResolveExclude  = "exclude"
	ResolveFlag     = "flag"
)

// ReviewItemRole marks a review item as a role membership.
type ReviewItemRole struct {
	ItemID       int64
	RoleID       string
	MemberSource string
	Resolution   *string
	ResolvedAt   *time.Time
}

const exclusionCols = `x.id, x.role_id, x.identity_id, x.reason, x.version, x.excluded_by, x.excluded_actor, x.excluded_at,
	x.review_item_id, x.removed_at, x.removed_version, x.removed_by, x.removed_reason`

const itemRoleCols = `ir.item_id, ir.role_id, ir.member_source, ir.resolution, ir.resolved_at`

var (
	exclusionsAll = tq("business_role_exclusions.all", `
		SELECT `+exclusionCols+` FROM business_role_exclusions x WHERE x.tenant_id = @tenant ORDER BY x.role_id, x.version`)
	exclusionsForRole = tq("business_role_exclusions.for_role", `
		SELECT `+exclusionCols+` FROM business_role_exclusions x WHERE x.tenant_id = @tenant AND x.role_id = @role_id
		ORDER BY x.version`)
	exclusionsInsert = tq("business_role_exclusions.insert", `
		INSERT INTO business_role_exclusions (tenant_id, role_id, identity_id, reason, version, excluded_by, excluded_actor,
			excluded_at, review_item_id)
		VALUES (@tenant, @role_id, @identity_id, @reason, @version, @excluded_by, @excluded_actor, @excluded_at, @review_item_id)`)
	exclusionsRemove = tq("business_role_exclusions.remove", `
		UPDATE business_role_exclusions SET removed_at = @removed_at, removed_version = @removed_version,
			removed_by = @removed_by, removed_reason = @removed_reason
		WHERE tenant_id = @tenant AND role_id = @role_id AND identity_id = @identity_id AND removed_at IS NULL`)

	itemRolesInsert = tq("review_item_roles.insert", `
		INSERT INTO review_item_roles (item_id, tenant_id, role_id, member_source)
		VALUES (@item_id, @tenant, @role_id, @member_source)`)
	itemRolesGet = tq("review_item_roles.get", `
		SELECT `+itemRoleCols+` FROM review_item_roles ir WHERE ir.tenant_id = @tenant AND ir.item_id = @item_id`)
	itemRolesByCampaign = tq("review_item_roles.by_campaign", `
		SELECT `+itemRoleCols+` FROM review_item_roles ir
		JOIN review_items ri ON ri.id = ir.item_id
		WHERE ir.tenant_id = @tenant AND ri.tenant_id = @tenant AND ri.campaign_id = @campaign_id ORDER BY ir.item_id`)
	itemRolesFlagged = tq("review_item_roles.flagged", `
		SELECT `+itemRoleCols+` FROM review_item_roles ir
		WHERE ir.tenant_id = @tenant AND ir.role_id = @role_id AND ir.resolution = 'flag' ORDER BY ir.item_id`)
	itemRolesDecideItem = tq("review_item_roles.decide_item", `
		UPDATE review_items SET decision = @decision, comment = @comment, decided_at = @decided_at,
			decided_by_user_id = @decided_by_user_id
		WHERE tenant_id = @tenant AND id = @id AND (decision IS NULL OR decision = '')`)
	itemRolesResolve = tq("review_item_roles.resolve", `
		UPDATE review_item_roles SET resolution = @resolution, resolved_at = @resolved_at
		WHERE tenant_id = @tenant AND item_id = @item_id`)

	templateRolesList = tq("review_template_roles.list", `
		SELECT tr.role_id FROM review_template_roles tr WHERE tr.tenant_id = @tenant AND tr.template_id = @template_id
		ORDER BY tr.role_id`)
	templateRolesDelete = tq("review_template_roles.delete", `
		DELETE FROM review_template_roles WHERE tenant_id = @tenant AND template_id = @template_id`)
	templateRolesInsert = tq("review_template_roles.insert", `
		INSERT INTO review_template_roles (tenant_id, template_id, role_id) VALUES (@tenant, @template_id, @role_id)`)
)

func scanExclusion(s scanner) (*RoleExclusion, error) {
	var x RoleExclusion
	var by, rby, rreason sql.NullString
	var item, rver sql.NullInt64
	var at, rat nullTime
	if err := s.Scan(&x.ID, &x.RoleID, &x.IdentityID, &x.Reason, &x.Version, &by, &x.ExcludedActor, &at, &item, &rat, &rver,
		&rby, &rreason); err != nil {
		return nil, err
	}
	x.ExcludedBy, x.ReviewItemID, x.RemovedBy, x.RemovedReason = strp(by), intp(item), strp(rby), strp(rreason)
	if rver.Valid {
		v := int(rver.Int64)
		x.RemovedVersion = &v
	}
	var err error
	if x.ExcludedAt, err = at.val(); err != nil {
		return nil, err
	}
	x.RemovedAt, err = rat.ptr()
	return &x, err
}

func scanItemRole(s scanner) (*ReviewItemRole, error) {
	var r ReviewItemRole
	var res sql.NullString
	var at nullTime
	if err := s.Scan(&r.ItemID, &r.RoleID, &r.MemberSource, &res, &at); err != nil {
		return nil, err
	}
	r.Resolution = strp(res)
	var err error
	r.ResolvedAt, err = at.ptr()
	return &r, err
}

// AllRoleExclusions returns every exclusion, active or removed, by role and version.
func (tx *TenantTx) AllRoleExclusions() ([]*RoleExclusion, error) {
	return collect(tx, scanExclusion, exclusionsAll)
}

// RoleExclusions returns a role's exclusion history, oldest version first.
func (tx *TenantTx) RoleExclusions(roleID string) ([]*RoleExclusion, error) {
	return collect(tx, scanExclusion, exclusionsForRole, sql.Named("role_id", roleID))
}

// InsertRoleExclusion records an exclusion at the version it creates.
func (tx *TenantTx) InsertRoleExclusion(x *RoleExclusion) error {
	_, err := tx.exec(exclusionsInsert, sql.Named("role_id", x.RoleID), sql.Named("identity_id", x.IdentityID),
		sql.Named("reason", x.Reason), sql.Named("version", x.Version), sql.Named("excluded_by", SP(x.ExcludedBy)),
		sql.Named("excluded_actor", x.ExcludedActor), sql.Named("excluded_at", T(x.ExcludedAt)),
		sql.Named("review_item_id", IP(x.ReviewItemID)))
	return err
}

// RemoveRoleExclusion ends a person's active exclusion at version; ErrNotFound
// if there is none.
func (tx *TenantTx) RemoveRoleExclusion(roleID string, identityID int64, version int, at time.Time, by *string, reason string) error {
	res, err := tx.exec(exclusionsRemove, sql.Named("role_id", roleID), sql.Named("identity_id", identityID),
		sql.Named("removed_at", T(at)), sql.Named("removed_version", version), sql.Named("removed_by", SP(by)),
		sql.Named("removed_reason", reason))
	return rowsOne(res, err)
}

// InsertMembershipItem inserts an undecided review item for a role membership
// (x.EdgeSrc "role:<id>", x.EdgeDst "identity:<id>") and marks it as one. It
// returns the item's id. Context must already be encoded JSON.
func (tx *TenantTx) InsertMembershipItem(x *ReviewItem, roleID, source string) (int64, error) {
	if err := tx.own(x.TenantID); err != nil {
		return 0, err
	}
	reasons, err := JSON(x.Reasons)
	if err != nil {
		return 0, err
	}
	id, err := tx.insert(itemsInsert, sql.Named("campaign_id", x.CampaignID), sql.Named("identity_id", x.IdentityID),
		sql.Named("edge_id", nil), sql.Named("edge_src", x.EdgeSrc), sql.Named("edge_dst", x.EdgeDst),
		sql.Named("grant_label", x.GrantLabel), sql.Named("reasons", reasons), sql.Named("context", string(x.Context)),
		sql.Named("reviewer_id", IP(x.ReviewerID)))
	if err != nil {
		return 0, err
	}
	_, err = tx.exec(itemRolesInsert, sql.Named("item_id", id), sql.Named("role_id", roleID), sql.Named("member_source", source))
	return id, err
}

// ReviewItemRole returns a review item's membership marker, or ErrNotFound
// when the item is a grant.
func (tx *TenantTx) ReviewItemRole(itemID int64) (*ReviewItemRole, error) {
	return one(tx, scanItemRole, itemRolesGet, sql.Named("item_id", itemID))
}

// CampaignItemRoles returns the membership markers of a campaign's items.
func (tx *TenantTx) CampaignItemRoles(campaignID int64) ([]*ReviewItemRole, error) {
	return collect(tx, scanItemRole, itemRolesByCampaign, sql.Named("campaign_id", campaignID))
}

// FlaggedRoleItems returns the review items that flagged a role's rule to its owner.
func (tx *TenantTx) FlaggedRoleItems(roleID string) ([]*ReviewItemRole, error) {
	return collect(tx, scanItemRole, itemRolesFlagged, sql.Named("role_id", roleID))
}

// DecideMembershipItem records the reviewer's decision on a membership item and
// how it was resolved. Like a grant item, it is decided once: applied is false
// when the item was already decided (or is not in this tenant).
func (tx *TenantTx) DecideMembershipItem(id int64, decision string, comment *string, at time.Time, by UserRef,
	resolution string) (applied bool, err error) {
	res, err := tx.exec(itemRolesDecideItem, sql.Named("decision", decision), sql.Named("comment", SP(comment)),
		sql.Named("decided_at", T(at)), sql.Named("decided_by_user_id", by.idOrNil()), sql.Named("id", id))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil || n != 1 {
		return false, err
	}
	if resolution != "" {
		if _, err := tx.exec(itemRolesResolve, sql.Named("item_id", id), sql.Named("resolution", resolution),
			sql.Named("resolved_at", T(at))); err != nil {
			return false, err
		}
	}
	return true, nil
}

// ReviewTemplateRoles returns the roles a template is scoped to (none: not scoped).
func (tx *TenantTx) ReviewTemplateRoles(templateID string) ([]string, error) {
	rows, err := tx.query(templateRolesList, sql.Named("template_id", templateID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only cursor
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// SetReviewTemplateRoles replaces the roles a template is scoped to.
func (tx *TenantTx) SetReviewTemplateRoles(templateID string, roleIDs []string) error {
	if _, err := tx.exec(templateRolesDelete, sql.Named("template_id", templateID)); err != nil {
		return err
	}
	for _, id := range roleIDs {
		if _, err := tx.exec(templateRolesInsert, sql.Named("template_id", templateID), sql.Named("role_id", id)); err != nil {
			return err
		}
	}
	return nil
}
