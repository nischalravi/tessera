package store

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// Group rule repository (schema/0288_group_rules.sql, issue #56, GR-13). The
// vocabulary and the checks live in internal/groups/rules; this file is only
// its statements, all bound to the transaction's tenant.

const ruleCols = `r.id, r.tenant_id, r.owner_type, r.owner_id, r.scope, r.name, r.trigger_type, r.conditions, r.action,
	r.params, r.enabled, r.secret_enc, r.created_by, r.created_at, r.updated_by, r.updated_at, r.active_seq`

var (
	grpRuleInsert = tq("grp_rules.insert", `
		INSERT INTO grp_rules (id, tenant_id, owner_type, owner_id, scope, name, trigger_type, conditions, action, params, enabled,
			secret_enc, created_by, created_at, updated_by, updated_at, active_seq)
		VALUES (@id, @tenant, @owner_type, @owner_id, @scope, @name, @trigger, @conditions, @action, @params, @enabled,
			@secret_enc, @created_by, @created_at, @updated_by, @updated_at, @active_seq)`)
	grpRuleGet = tq("grp_rules.get", `SELECT `+ruleCols+` FROM grp_rules r WHERE r.tenant_id = @tenant AND r.id = @id`)
	// everything a save may change; the owner and the creator never change
	grpRuleUpdate = tq("grp_rules.update", `UPDATE grp_rules SET scope = @scope, name = @name, trigger_type = @trigger,
		conditions = @conditions, action = @action, params = @params, enabled = @enabled, secret_enc = @secret_enc,
		updated_by = @updated_by, updated_at = @updated_at, active_seq = @active_seq
		WHERE tenant_id = @tenant AND id = @id`)
	grpRuleDelete   = tq("grp_rules.delete", `DELETE FROM grp_rules WHERE tenant_id = @tenant AND id = @id`)
	grpRuleDeleteOf = tq("grp_rules.delete_of", `DELETE FROM grp_rules WHERE tenant_id = @tenant AND owner_type = @owner_type AND owner_id = @owner_id`)
	grpRuleOfOwner  = tq("grp_rules.of_owner", `SELECT `+ruleCols+` FROM grp_rules r
		WHERE r.tenant_id = @tenant AND r.owner_type = @owner_type AND r.owner_id = @owner_id ORDER BY r.created_at, r.id`)
	// the enabled rules of a trigger and/or an action ("" matches any), oldest first
	grpRuleEnabled = tq("grp_rules.enabled", `SELECT `+ruleCols+` FROM grp_rules r
		WHERE r.tenant_id = @tenant AND r.enabled = 1 AND (@trigger = '' OR r.trigger_type = @trigger)
		  AND (@action = '' OR r.action = @action) ORDER BY r.created_at, r.id`)

	grpRuleSettingsGet = tq("grp_rule_settings.get", `SELECT s.email_enabled, s.updated_at, s.updated_by FROM grp_rule_settings s
		WHERE s.tenant_id = @tenant`)
	grpRuleSettingsSet = tq("grp_rule_settings.set", `
		INSERT INTO grp_rule_settings (tenant_id, email_enabled, updated_at, updated_by)
		VALUES (@tenant, @email_enabled, @updated_at, @updated_by)
		ON CONFLICT (tenant_id) DO UPDATE SET email_enabled = excluded.email_enabled, updated_at = excluded.updated_at,
			updated_by = excluded.updated_by`)

	// the groups where an identity has an active direct row of its own in a list: a constraint
	// that looks at "the other groups of a folder" filters these by folder in the caller
	grpDmIdentityGroups = tq("grp_dm.identity_groups", `SELECT d.group_id FROM grp_direct_memberships d
		JOIN grp_groups g ON g.tenant_id = @tenant AND g.id = d.group_id
		WHERE d.tenant_id = @tenant AND d.list_id = @list_id AND d.member_type = 'identity'
		  AND d.member_identity_id = @identity AND g.status <> 'deleted' AND `+dmActive+`
		ORDER BY d.group_id`)
)

func scanGrpRule(s scanner) (*GrpRule, error) {
	var r GrpRule
	var tenant, created, updated string
	var enabled int
	if err := s.Scan(&r.ID, &tenant, &r.OwnerType, &r.OwnerID, &r.Scope, &r.Name, &r.Trigger, &r.Conditions, &r.Action,
		&r.Params, &enabled, &r.SecretEnc, &r.CreatedBy, &created, &r.UpdatedBy, &updated, &r.ActiveSeq); err != nil {
		return nil, err
	}
	var err error
	if r.TenantID, err = tenantOf(tenant); err != nil {
		return nil, err
	}
	r.Enabled = enabled == 1
	if r.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	r.UpdatedAt, err = ParseRT(updated)
	return &r, err
}

// InsertGrpRule adds a rule (a zero ID gets a fresh one).
func (tx *TenantTx) InsertGrpRule(r *GrpRule) error {
	if err := tx.own(r.TenantID); err != nil {
		return err
	}
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	_, err := tx.exec(grpRuleInsert, sql.Named("id", r.ID), sql.Named("owner_type", r.OwnerType), sql.Named("owner_id", r.OwnerID),
		sql.Named("scope", r.Scope), sql.Named("name", r.Name), sql.Named("trigger", r.Trigger),
		sql.Named("conditions", r.Conditions), sql.Named("action", r.Action), sql.Named("params", r.Params),
		sql.Named("enabled", B(r.Enabled)), sql.Named("secret_enc", r.SecretEnc), sql.Named("created_by", r.CreatedBy),
		sql.Named("created_at", RT(r.CreatedAt)), sql.Named("updated_by", r.UpdatedBy), sql.Named("updated_at", RT(r.UpdatedAt)),
		sql.Named("active_seq", r.ActiveSeq))
	if err == nil {
		r.TenantID = tx.tenant
	}
	return err
}

// GrpRule returns one rule or ErrNotFound.
func (tx *TenantTx) GrpRule(id string) (*GrpRule, error) {
	return one(tx, scanGrpRule, grpRuleGet, sql.Named("id", id))
}

// UpdateGrpRule stores what a save may change (ErrNotFound if this tenant has no such rule).
func (tx *TenantTx) UpdateGrpRule(r *GrpRule) error {
	return tx.execOne(grpRuleUpdate, sql.Named("id", r.ID), sql.Named("scope", r.Scope), sql.Named("name", r.Name),
		sql.Named("trigger", r.Trigger), sql.Named("conditions", r.Conditions), sql.Named("action", r.Action),
		sql.Named("params", r.Params), sql.Named("enabled", B(r.Enabled)), sql.Named("secret_enc", r.SecretEnc),
		sql.Named("updated_by", r.UpdatedBy), sql.Named("updated_at", RT(r.UpdatedAt)),
		sql.Named("active_seq", r.ActiveSeq))
}

// DeleteGrpRule removes one rule (ErrNotFound if this tenant has none).
func (tx *TenantTx) DeleteGrpRule(id string) error {
	return tx.execOne(grpRuleDelete, sql.Named("id", id))
}

// DeleteGrpRulesOf removes the rules an owner has and returns how many.
func (tx *TenantTx) DeleteGrpRulesOf(ownerType, ownerID string) (int64, error) {
	res, err := tx.exec(grpRuleDeleteOf, sql.Named("owner_type", ownerType), sql.Named("owner_id", ownerID))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// GrpRulesOf lists the rules of one owner, oldest first.
func (tx *TenantTx) GrpRulesOf(ownerType, ownerID string) ([]*GrpRule, error) {
	return collect(tx, scanGrpRule, grpRuleOfOwner, sql.Named("owner_type", ownerType), sql.Named("owner_id", ownerID))
}

// GrpRulesEnabled lists the enabled rules with the trigger and the action
// ("" matches any), oldest first.
func (tx *TenantTx) GrpRulesEnabled(trigger, action string) ([]*GrpRule, error) {
	return collect(tx, scanGrpRule, grpRuleEnabled, sql.Named("trigger", trigger), sql.Named("action", action))
}

// GrpRuleSettings returns the tenant's rule settings, or ErrNotFound while it
// has never saved any (the defaults apply: email rules off).
func (tx *TenantTx) GrpRuleSettings() (*GrpRuleSettings, error) {
	return one(tx, func(s scanner) (*GrpRuleSettings, error) {
		var v GrpRuleSettings
		var email int
		var at string
		var by sql.NullString
		if err := s.Scan(&email, &at, &by); err != nil {
			return nil, err
		}
		v.EmailEnabled, v.UpdatedBy = email == 1, strp(by)
		var err error
		v.UpdatedAt, err = ParseRT(at)
		return &v, err
	}, grpRuleSettingsGet)
}

// SetGrpRuleSettings stores the tenant's rule settings.
func (tx *TenantTx) SetGrpRuleSettings(emailEnabled bool, at time.Time, by *string) error {
	_, err := tx.exec(grpRuleSettingsSet, sql.Named("email_enabled", B(emailEnabled)), sql.Named("updated_at", RT(at)),
		sql.Named("updated_by", SP(by)))
	return err
}

// GrpDirectIdentityGroups lists the groups (not deleted) in which the identity
// has an active direct row of its own in the list at now.
func (tx *TenantTx) GrpDirectIdentityGroups(list ListID, identity int64, now time.Time) ([]GroupID, error) {
	ids, err := collect(tx, scanGroupID, grpDmIdentityGroups, sql.Named("list_id", string(list)), sql.Named("identity", identity),
		sql.Named("now", RT(now)))
	out := make([]GroupID, len(ids))
	for i, id := range ids {
		out[i] = *id
	}
	return out, err
}
