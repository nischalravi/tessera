package store

import (
	"database/sql"
	"encoding/json"
	"time"
)

// Organization settings (schema/0495_org_settings.sql, issue #298): assigned
// owners, per-organization policies and the source of the hierarchy. The
// organization tree itself is derived (internal/orgs).

// OrgOwnerRow is one assigned owner of an organization.
type OrgOwnerRow struct {
	OrgID      string
	IdentityID int64
	Ord        int
}

// OrgSettingsRow is the stored form of orgs.Policies. Nil fields are "not set".
type OrgSettingsRow struct {
	OrgID                string
	DefaultStages        []string // nil: no default approval workflow
	DefaultEscalateHours *float64
	JustificationReq     *bool
	JustificationMin     *int
	DefaultHours         *float64
	MaxHours             *float64
	Version              int
	UpdatedBy            string
	UpdatedAt            time.Time
}

// OrgHierarchySourceRow is where the organization hierarchy comes from.
type OrgHierarchySourceRow struct {
	Source    string
	System    *string
	Version   int
	UpdatedBy string
	UpdatedAt time.Time
}

const orgSettingsCols = `s.org_id, s.default_stages, s.default_escalate_hours, s.ov_justification_required,
	s.ov_justification_min_length, s.ov_default_hours, s.ov_max_hours, s.version, s.updated_by, s.updated_at`

var (
	orgOwnersList = tq("org_owners.list", `
		SELECT o.org_id, o.identity_id, o.ord FROM org_owners o WHERE o.tenant_id = @tenant ORDER BY o.org_id, o.ord, o.identity_id`)
	orgOwnersDelete = tq("org_owners.delete_org", `
		DELETE FROM org_owners WHERE tenant_id = @tenant AND org_id = @org_id`)
	orgOwnersInsert = tq("org_owners.insert", `
		INSERT INTO org_owners (tenant_id, org_id, identity_id, ord) VALUES (@tenant, @org_id, @identity_id, @ord)`)

	orgSettingsList = tq("org_settings.list", `
		SELECT `+orgSettingsCols+` FROM org_settings s WHERE s.tenant_id = @tenant ORDER BY s.org_id`)
	orgSettingsGet = tq("org_settings.get", `
		SELECT `+orgSettingsCols+` FROM org_settings s WHERE s.tenant_id = @tenant AND s.org_id = @org_id`)
	orgSettingsPut = tq("org_settings.put", `
		INSERT INTO org_settings (tenant_id, org_id, default_stages, default_escalate_hours, ov_justification_required,
			ov_justification_min_length, ov_default_hours, ov_max_hours, version, updated_by, updated_at)
		VALUES (@tenant, @org_id, @default_stages, @default_escalate_hours, @ov_justification_required,
			@ov_justification_min_length, @ov_default_hours, @ov_max_hours, 1, @updated_by, @updated_at)
		ON CONFLICT (tenant_id, org_id) DO UPDATE SET default_stages = excluded.default_stages,
			default_escalate_hours = excluded.default_escalate_hours, ov_justification_required = excluded.ov_justification_required,
			ov_justification_min_length = excluded.ov_justification_min_length, ov_default_hours = excluded.ov_default_hours,
			ov_max_hours = excluded.ov_max_hours, version = org_settings.version + 1, updated_by = excluded.updated_by,
			updated_at = excluded.updated_at`)

	orgSourceGet = tq("org_hierarchy_source.get", `
		SELECT s.source, s.system, s.version, s.updated_by, s.updated_at FROM org_hierarchy_source s WHERE s.tenant_id = @tenant`)
	orgSourcePut = tq("org_hierarchy_source.put", `
		INSERT INTO org_hierarchy_source (tenant_id, source, system, version, updated_by, updated_at)
		VALUES (@tenant, @source, @system, 1, @updated_by, @updated_at)
		ON CONFLICT (tenant_id) DO UPDATE SET source = excluded.source, system = excluded.system,
			version = org_hierarchy_source.version + 1, updated_by = excluded.updated_by, updated_at = excluded.updated_at`)
)

// OrgOwners lists every assigned owner, by organization and position.
func (tx *TenantTx) OrgOwners() ([]*OrgOwnerRow, error) {
	return collect(tx, func(s scanner) (*OrgOwnerRow, error) {
		var o OrgOwnerRow
		return &o, s.Scan(&o.OrgID, &o.IdentityID, &o.Ord)
	}, orgOwnersList)
}

// ReplaceOrgOwners sets an organization's assigned owners, in order (none: the owners are derived again).
func (tx *TenantTx) ReplaceOrgOwners(orgID string, identityIDs []int64) error {
	if _, err := tx.exec(orgOwnersDelete, sql.Named("org_id", orgID)); err != nil {
		return err
	}
	for i, id := range identityIDs {
		if _, err := tx.exec(orgOwnersInsert, sql.Named("org_id", orgID), sql.Named("identity_id", id), sql.Named("ord", i)); err != nil {
			return err
		}
	}
	return nil
}

func scanOrgSettings(s scanner) (*OrgSettingsRow, error) {
	var r OrgSettingsRow
	var stages sql.NullString
	var esc, def, max sql.NullFloat64
	var req, min sql.NullInt64
	var at string
	if err := s.Scan(&r.OrgID, &stages, &esc, &req, &min, &def, &max, &r.Version, &r.UpdatedBy, &at); err != nil {
		return nil, err
	}
	if stages.Valid {
		if err := json.Unmarshal([]byte(stages.String), &r.DefaultStages); err != nil {
			return nil, err
		}
	}
	if esc.Valid {
		r.DefaultEscalateHours = &esc.Float64
	}
	if def.Valid {
		r.DefaultHours = &def.Float64
	}
	if max.Valid {
		r.MaxHours = &max.Float64
	}
	if req.Valid {
		b := req.Int64 == 1
		r.JustificationReq = &b
	}
	if min.Valid {
		m := int(min.Int64)
		r.JustificationMin = &m
	}
	var err error
	r.UpdatedAt, err = ParseRT(at)
	return &r, err
}

// OrgSettingsList lists every organization with saved policies.
func (tx *TenantTx) OrgSettingsList() ([]*OrgSettingsRow, error) {
	return collect(tx, scanOrgSettings, orgSettingsList)
}

// OrgSettings returns one organization's policies; ErrNotFound if it has none.
func (tx *TenantTx) OrgSettings(orgID string) (*OrgSettingsRow, error) {
	return one(tx, scanOrgSettings, orgSettingsGet, sql.Named("org_id", orgID))
}

// PutOrgSettings replaces one organization's policies and moves their version on.
func (tx *TenantTx) PutOrgSettings(r *OrgSettingsRow, now time.Time) error {
	var stages, esc, req, min, def, max any
	if r.DefaultStages != nil {
		b, err := json.Marshal(r.DefaultStages)
		if err != nil {
			return err
		}
		stages = string(b)
	}
	if r.DefaultEscalateHours != nil {
		esc = *r.DefaultEscalateHours
	}
	if r.JustificationReq != nil {
		req = B(*r.JustificationReq)
	}
	if r.JustificationMin != nil {
		min = *r.JustificationMin
	}
	if r.DefaultHours != nil {
		def = *r.DefaultHours
	}
	if r.MaxHours != nil {
		max = *r.MaxHours
	}
	_, err := tx.exec(orgSettingsPut, sql.Named("org_id", r.OrgID), sql.Named("default_stages", stages),
		sql.Named("default_escalate_hours", esc), sql.Named("ov_justification_required", req),
		sql.Named("ov_justification_min_length", min), sql.Named("ov_default_hours", def), sql.Named("ov_max_hours", max),
		sql.Named("updated_by", r.UpdatedBy), sql.Named("updated_at", RT(now)))
	return err
}

// OrgHierarchySource returns where the hierarchy comes from; ErrNotFound if the tenant never set it.
func (tx *TenantTx) OrgHierarchySource() (*OrgHierarchySourceRow, error) {
	return one(tx, func(s scanner) (*OrgHierarchySourceRow, error) {
		var r OrgHierarchySourceRow
		var sys sql.NullString
		var at string
		if err := s.Scan(&r.Source, &sys, &r.Version, &r.UpdatedBy, &at); err != nil {
			return nil, err
		}
		r.System = strp(sys)
		var err error
		r.UpdatedAt, err = ParseRT(at)
		return &r, err
	}, orgSourceGet)
}

// PutOrgHierarchySource replaces the hierarchy source and moves its version on.
func (tx *TenantTx) PutOrgHierarchySource(r *OrgHierarchySourceRow, now time.Time) error {
	_, err := tx.exec(orgSourcePut, sql.Named("source", r.Source), sql.Named("system", SP(r.System)),
		sql.Named("updated_by", r.UpdatedBy), sql.Named("updated_at", RT(now)))
	return err
}
