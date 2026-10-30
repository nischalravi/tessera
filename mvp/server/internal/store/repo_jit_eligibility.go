package store

import (
	"database/sql"
	"errors"
	"time"
)

// JIT eligibility as code (schema/0954_jit_eligibility.sql, issue #651, AC-5). Every statement binds the tenant.

// JIT eligibility statuses.
const (
	JITEligibilityActive  = "active"
	JITEligibilityRetired = "retired"
)

// The roles a group plays in an eligibility rule.
const (
	JITPrincipal   = "principal"   // membership lets a person ask
	JITEntitlement = "entitlement" // what may be asked for
	JITApprover    = "approver"    // membership lets a person approve
)

// JITSettings says whether the tenant's JIT requests are decided by eligibility rules (deny by default) or, until
// then, by groups.requestable.
type JITSettings struct {
	Enabled   bool
	UpdatedBy string
	UpdatedAt time.Time
}

// JITEligibility is one rule: the people in Principals may ask for the groups in Entitlements for up to MaxHours,
// and the people in Approvers (none: any jit.decide holder) decide.
type JITEligibility struct {
	ID           string
	Key          string
	Status       string
	MaxHours     int
	MinApprovals int
	StepUp       bool
	Version      int
	CreatedAt    time.Time
	UpdatedAt    time.Time
	// The group ids by role, ascending; filled by JITEligibilities and JITEligibilityByKey.
	Principals   []int64
	Entitlements []int64
	Approvers    []int64
}

// JITEligibilityVersion is a snapshot of one change of a rule.
type JITEligibilityVersion struct {
	ID            int64
	EligibilityID string
	Version       int
	Snapshot      string // JSON
	Actor         string
	ChangedAt     time.Time
	PolicyRef     *string // JSON {commit, path, bundle_sha256}
}

const jeCols = `e.id, e.key, e.status, e.max_hours, e.min_approvals, e.step_up, e.version, e.created_at, e.updated_at`

var (
	jsGet = tq("jit_settings.get", `
		SELECT s.enabled, s.updated_by, s.updated_at FROM jit_settings s WHERE s.tenant_id = @tenant`)
	jsPut = tq("jit_settings.put", `
		INSERT INTO jit_settings (tenant_id, enabled, updated_by, updated_at) VALUES (@tenant, @enabled, @updated_by, @updated_at)
		ON CONFLICT (tenant_id) DO UPDATE SET enabled = excluded.enabled, updated_by = excluded.updated_by,
			updated_at = excluded.updated_at`)

	jeList = tq("jit_eligibility.list", `
		SELECT `+jeCols+` FROM jit_eligibility e WHERE e.tenant_id = @tenant ORDER BY e.key`)
	jeByKey = tq("jit_eligibility.by_key", `
		SELECT `+jeCols+` FROM jit_eligibility e WHERE e.tenant_id = @tenant AND e.key = @key`)
	jeInsert = tq("jit_eligibility.insert", `
		INSERT INTO jit_eligibility (id, tenant_id, key, status, max_hours, min_approvals, step_up, version, created_at, updated_at)
		VALUES (@id, @tenant, @key, @status, @max_hours, @min_approvals, @step_up, @version, @created_at, @updated_at)`)
	jeSave = tq("jit_eligibility.save", `
		UPDATE jit_eligibility SET status = @status, max_hours = @max_hours, min_approvals = @min_approvals,
			step_up = @step_up, version = @version, updated_at = @updated_at
		WHERE tenant_id = @tenant AND id = @id AND version = @from_version`)

	jgList = tq("jit_eligibility_groups.list", `
		SELECT g.eligibility_id, g.role, g.group_id FROM jit_eligibility_groups g WHERE g.tenant_id = @tenant
		ORDER BY g.eligibility_id, g.role, g.group_id`)
	jgClear = tq("jit_eligibility_groups.clear", `
		DELETE FROM jit_eligibility_groups WHERE tenant_id = @tenant AND eligibility_id = @eligibility_id AND role = @role`)
	jgInsert = tq("jit_eligibility_groups.insert", `
		INSERT INTO jit_eligibility_groups (tenant_id, eligibility_id, role, group_id)
		VALUES (@tenant, @eligibility_id, @role, @group_id)`)

	jvInsert = tq("jit_eligibility_versions.insert", `
		INSERT INTO jit_eligibility_versions (tenant_id, eligibility_id, version, snapshot, actor, changed_at, policy_ref)
		VALUES (@tenant, @eligibility_id, @version, @snapshot, @actor, @changed_at, @policy_ref)`)
	jvForEligibility = tq("jit_eligibility_versions.for_eligibility", `
		SELECT v.id, v.eligibility_id, v.version, v.snapshot, v.actor, v.changed_at, v.policy_ref
		FROM jit_eligibility_versions v WHERE v.tenant_id = @tenant AND v.eligibility_id = @eligibility_id
		ORDER BY v.version DESC`)
)

type jitGroupRow struct {
	eligibility, role string
	group             int64
}

// JITSettings returns the tenant's JIT settings; a tenant that never applied eligibility has them off.
func (tx *TenantTx) JITSettings() (*JITSettings, error) {
	s, err := one(tx, func(r scanner) (*JITSettings, error) {
		var s JITSettings
		var on int
		var at string
		if err := r.Scan(&on, &s.UpdatedBy, &at); err != nil {
			return nil, err
		}
		s.Enabled = on == 1
		var err error
		s.UpdatedAt, err = ParseRT(at)
		return &s, err
	}, jsGet)
	if errors.Is(err, ErrNotFound) {
		return &JITSettings{}, nil
	}
	return s, err
}

// PutJITSettings turns eligibility enforcement on or off.
func (tx *TenantTx) PutJITSettings(enabled bool, by string, now time.Time) error {
	_, err := tx.exec(jsPut, sql.Named("enabled", B(enabled)), sql.Named("updated_by", by), sql.Named("updated_at", RT(now)))
	return err
}

func scanJITEligibility(s scanner) (*JITEligibility, error) {
	var e JITEligibility
	var step int
	var created, updated string
	if err := s.Scan(&e.ID, &e.Key, &e.Status, &e.MaxHours, &e.MinApprovals, &step, &e.Version, &created, &updated); err != nil {
		return nil, err
	}
	e.StepUp = step == 1
	var err error
	if e.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	e.UpdatedAt, err = ParseRT(updated)
	return &e, err
}

func (tx *TenantTx) fillJITGroups(es []*JITEligibility) error {
	rows, err := collect(tx, func(s scanner) (*jitGroupRow, error) {
		var r jitGroupRow
		return &r, s.Scan(&r.eligibility, &r.role, &r.group)
	}, jgList)
	if err != nil {
		return err
	}
	byID := map[string]*JITEligibility{}
	for _, e := range es {
		byID[e.ID] = e
	}
	for _, r := range rows {
		e := byID[r.eligibility]
		if e == nil {
			continue
		}
		switch r.role {
		case JITPrincipal:
			e.Principals = append(e.Principals, r.group)
		case JITEntitlement:
			e.Entitlements = append(e.Entitlements, r.group)
		case JITApprover:
			e.Approvers = append(e.Approvers, r.group)
		}
	}
	return nil
}

// JITEligibilities returns every rule, retired ones included, by key.
func (tx *TenantTx) JITEligibilities() ([]*JITEligibility, error) {
	es, err := collect(tx, scanJITEligibility, jeList)
	if err != nil {
		return nil, err
	}
	return es, tx.fillJITGroups(es)
}

// JITEligibilityByKey returns the rule with the key, or ErrNotFound.
func (tx *TenantTx) JITEligibilityByKey(key string) (*JITEligibility, error) {
	e, err := one(tx, scanJITEligibility, jeByKey, sql.Named("key", key))
	if err != nil {
		return nil, err
	}
	return e, tx.fillJITGroups([]*JITEligibility{e})
}

func jitEligibilityArgs(e *JITEligibility) []sql.NamedArg {
	return []sql.NamedArg{sql.Named("id", e.ID), sql.Named("status", e.Status), sql.Named("max_hours", e.MaxHours),
		sql.Named("min_approvals", e.MinApprovals), sql.Named("step_up", B(e.StepUp)), sql.Named("version", e.Version),
		sql.Named("updated_at", RT(e.UpdatedAt))}
}

// InsertJITEligibility creates a rule (the id is made when empty). ErrDuplicate: the key is taken.
func (tx *TenantTx) InsertJITEligibility(e *JITEligibility) error {
	if e.ID == "" {
		e.ID = NewID()
	}
	_, err := tx.exec(jeInsert, append(jitEligibilityArgs(e), sql.Named("key", e.Key), sql.Named("created_at", RT(e.CreatedAt)))...)
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// SaveJITEligibility updates a rule that is still at version from; ErrNotFound if it moved on or does not exist.
func (tx *TenantTx) SaveJITEligibility(e *JITEligibility, from int) error {
	res, err := tx.exec(jeSave, append(jitEligibilityArgs(e), sql.Named("from_version", from))...)
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

// SetJITEligibilityGroups replaces the groups a rule names in one role (JITPrincipal, JITEntitlement, JITApprover).
func (tx *TenantTx) SetJITEligibilityGroups(id, role string, groups []int64) error {
	if _, err := tx.exec(jgClear, sql.Named("eligibility_id", id), sql.Named("role", role)); err != nil {
		return err
	}
	for _, g := range groups {
		if _, err := tx.exec(jgInsert, sql.Named("eligibility_id", id), sql.Named("role", role), sql.Named("group_id", g)); err != nil {
			return err
		}
	}
	return nil
}

// AddJITEligibilityVersion appends a snapshot.
func (tx *TenantTx) AddJITEligibilityVersion(v *JITEligibilityVersion) error {
	_, err := tx.exec(jvInsert, sql.Named("eligibility_id", v.EligibilityID), sql.Named("version", v.Version),
		sql.Named("snapshot", v.Snapshot), sql.Named("actor", v.Actor), sql.Named("changed_at", RT(v.ChangedAt)),
		sql.Named("policy_ref", SP(v.PolicyRef)))
	return err
}

// JITEligibilityVersions returns a rule's snapshots, newest first.
func (tx *TenantTx) JITEligibilityVersions(id string) ([]*JITEligibilityVersion, error) {
	return collect(tx, func(s scanner) (*JITEligibilityVersion, error) {
		var v JITEligibilityVersion
		var ref sql.NullString
		var at string
		if err := s.Scan(&v.ID, &v.EligibilityID, &v.Version, &v.Snapshot, &v.Actor, &at, &ref); err != nil {
			return nil, err
		}
		v.PolicyRef = strp(ref)
		var err error
		v.ChangedAt, err = ParseRT(at)
		return &v, err
	}, jvForEligibility, sql.Named("eligibility_id", id))
}
