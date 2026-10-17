package store

import (
	"database/sql"
	"time"
)

// Attribute conditions (schema/0221_abac.sql, issue #162).

// AbacPolicy is a named, versioned attribute condition.
type AbacPolicy struct {
	ID          string
	Name        string
	Description string
	Condition   string // canonical JSON of internal/abac
	Status      string // active, retired
	Version     int
	CreatedAt   time.Time
	UpdatedBy   *string
	UpdatedAt   time.Time
}

// ABAC policy statuses.
const (
	AbacActive  = "active"
	AbacRetired = "retired"
)

// AbacPolicyVersion is a snapshot of one saved change of a policy.
type AbacPolicyVersion struct {
	ID        int64
	PolicyID  string
	Version   int
	Snapshot  string // JSON
	Note      *string
	ChangedBy *string
	Actor     string
	ChangedAt time.Time
}

// AbacBinding attaches a policy to a target (kind catalog_item: the item id).
type AbacBinding struct {
	Kind     string
	TargetID string
	PolicyID string
	BoundBy  *string
	BoundAt  time.Time
}

// ABAC binding kinds.
const BindCatalogItem = "catalog_item"

const apCols = `p.id, p.name, p.description, p.condition, p.status, p.version, p.created_at, p.updated_by, p.updated_at`

var (
	apList = tq("abac_policies.list", `
		SELECT `+apCols+` FROM abac_policies p WHERE p.tenant_id = @tenant ORDER BY p.name, p.id`)
	apGet = tq("abac_policies.get", `
		SELECT `+apCols+` FROM abac_policies p WHERE p.tenant_id = @tenant AND p.id = @id`)
	apByName = tq("abac_policies.by_name", `
		SELECT `+apCols+` FROM abac_policies p WHERE p.tenant_id = @tenant AND p.name = @name`)
	apInsert = tq("abac_policies.insert", `
		INSERT INTO abac_policies (id, tenant_id, name, description, condition, status, version, created_at, updated_by,
			updated_at)
		VALUES (@id, @tenant, @name, @description, @condition, @status, @version, @created_at, @updated_by, @updated_at)`)
	apSave = tq("abac_policies.save", `
		UPDATE abac_policies SET name = @name, description = @description, condition = @condition, status = @status,
			version = @version, updated_by = @updated_by, updated_at = @updated_at
		WHERE tenant_id = @tenant AND id = @id AND version = @from_version`)

	apvInsert = tq("abac_policy_versions.insert", `
		INSERT INTO abac_policy_versions (tenant_id, policy_id, version, snapshot, note, changed_by, actor, changed_at)
		VALUES (@tenant, @policy_id, @version, @snapshot, @note, @changed_by, @actor, @changed_at)`)
	apvForPolicy = tq("abac_policy_versions.for_policy", `
		SELECT v.id, v.policy_id, v.version, v.snapshot, v.note, v.changed_by, v.actor, v.changed_at
		FROM abac_policy_versions v WHERE v.tenant_id = @tenant AND v.policy_id = @policy_id ORDER BY v.version DESC`)

	abList = tq("abac_bindings.list", `
		SELECT b.kind, b.target_id, b.policy_id, b.bound_by, b.bound_at FROM abac_bindings b
		WHERE b.tenant_id = @tenant ORDER BY b.kind, b.target_id`)
	abGet = tq("abac_bindings.get", `
		SELECT b.kind, b.target_id, b.policy_id, b.bound_by, b.bound_at FROM abac_bindings b
		WHERE b.tenant_id = @tenant AND b.kind = @kind AND b.target_id = @target_id`)
	abPut = tq("abac_bindings.put", `
		INSERT INTO abac_bindings (tenant_id, kind, target_id, policy_id, bound_by, bound_at)
		VALUES (@tenant, @kind, @target_id, @policy_id, @bound_by, @bound_at)
		ON CONFLICT (tenant_id, kind, target_id) DO UPDATE SET policy_id = excluded.policy_id,
			bound_by = excluded.bound_by, bound_at = excluded.bound_at`)
	abDelete = tq("abac_bindings.delete", `
		DELETE FROM abac_bindings WHERE tenant_id = @tenant AND kind = @kind AND target_id = @target_id`)
)

func scanAbacPolicy(s scanner) (*AbacPolicy, error) {
	var p AbacPolicy
	var by sql.NullString
	var created, updated nullTime
	if err := s.Scan(&p.ID, &p.Name, &p.Description, &p.Condition, &p.Status, &p.Version, &created, &by, &updated); err != nil {
		return nil, err
	}
	p.UpdatedBy = strp(by)
	var err error
	if p.CreatedAt, err = created.val(); err != nil {
		return nil, err
	}
	p.UpdatedAt, err = updated.val()
	return &p, err
}

func scanAbacVersion(s scanner) (*AbacPolicyVersion, error) {
	var v AbacPolicyVersion
	var note, by sql.NullString
	var at nullTime
	if err := s.Scan(&v.ID, &v.PolicyID, &v.Version, &v.Snapshot, &note, &by, &v.Actor, &at); err != nil {
		return nil, err
	}
	v.Note, v.ChangedBy = strp(note), strp(by)
	var err error
	v.ChangedAt, err = at.val()
	return &v, err
}

func scanAbacBinding(s scanner) (*AbacBinding, error) {
	var b AbacBinding
	var by sql.NullString
	var at nullTime
	if err := s.Scan(&b.Kind, &b.TargetID, &b.PolicyID, &by, &at); err != nil {
		return nil, err
	}
	b.BoundBy = strp(by)
	var err error
	b.BoundAt, err = at.val()
	return &b, err
}

// AbacPolicies returns every policy, by name.
func (tx *TenantTx) AbacPolicies() ([]*AbacPolicy, error) {
	return collect(tx, scanAbacPolicy, apList)
}

// AbacPolicy returns one policy, or ErrNotFound.
func (tx *TenantTx) AbacPolicy(id string) (*AbacPolicy, error) {
	return one(tx, scanAbacPolicy, apGet, sql.Named("id", id))
}

// AbacPolicyByName returns the policy with the name, or ErrNotFound.
func (tx *TenantTx) AbacPolicyByName(name string) (*AbacPolicy, error) {
	return one(tx, scanAbacPolicy, apByName, sql.Named("name", name))
}

func abacArgs(p *AbacPolicy) []sql.NamedArg {
	return []sql.NamedArg{sql.Named("id", p.ID), sql.Named("name", p.Name), sql.Named("description", p.Description),
		sql.Named("condition", p.Condition), sql.Named("status", p.Status), sql.Named("version", p.Version),
		sql.Named("updated_by", SP(p.UpdatedBy)), sql.Named("updated_at", T(p.UpdatedAt))}
}

// InsertAbacPolicy creates a policy.
func (tx *TenantTx) InsertAbacPolicy(p *AbacPolicy) error {
	_, err := tx.exec(apInsert, append(abacArgs(p), sql.Named("created_at", T(p.CreatedAt)))...)
	return err
}

// SaveAbacPolicy updates a policy that is still at version from; ErrNotFound
// if it moved on (a concurrent change) or does not exist.
func (tx *TenantTx) SaveAbacPolicy(p *AbacPolicy, from int) error {
	res, err := tx.exec(apSave, append(abacArgs(p), sql.Named("from_version", from))...)
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

// AddAbacPolicyVersion appends a version snapshot.
func (tx *TenantTx) AddAbacPolicyVersion(v *AbacPolicyVersion) error {
	_, err := tx.exec(apvInsert, sql.Named("policy_id", v.PolicyID), sql.Named("version", v.Version),
		sql.Named("snapshot", v.Snapshot), sql.Named("note", SP(v.Note)), sql.Named("changed_by", SP(v.ChangedBy)),
		sql.Named("actor", v.Actor), sql.Named("changed_at", T(v.ChangedAt)))
	return err
}

// AbacPolicyVersions returns a policy's versions, newest first.
func (tx *TenantTx) AbacPolicyVersions(policyID string) ([]*AbacPolicyVersion, error) {
	return collect(tx, scanAbacVersion, apvForPolicy, sql.Named("policy_id", policyID))
}

// AbacBindings returns every binding.
func (tx *TenantTx) AbacBindings() ([]*AbacBinding, error) {
	return collect(tx, scanAbacBinding, abList)
}

// AbacBinding returns the binding of a target, or ErrNotFound.
func (tx *TenantTx) AbacBinding(kind, targetID string) (*AbacBinding, error) {
	return one(tx, scanAbacBinding, abGet, sql.Named("kind", kind), sql.Named("target_id", targetID))
}

// PutAbacBinding binds (or rebinds) a target to a policy.
func (tx *TenantTx) PutAbacBinding(b *AbacBinding) error {
	_, err := tx.exec(abPut, sql.Named("kind", b.Kind), sql.Named("target_id", b.TargetID),
		sql.Named("policy_id", b.PolicyID), sql.Named("bound_by", SP(b.BoundBy)), sql.Named("bound_at", T(b.BoundAt)))
	return err
}

// DeleteAbacBinding removes a target's binding.
func (tx *TenantTx) DeleteAbacBinding(kind, targetID string) error {
	_, err := tx.exec(abDelete, sql.Named("kind", kind), sql.Named("target_id", targetID))
	return err
}
