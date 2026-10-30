package store

import (
	"database/sql"
	"time"
)

// Agent scopes as code (schema/0956_agent_scopes.sql, issue #653, AC-7). Every statement binds the tenant.

// Agent scope statuses.
const (
	AgentScopeActive  = "active"
	AgentScopeRetired = "retired"
)

// AgentScope is one scope of the policy repository (agents/<key>.yaml). Doc is the canonical JSON of the
// tessera.agentscope/v1 document, which internal/agentscope reads and writes.
type AgentScope struct {
	ID        string
	Key       string
	Status    string
	Name      string
	Doc       string
	DocSHA256 string
	Version   int
	CreatedAt time.Time
	UpdatedAt time.Time
}

// AgentScopeVersion is a snapshot of one change of a scope.
type AgentScopeVersion struct {
	ID        int64
	ScopeID   string
	Version   int
	Snapshot  string // JSON
	Actor     string
	ChangedAt time.Time
	PolicyRef *string // JSON {commit, path, bundle_sha256}
}

const asCols = `s.id, s.key, s.status, s.name, s.doc, s.doc_sha256, s.version, s.created_at, s.updated_at`

var (
	asList = tq("agent_scopes.list", `
		SELECT `+asCols+` FROM agent_scopes s WHERE s.tenant_id = @tenant ORDER BY s.key`)
	asByKey = tq("agent_scopes.by_key", `
		SELECT `+asCols+` FROM agent_scopes s WHERE s.tenant_id = @tenant AND s.key = @key`)
	asInsert = tq("agent_scopes.insert", `
		INSERT INTO agent_scopes (id, tenant_id, key, status, name, doc, doc_sha256, version, created_at, updated_at)
		VALUES (@id, @tenant, @key, @status, @name, @doc, @doc_sha256, @version, @created_at, @updated_at)`)
	asSave = tq("agent_scopes.save", `
		UPDATE agent_scopes SET status = @status, name = @name, doc = @doc, doc_sha256 = @doc_sha256,
			version = @version, updated_at = @updated_at
		WHERE tenant_id = @tenant AND id = @id AND version = @from_version`)

	asvInsert = tq("agent_scope_versions.insert", `
		INSERT INTO agent_scope_versions (tenant_id, scope_id, version, snapshot, actor, changed_at, policy_ref)
		VALUES (@tenant, @scope_id, @version, @snapshot, @actor, @changed_at, @policy_ref)`)
	asvForScope = tq("agent_scope_versions.for_scope", `
		SELECT v.id, v.scope_id, v.version, v.snapshot, v.actor, v.changed_at, v.policy_ref
		FROM agent_scope_versions v WHERE v.tenant_id = @tenant AND v.scope_id = @scope_id
		ORDER BY v.version DESC`)
)

func scanAgentScope(s scanner) (*AgentScope, error) {
	var a AgentScope
	var created, updated string
	if err := s.Scan(&a.ID, &a.Key, &a.Status, &a.Name, &a.Doc, &a.DocSHA256, &a.Version, &created, &updated); err != nil {
		return nil, err
	}
	var err error
	if a.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	a.UpdatedAt, err = ParseRT(updated)
	return &a, err
}

// AgentScopes returns every scope, retired ones included, by key.
func (tx *TenantTx) AgentScopes() ([]*AgentScope, error) { return collect(tx, scanAgentScope, asList) }

// AgentScopeByKey returns the scope with the key, or ErrNotFound.
func (tx *TenantTx) AgentScopeByKey(key string) (*AgentScope, error) {
	return one(tx, scanAgentScope, asByKey, sql.Named("key", key))
}

func agentScopeArgs(a *AgentScope) []sql.NamedArg {
	return []sql.NamedArg{sql.Named("id", a.ID), sql.Named("status", a.Status), sql.Named("name", a.Name),
		sql.Named("doc", a.Doc), sql.Named("doc_sha256", a.DocSHA256), sql.Named("version", a.Version),
		sql.Named("updated_at", RT(a.UpdatedAt))}
}

// InsertAgentScope creates a scope (the id is made when empty). ErrDuplicate: the key is taken.
func (tx *TenantTx) InsertAgentScope(a *AgentScope) error {
	if a.ID == "" {
		a.ID = NewID()
	}
	_, err := tx.exec(asInsert, append(agentScopeArgs(a), sql.Named("key", a.Key), sql.Named("created_at", RT(a.CreatedAt)))...)
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// SaveAgentScope updates a scope that is still at version from; ErrNotFound if it moved on or does not exist.
func (tx *TenantTx) SaveAgentScope(a *AgentScope, from int) error {
	res, err := tx.exec(asSave, append(agentScopeArgs(a), sql.Named("from_version", from))...)
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

// AddAgentScopeVersion appends a snapshot.
func (tx *TenantTx) AddAgentScopeVersion(v *AgentScopeVersion) error {
	_, err := tx.exec(asvInsert, sql.Named("scope_id", v.ScopeID), sql.Named("version", v.Version),
		sql.Named("snapshot", v.Snapshot), sql.Named("actor", v.Actor), sql.Named("changed_at", RT(v.ChangedAt)),
		sql.Named("policy_ref", SP(v.PolicyRef)))
	return err
}

// AgentScopeVersions returns a scope's snapshots, newest first.
func (tx *TenantTx) AgentScopeVersions(id string) ([]*AgentScopeVersion, error) {
	return collect(tx, func(s scanner) (*AgentScopeVersion, error) {
		var v AgentScopeVersion
		var ref sql.NullString
		var at string
		if err := s.Scan(&v.ID, &v.ScopeID, &v.Version, &v.Snapshot, &v.Actor, &at, &ref); err != nil {
			return nil, err
		}
		v.PolicyRef = strp(ref)
		var err error
		v.ChangedAt, err = ParseRT(at)
		return &v, err
	}, asvForScope, sql.Named("scope_id", id))
}
