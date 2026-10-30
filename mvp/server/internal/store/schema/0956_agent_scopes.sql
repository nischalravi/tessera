-- Agent scopes as code (issue #653, AC-7; design docs/design/access-as-code-repo.md section 3.5): what an AI agent
-- may do, declared in agents/<key>.yaml of the policy repository. An agent with an active scope may hold only
-- permissions inside it (and, unless the scope says otherwise, only what its owner holds); anything else is a
-- violation of the agent-out-of-scope or agent-exceeds-owner invariant (internal/policy).
--
-- agent_scopes: one row per scope key; status active or retired (a retired scope is kept, never deleted, and
-- stops applying); doc is the canonical JSON of the tessera.agentscope/v1 document (internal/agentscope) and
-- doc_sha256 its digest; version counts the changes, each one a row of agent_scope_versions. Every row was written by
-- an apply, so every scope is managed by the repository: full mode may retire one a later bundle no longer lists.
--
-- agent_scope_versions: append-only snapshots of each change with the policy_ref {commit, path, bundle_sha256} of
-- the repository change that made it.
--
-- Tenant-owned: tenant_id on every row, every unique index starts with it, guard triggers at the end refuse a
-- version of another tenant's scope. Postgres: migration 0963.
CREATE TABLE IF NOT EXISTS agent_scopes (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  key TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','retired')),
  name TEXT NOT NULL,
  doc TEXT NOT NULL,
  doc_sha256 TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, key)
);

CREATE TABLE IF NOT EXISTS agent_scope_versions (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  scope_id TEXT NOT NULL REFERENCES agent_scopes (id),
  version INTEGER NOT NULL,
  snapshot TEXT NOT NULL,
  actor TEXT NOT NULL,
  changed_at TEXT NOT NULL,
  policy_ref TEXT,
  UNIQUE (tenant_id, scope_id, version)
);

CREATE TRIGGER IF NOT EXISTS tg_agent_scope_versions_no_update BEFORE UPDATE ON agent_scope_versions
BEGIN SELECT RAISE(ABORT, 'agent_scope_versions is append-only'); END;
CREATE TRIGGER IF NOT EXISTS tg_agent_scope_versions_no_delete BEFORE DELETE ON agent_scope_versions
BEGIN SELECT RAISE(ABORT, 'agent_scope_versions is append-only'); END;

-- Cross-tenant reference guards (same pattern as 0954_jit_eligibility.sql).

CREATE TRIGGER IF NOT EXISTS tg_agent_scope_versions_xtenant_ins BEFORE INSERT ON agent_scope_versions
WHEN EXISTS (SELECT 1 FROM agent_scopes p WHERE p.id = NEW.scope_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: agent_scope_versions'); END;

CREATE TRIGGER IF NOT EXISTS tg_agent_scope_versions_xtenant_upd BEFORE UPDATE OF tenant_id, scope_id ON agent_scope_versions
WHEN EXISTS (SELECT 1 FROM agent_scopes p WHERE p.id = NEW.scope_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: agent_scope_versions'); END;
