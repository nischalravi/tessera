-- Postgres dialect of schema/0206_approvals.sql (Phase 0 PR14 dialect, kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE approval_policies (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  catalog_item_id TEXT NOT NULL,
  stages TEXT NOT NULL,
  escalate_after_hours DOUBLE PRECISION NOT NULL DEFAULT 48 CHECK (escalate_after_hours > 0),
  updated_by TEXT,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, catalog_item_id),
  FOREIGN KEY (tenant_id, catalog_item_id) REFERENCES catalog_items (tenant_id, id)
);

CREATE TABLE access_request_stages (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  line_id TEXT NOT NULL,
  idx BIGINT NOT NULL CHECK (idx >= 0),
  kind TEXT NOT NULL CHECK (kind IN ('manager','owner','decider','sponsor')),
  assignee_identity_id BIGINT,
  status TEXT NOT NULL CHECK (status IN ('queued','waiting','approved','denied','closed')),
  started_at TEXT,
  due_at TEXT,
  decided_by TEXT,
  on_behalf_of TEXT,
  decided_at TEXT,
  reason TEXT,
  PRIMARY KEY (tenant_id, line_id, idx),
  FOREIGN KEY (tenant_id, line_id) REFERENCES access_request_lines (tenant_id, id),
  FOREIGN KEY (tenant_id, assignee_identity_id) REFERENCES identities (tenant_id, id)
);

CREATE INDEX ix_request_stages_tenant_status ON access_request_stages (tenant_id, status);

CREATE TABLE approval_delegations (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  from_user TEXT NOT NULL,
  to_user TEXT NOT NULL,
  starts_at TEXT NOT NULL,
  ends_at TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL,
  revoked_at TEXT,
  revoked_by TEXT,
  CHECK (from_user <> to_user),
  CHECK (ends_at > starts_at),
  FOREIGN KEY (tenant_id, from_user) REFERENCES platform_users (tenant_id, id),
  FOREIGN KEY (tenant_id, to_user) REFERENCES platform_users (tenant_id, id)
);

CREATE INDEX ix_approval_delegations_tenant_to ON approval_delegations (tenant_id, to_user);
CREATE INDEX ix_approval_delegations_tenant_from ON approval_delegations (tenant_id, from_user);

-- Columns that name a user (or an edge that may expire) but are not foreign keys: SQLite never
-- enforced them, and they hold display strings or ids of rows that may be gone. The guard refuses an
-- id that belongs to ANOTHER tenant and tolerates one that does not exist (tessera_guard_soft_ref).
CREATE TRIGGER tg_approval_policies_updated_by_xtenant BEFORE INSERT OR UPDATE OF tenant_id, updated_by ON approval_policies
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('platform_users', 'updated_by', 'text');
CREATE TRIGGER tg_access_request_stages_on_behalf_of_xtenant BEFORE INSERT OR UPDATE OF tenant_id, on_behalf_of ON access_request_stages
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('platform_users', 'on_behalf_of', 'text');
CREATE TRIGGER tg_access_request_stages_decided_by_xtenant BEFORE INSERT OR UPDATE OF tenant_id, decided_by ON access_request_stages
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('platform_users', 'decided_by', 'text');
CREATE TRIGGER tg_approval_delegations_revoked_by_xtenant BEFORE INSERT OR UPDATE OF tenant_id, revoked_by ON approval_delegations
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('platform_users', 'revoked_by', 'text');
