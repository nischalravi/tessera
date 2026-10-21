-- Postgres dialect of schema/0482_service_account_requests.sql (kept in parity with the SQLite
-- file by TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id).

-- +goose Up

CREATE TABLE service_account_requests (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  kind TEXT NOT NULL CHECK (kind IN ('create','change','transfer')),
  status TEXT NOT NULL CHECK (status IN ('pending','approved','fulfilled','denied','cancelled')),
  identity_id BIGINT,
  name TEXT NOT NULL,
  system TEXT NOT NULL DEFAULT '',
  username TEXT NOT NULL DEFAULT '',
  purpose TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  primary_owner_id BIGINT NOT NULL,
  backup_owner_id BIGINT,
  previous_primary_id BIGINT,
  previous_backup_id BIGINT,
  justification TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  requested_at TEXT NOT NULL,
  decided_by TEXT,
  decided_at TEXT,
  decision_reason TEXT,
  closed_at TEXT,
  fulfilled_at TEXT,
  op_id TEXT,
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, primary_owner_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, backup_owner_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, previous_primary_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, previous_backup_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, requested_by) REFERENCES platform_users (tenant_id, id),
  FOREIGN KEY (tenant_id, decided_by) REFERENCES platform_users (tenant_id, id)
);

CREATE INDEX ix_sa_requests_tenant_status ON service_account_requests (tenant_id, status);
CREATE INDEX ix_sa_requests_tenant_requester ON service_account_requests (tenant_id, requested_by);
CREATE INDEX ix_sa_requests_tenant_identity ON service_account_requests (tenant_id, identity_id);
