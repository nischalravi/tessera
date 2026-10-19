-- Postgres dialect of schema/0283_provisioning_ops.sql (kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE provisioning_ops (
  rowid BIGINT GENERATED ALWAYS AS IDENTITY,
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  connection_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('create_account','update_account','disable_account','delete_account',
    'add_entitlement','remove_entitlement')),
  target_ref TEXT NOT NULL,
  payload TEXT NOT NULL,
  completion TEXT,
  source TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('queued','sent','pending_verification','verified','mismatch','failed','cancelled')),
  attempts BIGINT NOT NULL DEFAULT 0,
  verify_attempts BIGINT NOT NULL DEFAULT 0,
  next_attempt_at TEXT NOT NULL,
  last_error TEXT,
  observed TEXT,
  requested_by TEXT NOT NULL,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL, completed_at TEXT,
  UNIQUE (tenant_id, idempotency_key),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES connections (tenant_id, id)
);
CREATE INDEX provisioning_ops_due ON provisioning_ops (tenant_id, status, next_attempt_at);
CREATE INDEX provisioning_ops_conn ON provisioning_ops (tenant_id, connection_id);

CREATE TABLE provisioning_findings (
  rowid BIGINT GENERATED ALWAYS AS IDENTITY,
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  op_id TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  code TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('high','medium','low')),
  title TEXT NOT NULL,
  expected TEXT NOT NULL,
  observed TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','resolved')),
  created_at TEXT NOT NULL, resolved_at TEXT,
  UNIQUE (tenant_id, op_id, code),
  FOREIGN KEY (tenant_id, op_id) REFERENCES provisioning_ops (tenant_id, id),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES connections (tenant_id, id)
);
CREATE INDEX provisioning_findings_tenant ON provisioning_findings (tenant_id, status);
