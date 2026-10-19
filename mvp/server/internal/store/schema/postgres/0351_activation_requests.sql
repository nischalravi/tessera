-- Postgres dialect of schema/0351_activation_requests.sql (kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE connection_activation_requests (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  connection_id TEXT NOT NULL,
  revision_id TEXT NOT NULL,
  config_hash TEXT NOT NULL,
  write_mode TEXT NOT NULL CHECK (write_mode IN ('dry_run','scoped')),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','applied','rejected','cancelled','expired')),
  requested_by_key TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  requested_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  decided_by_key TEXT,
  decided_by TEXT,
  decided_at TEXT,
  decision_note TEXT NOT NULL DEFAULT '',
  CHECK (status = 'pending' OR decided_at IS NOT NULL),
  CHECK (status <> 'applied' OR decided_by_key <> requested_by_key),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES connections (tenant_id, id),
  FOREIGN KEY (tenant_id, revision_id) REFERENCES connection_revisions (tenant_id, id)
);
CREATE INDEX ix_activation_requests_conn ON connection_activation_requests (tenant_id, connection_id, requested_at);
-- at most one open request per revision
CREATE UNIQUE INDEX ux_activation_requests_open ON connection_activation_requests (tenant_id, revision_id) WHERE status = 'pending';
