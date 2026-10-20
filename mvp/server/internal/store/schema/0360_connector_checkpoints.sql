-- Connector sync checkpoints (issue #104): where an incremental sync of one
-- source system resumes (an Okta lastUpdated watermark, Entra delta links) and
-- the snapshot that cursor applies to, so a restart does not force a full read.
--
-- Tenant-owned like every table of 0001_tenancy.sql: tenant_id references
-- tenants(id) and the primary key starts with tenant_id. The row holds no
-- reference to another tenant-owned table, so there is no guard trigger.
-- cursor and state never hold a credential: the cursor is an opaque position
-- (a timestamp or a Graph delta link) and state is the normalised discovery
-- snapshot, the same data the ingest already writes to the graph tables.
CREATE TABLE IF NOT EXISTS connector_checkpoints (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  system TEXT NOT NULL,
  name TEXT NOT NULL,
  cursor TEXT NOT NULL DEFAULT '',
  state BLOB,
  full_sync_at TEXT,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, system, name)
);
