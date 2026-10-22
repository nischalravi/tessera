-- Contractor (VMS) feeds (issue #304): one row per vendor-management system a
-- tenant reads contractors from. vendor is 'fieldglass' or 'beeline' (read over
-- their REST APIs) or 'csv' (a generic file, uploaded or fetched from a URL).
--
-- settings is a JSON object without secrets (the CSV column mapping, the API
-- paths, the buyer code). The credential is sealed (internal/seal) and bound
-- to this row; it is write-only and never returned or logged. cursor is the
-- watermark of the last good sync: a failed sync leaves it where it was, so a
-- retry reads the same window again (the intake events are idempotent).
--
-- A record read from a feed becomes an intake event of channel 'vms'
-- (0374_intake.sql); a source holds no contractor data itself.
--
-- Tenant-owned like 0001_tenancy.sql; it references no other tenant table.
CREATE TABLE IF NOT EXISTS vms_sources (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  vendor TEXT NOT NULL CHECK (vendor IN ('fieldglass','beeline','csv')),
  name TEXT NOT NULL CHECK (name <> ''),
  base_url TEXT NOT NULL DEFAULT '',
  settings TEXT NOT NULL DEFAULT '{}',
  credential_enc BLOB,
  credential_version TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','paused')),
  cursor TEXT,
  last_sync_at TEXT,
  last_result TEXT CHECK (last_result IN ('ok','failed')),
  last_error TEXT,
  last_counts TEXT NOT NULL DEFAULT '{}',
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, name)
);
CREATE INDEX IF NOT EXISTS ix_vms_sources_tenant ON vms_sources (tenant_id, status);

