-- Directory CSV import of people and entitlements (issue #915). A file is loaded into one tenant-scoped
-- manual source (a name the admin chooses, never a connector's system); this is the snapshot the last
-- applied import of each kind left, the baseline of the next plan. A row the next file no longer lists is
-- removed only if it is in this snapshot: an object another source owns is never touched. Accounts use
-- the flat-file tables (0352_flatfile.sql).
--
-- Tenant-owned like 0001_tenancy.sql.
CREATE TABLE IF NOT EXISTS dirimport_records (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  system TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('people','entitlements')),
  rec_key TEXT NOT NULL,
  data TEXT NOT NULL,
  row_hash TEXT NOT NULL,
  imported_by TEXT NOT NULL,
  imported_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, system, kind, rec_key)
);
CREATE INDEX IF NOT EXISTS ix_dirimport_records_key ON dirimport_records (tenant_id, kind, rec_key);
