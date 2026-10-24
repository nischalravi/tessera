-- Datasets (issue #588): named lookup tables (a list of allowed cost centers, a list of
-- restricted domains) that rules and request forms read by name. A dataset is a set of
-- distinct string values; version counts every change to its values, so a reader can tell
-- a stale copy. Limits (values per dataset, value length, datasets per tenant) are enforced
-- in internal/datasets.
--
-- Tenant-owned like 0001_tenancy.sql.
CREATE TABLE IF NOT EXISTS datasets (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS dataset_values (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  dataset_id TEXT NOT NULL REFERENCES datasets (id),
  value TEXT NOT NULL CHECK (length(value) BETWEEN 1 AND 200),
  UNIQUE (tenant_id, dataset_id, value)
);

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_dataset_values_xtenant_ins BEFORE INSERT ON dataset_values
WHEN EXISTS (SELECT 1 FROM datasets p WHERE p.id = NEW.dataset_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: dataset_values'); END;

CREATE TRIGGER IF NOT EXISTS tg_dataset_values_xtenant_upd BEFORE UPDATE OF tenant_id, dataset_id ON dataset_values
WHEN EXISTS (SELECT 1 FROM datasets p WHERE p.id = NEW.dataset_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: dataset_values'); END;
