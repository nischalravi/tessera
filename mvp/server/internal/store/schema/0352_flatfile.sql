-- Flat-file (CSV) import for disconnected applications (issue #105).
--
-- An app with no connector is registered as a mapping (one per system): which
-- CSV column holds which field. An upload (accounts or account-entitlement
-- rows) is parsed with the mapping, compared with the snapshot the last
-- applied upload left (flatfile_records), and fed to the graph through the
-- normal ingest path. flatfile_uploads, _upload_errors and _changes are
-- history: append-only. A file with any invalid row is rejected whole
-- (status 'rejected', every error listed per row), so a partial file can
-- never make the delta report accounts as removed.
--
-- flatfile_tasks are the manual fulfilment tasks: a leaver or revoke on an
-- account of a disconnected app cannot be carried out by Tessera, so a task
-- stays 'open' until an import confirms the account or entitlement is gone
-- ('confirmed'), or a person closes it with a reason ('closed').
--
-- Tenant-owned like 0001_tenancy.sql: the guard triggers refuse a reference
-- to another tenant's mapping, upload, account or identity.
CREATE TABLE IF NOT EXISTS flatfile_mappings (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  system TEXT NOT NULL,
  name TEXT NOT NULL,
  owner TEXT NOT NULL DEFAULT '',
  account_cols TEXT NOT NULL,
  entitlement_cols TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, system)
);

CREATE TABLE IF NOT EXISTS flatfile_uploads (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  mapping_id TEXT NOT NULL REFERENCES flatfile_mappings (id),
  system TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('accounts','entitlements')),
  source TEXT NOT NULL DEFAULT 'api' CHECK (source IN ('api','sftp')),
  filename TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('applied','rejected')),
  rows_total INTEGER NOT NULL,
  rows_rejected INTEGER NOT NULL,
  added INTEGER NOT NULL,
  removed INTEGER NOT NULL,
  changed INTEGER NOT NULL,
  unchanged INTEGER NOT NULL,
  tasks_confirmed INTEGER NOT NULL DEFAULT 0,
  uploaded_by TEXT NOT NULL,
  uploaded_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_flatfile_uploads_system ON flatfile_uploads (tenant_id, system, uploaded_at);

CREATE TABLE IF NOT EXISTS flatfile_upload_errors (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  upload_id TEXT NOT NULL REFERENCES flatfile_uploads (id),
  seq INTEGER NOT NULL,
  row_num INTEGER NOT NULL,
  col TEXT NOT NULL,
  code TEXT NOT NULL,
  message TEXT NOT NULL,
  PRIMARY KEY (tenant_id, upload_id, seq)
);

CREATE TABLE IF NOT EXISTS flatfile_changes (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  upload_id TEXT NOT NULL REFERENCES flatfile_uploads (id),
  seq INTEGER NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('accounts','entitlements')),
  change TEXT NOT NULL CHECK (change IN ('added','removed','changed')),
  label TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (tenant_id, upload_id, seq)
);

-- The snapshot the last applied upload of each kind left: the baseline of
-- the next delta. rec_key is the account id (accounts) or account id, unit
-- separator, entitlement (entitlements); data is the normalised row (JSON).
CREATE TABLE IF NOT EXISTS flatfile_records (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  system TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('accounts','entitlements')),
  rec_key TEXT NOT NULL,
  data TEXT NOT NULL,
  row_hash TEXT NOT NULL,
  upload_id TEXT NOT NULL REFERENCES flatfile_uploads (id),
  PRIMARY KEY (tenant_id, system, kind, rec_key)
);

CREATE TABLE IF NOT EXISTS flatfile_tasks (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  system TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('disable_account','remove_entitlement')),
  account_id INTEGER NOT NULL REFERENCES accounts (id),
  account_xid TEXT NOT NULL,
  account_label TEXT NOT NULL,
  entitlement TEXT NOT NULL DEFAULT '',
  identity_id INTEGER REFERENCES identities (id),
  trigger TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','confirmed','closed')),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  closed_by TEXT,
  closed_at TEXT,
  close_reason TEXT NOT NULL DEFAULT '',
  closed_upload_id TEXT REFERENCES flatfile_uploads (id),
  CHECK ((status = 'open') = (closed_at IS NULL))
);
CREATE INDEX IF NOT EXISTS ix_flatfile_tasks_status ON flatfile_tasks (tenant_id, status, created_at);
CREATE INDEX IF NOT EXISTS ix_flatfile_tasks_system ON flatfile_tasks (tenant_id, system, status);
-- one open task per account and step
CREATE UNIQUE INDEX IF NOT EXISTS ux_flatfile_tasks_open ON flatfile_tasks (tenant_id, account_id, kind, entitlement) WHERE status = 'open';

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_flatfile_uploads_xtenant_ins BEFORE INSERT ON flatfile_uploads
WHEN EXISTS (SELECT 1 FROM flatfile_mappings p WHERE p.id = NEW.mapping_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: flatfile_uploads'); END;

CREATE TRIGGER IF NOT EXISTS tg_flatfile_uploads_xtenant_upd BEFORE UPDATE OF tenant_id, mapping_id ON flatfile_uploads
WHEN EXISTS (SELECT 1 FROM flatfile_mappings p WHERE p.id = NEW.mapping_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: flatfile_uploads'); END;

CREATE TRIGGER IF NOT EXISTS tg_flatfile_upload_errors_xtenant_ins BEFORE INSERT ON flatfile_upload_errors
WHEN EXISTS (SELECT 1 FROM flatfile_uploads p WHERE p.id = NEW.upload_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: flatfile_upload_errors'); END;

CREATE TRIGGER IF NOT EXISTS tg_flatfile_upload_errors_xtenant_upd BEFORE UPDATE OF tenant_id, upload_id ON flatfile_upload_errors
WHEN EXISTS (SELECT 1 FROM flatfile_uploads p WHERE p.id = NEW.upload_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: flatfile_upload_errors'); END;

CREATE TRIGGER IF NOT EXISTS tg_flatfile_changes_xtenant_ins BEFORE INSERT ON flatfile_changes
WHEN EXISTS (SELECT 1 FROM flatfile_uploads p WHERE p.id = NEW.upload_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: flatfile_changes'); END;

CREATE TRIGGER IF NOT EXISTS tg_flatfile_changes_xtenant_upd BEFORE UPDATE OF tenant_id, upload_id ON flatfile_changes
WHEN EXISTS (SELECT 1 FROM flatfile_uploads p WHERE p.id = NEW.upload_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: flatfile_changes'); END;

CREATE TRIGGER IF NOT EXISTS tg_flatfile_records_xtenant_ins BEFORE INSERT ON flatfile_records
WHEN EXISTS (SELECT 1 FROM flatfile_uploads p WHERE p.id = NEW.upload_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: flatfile_records'); END;

CREATE TRIGGER IF NOT EXISTS tg_flatfile_records_xtenant_upd BEFORE UPDATE OF tenant_id, upload_id ON flatfile_records
WHEN EXISTS (SELECT 1 FROM flatfile_uploads p WHERE p.id = NEW.upload_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: flatfile_records'); END;

CREATE TRIGGER IF NOT EXISTS tg_flatfile_tasks_xtenant_ins BEFORE INSERT ON flatfile_tasks
WHEN EXISTS (SELECT 1 FROM accounts p WHERE p.id = NEW.account_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.closed_upload_id IS NOT NULL AND EXISTS (SELECT 1 FROM flatfile_uploads p WHERE p.id = NEW.closed_upload_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: flatfile_tasks'); END;

CREATE TRIGGER IF NOT EXISTS tg_flatfile_tasks_xtenant_upd BEFORE UPDATE OF tenant_id, account_id, identity_id, closed_upload_id ON flatfile_tasks
WHEN EXISTS (SELECT 1 FROM accounts p WHERE p.id = NEW.account_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.closed_upload_id IS NOT NULL AND EXISTS (SELECT 1 FROM flatfile_uploads p WHERE p.id = NEW.closed_upload_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: flatfile_tasks'); END;

-- Upload history is append-only; a closed task is history too.

CREATE TRIGGER IF NOT EXISTS tg_flatfile_uploads_no_update BEFORE UPDATE ON flatfile_uploads
BEGIN SELECT RAISE(ABORT, 'flatfile_uploads is append-only'); END;

CREATE TRIGGER IF NOT EXISTS tg_flatfile_uploads_no_delete BEFORE DELETE ON flatfile_uploads
BEGIN SELECT RAISE(ABORT, 'flatfile_uploads is append-only'); END;

CREATE TRIGGER IF NOT EXISTS tg_flatfile_upload_errors_no_update BEFORE UPDATE ON flatfile_upload_errors
BEGIN SELECT RAISE(ABORT, 'flatfile_upload_errors is append-only'); END;

CREATE TRIGGER IF NOT EXISTS tg_flatfile_upload_errors_no_delete BEFORE DELETE ON flatfile_upload_errors
BEGIN SELECT RAISE(ABORT, 'flatfile_upload_errors is append-only'); END;

CREATE TRIGGER IF NOT EXISTS tg_flatfile_changes_no_update BEFORE UPDATE ON flatfile_changes
BEGIN SELECT RAISE(ABORT, 'flatfile_changes is append-only'); END;

CREATE TRIGGER IF NOT EXISTS tg_flatfile_changes_no_delete BEFORE DELETE ON flatfile_changes
BEGIN SELECT RAISE(ABORT, 'flatfile_changes is append-only'); END;

CREATE TRIGGER IF NOT EXISTS tg_flatfile_tasks_closed_immutable BEFORE UPDATE ON flatfile_tasks
WHEN OLD.status <> 'open'
BEGIN SELECT RAISE(ABORT, 'flatfile_tasks: a closed task cannot change'); END;

CREATE TRIGGER IF NOT EXISTS tg_flatfile_tasks_no_delete BEFORE DELETE ON flatfile_tasks
BEGIN SELECT RAISE(ABORT, 'flatfile_tasks is append-only'); END;
