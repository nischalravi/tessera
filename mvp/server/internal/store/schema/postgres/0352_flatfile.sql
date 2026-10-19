-- Postgres dialect of schema/0352_flatfile.sql (kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE flatfile_mappings (
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
  UNIQUE (tenant_id, system),
  UNIQUE (tenant_id, id)
);

CREATE TABLE flatfile_uploads (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  mapping_id TEXT NOT NULL,
  system TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('accounts','entitlements')),
  source TEXT NOT NULL DEFAULT 'api' CHECK (source IN ('api','sftp')),
  filename TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size_bytes BIGINT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('applied','rejected')),
  rows_total BIGINT NOT NULL,
  rows_rejected BIGINT NOT NULL,
  added BIGINT NOT NULL,
  removed BIGINT NOT NULL,
  changed BIGINT NOT NULL,
  unchanged BIGINT NOT NULL,
  tasks_confirmed BIGINT NOT NULL DEFAULT 0,
  uploaded_by TEXT NOT NULL,
  uploaded_at TEXT NOT NULL,
  FOREIGN KEY (tenant_id, mapping_id) REFERENCES flatfile_mappings (tenant_id, id),
  UNIQUE (tenant_id, id)
);
CREATE INDEX ix_flatfile_uploads_system ON flatfile_uploads (tenant_id, system, uploaded_at);

CREATE TABLE flatfile_upload_errors (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  upload_id TEXT NOT NULL,
  seq BIGINT NOT NULL,
  row_num BIGINT NOT NULL,
  col TEXT NOT NULL,
  code TEXT NOT NULL,
  message TEXT NOT NULL,
  PRIMARY KEY (tenant_id, upload_id, seq),
  FOREIGN KEY (tenant_id, upload_id) REFERENCES flatfile_uploads (tenant_id, id)
);

CREATE TABLE flatfile_changes (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  upload_id TEXT NOT NULL,
  seq BIGINT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('accounts','entitlements')),
  change TEXT NOT NULL CHECK (change IN ('added','removed','changed')),
  label TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (tenant_id, upload_id, seq),
  FOREIGN KEY (tenant_id, upload_id) REFERENCES flatfile_uploads (tenant_id, id)
);

-- The snapshot the last applied upload of each kind left: the baseline of
-- the next delta. rec_key is the account id (accounts) or account id, unit
-- separator, entitlement (entitlements); data is the normalised row (JSON).
CREATE TABLE flatfile_records (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  system TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('accounts','entitlements')),
  rec_key TEXT NOT NULL,
  data TEXT NOT NULL,
  row_hash TEXT NOT NULL,
  upload_id TEXT NOT NULL,
  PRIMARY KEY (tenant_id, system, kind, rec_key),
  FOREIGN KEY (tenant_id, upload_id) REFERENCES flatfile_uploads (tenant_id, id)
);

CREATE TABLE flatfile_tasks (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  system TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('disable_account','remove_entitlement')),
  account_id BIGINT NOT NULL,
  account_xid TEXT NOT NULL,
  account_label TEXT NOT NULL,
  entitlement TEXT NOT NULL DEFAULT '',
  identity_id BIGINT,
  trigger TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','confirmed','closed')),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  closed_by TEXT,
  closed_at TEXT,
  close_reason TEXT NOT NULL DEFAULT '',
  closed_upload_id TEXT,
  CHECK ((status = 'open') = (closed_at IS NULL)),
  FOREIGN KEY (tenant_id, account_id) REFERENCES accounts (tenant_id, id),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, closed_upload_id) REFERENCES flatfile_uploads (tenant_id, id)
);
CREATE INDEX ix_flatfile_tasks_status ON flatfile_tasks (tenant_id, status, created_at);
CREATE INDEX ix_flatfile_tasks_system ON flatfile_tasks (tenant_id, system, status);
-- one open task per account and step
CREATE UNIQUE INDEX ux_flatfile_tasks_open ON flatfile_tasks (tenant_id, account_id, kind, entitlement) WHERE status = 'open';

-- Upload history is append-only; a closed task is history too.

CREATE TRIGGER tg_flatfile_uploads_no_update BEFORE UPDATE ON flatfile_uploads
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('flatfile_uploads is append-only');
CREATE TRIGGER tg_flatfile_uploads_no_delete BEFORE DELETE ON flatfile_uploads
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('flatfile_uploads is append-only');
CREATE TRIGGER tg_flatfile_upload_errors_no_update BEFORE UPDATE ON flatfile_upload_errors
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('flatfile_upload_errors is append-only');
CREATE TRIGGER tg_flatfile_upload_errors_no_delete BEFORE DELETE ON flatfile_upload_errors
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('flatfile_upload_errors is append-only');
CREATE TRIGGER tg_flatfile_changes_no_update BEFORE UPDATE ON flatfile_changes
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('flatfile_changes is append-only');
CREATE TRIGGER tg_flatfile_changes_no_delete BEFORE DELETE ON flatfile_changes
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('flatfile_changes is append-only');
CREATE TRIGGER tg_flatfile_tasks_closed_immutable BEFORE UPDATE ON flatfile_tasks
	FOR EACH ROW WHEN (OLD.status <> 'open')
	EXECUTE FUNCTION tessera_abort('flatfile_tasks: a closed task cannot change');
CREATE TRIGGER tg_flatfile_tasks_no_delete BEFORE DELETE ON flatfile_tasks
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('flatfile_tasks is append-only');
