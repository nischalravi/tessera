-- Amending a live access request (issue #588): comments and attachment metadata that people add
-- to a pending line. Both are append-only. An attachment is metadata only (a name, a type, a size
-- the server capped, and an optional reference such as a ticket link); Tessera stores no files.
-- Adding an approver needs no table: it appends a stage to access_request_stages.
--
-- Tenant-owned like 0001_tenancy.sql.
CREATE TABLE IF NOT EXISTS access_request_comments (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  line_id TEXT NOT NULL REFERENCES access_request_lines (id),
  author_user_id TEXT NOT NULL REFERENCES platform_users (id),
  author TEXT NOT NULL,
  body TEXT NOT NULL CHECK (length(body) BETWEEN 1 AND 1000),
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_request_comments_tenant_line ON access_request_comments (tenant_id, line_id, created_at);

CREATE TABLE IF NOT EXISTS access_request_attachments (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  line_id TEXT NOT NULL REFERENCES access_request_lines (id),
  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  content_type TEXT NOT NULL DEFAULT '' CHECK (length(content_type) <= 100),
  size_bytes INTEGER NOT NULL CHECK (size_bytes BETWEEN 0 AND 10485760),
  reference TEXT NOT NULL DEFAULT '' CHECK (length(reference) <= 300),
  added_by TEXT NOT NULL REFERENCES platform_users (id),
  added_by_name TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_request_attachments_tenant_line ON access_request_attachments (tenant_id, line_id, created_at);

CREATE TRIGGER IF NOT EXISTS tg_request_comments_no_update BEFORE UPDATE ON access_request_comments
BEGIN SELECT RAISE(ABORT, 'access_request_comments is append-only'); END;
CREATE TRIGGER IF NOT EXISTS tg_request_comments_no_delete BEFORE DELETE ON access_request_comments
BEGIN SELECT RAISE(ABORT, 'access_request_comments is append-only'); END;
CREATE TRIGGER IF NOT EXISTS tg_request_attachments_no_update BEFORE UPDATE ON access_request_attachments
BEGIN SELECT RAISE(ABORT, 'access_request_attachments is append-only'); END;
CREATE TRIGGER IF NOT EXISTS tg_request_attachments_no_delete BEFORE DELETE ON access_request_attachments
BEGIN SELECT RAISE(ABORT, 'access_request_attachments is append-only'); END;

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_access_request_comments_xtenant_ins BEFORE INSERT ON access_request_comments
WHEN EXISTS (SELECT 1 FROM access_request_lines p WHERE p.id = NEW.line_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.author_user_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: access_request_comments'); END;

CREATE TRIGGER IF NOT EXISTS tg_access_request_attachments_xtenant_ins BEFORE INSERT ON access_request_attachments
WHEN EXISTS (SELECT 1 FROM access_request_lines p WHERE p.id = NEW.line_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.added_by AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: access_request_attachments'); END;

CREATE TRIGGER IF NOT EXISTS tg_access_request_comments_xtenant_upd BEFORE UPDATE OF tenant_id, line_id, author_user_id ON access_request_comments
WHEN EXISTS (SELECT 1 FROM access_request_lines p WHERE p.id = NEW.line_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.author_user_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: access_request_comments'); END;

CREATE TRIGGER IF NOT EXISTS tg_access_request_attachments_xtenant_upd BEFORE UPDATE OF tenant_id, line_id, added_by ON access_request_attachments
WHEN EXISTS (SELECT 1 FROM access_request_lines p WHERE p.id = NEW.line_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.added_by AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: access_request_attachments'); END;
