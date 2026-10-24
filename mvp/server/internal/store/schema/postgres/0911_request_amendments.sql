-- Postgres dialect of schema/0911_request_amendments.sql. Cross-tenant guard triggers become composite
-- foreign keys. See 0001_tenancy.sql.

-- +goose Up

CREATE TABLE access_request_comments (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  line_id TEXT NOT NULL,
  author_user_id TEXT NOT NULL,
  author TEXT NOT NULL,
  body TEXT NOT NULL CHECK (length(body) BETWEEN 1 AND 1000),
  created_at TEXT NOT NULL,
  FOREIGN KEY (tenant_id, line_id) REFERENCES access_request_lines (tenant_id, id),
  FOREIGN KEY (tenant_id, author_user_id) REFERENCES platform_users (tenant_id, id)
);
CREATE INDEX ix_request_comments_tenant_line ON access_request_comments (tenant_id, line_id, created_at);

CREATE TABLE access_request_attachments (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  line_id TEXT NOT NULL,
  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  content_type TEXT NOT NULL DEFAULT '' CHECK (length(content_type) <= 100),
  size_bytes BIGINT NOT NULL CHECK (size_bytes BETWEEN 0 AND 10485760),
  reference TEXT NOT NULL DEFAULT '' CHECK (length(reference) <= 300),
  added_by TEXT NOT NULL,
  added_by_name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (tenant_id, line_id) REFERENCES access_request_lines (tenant_id, id),
  FOREIGN KEY (tenant_id, added_by) REFERENCES platform_users (tenant_id, id)
);
CREATE INDEX ix_request_attachments_tenant_line ON access_request_attachments (tenant_id, line_id, created_at);

CREATE TRIGGER access_request_comments_no_update BEFORE UPDATE ON access_request_comments
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('access_request_comments is append-only');
CREATE TRIGGER access_request_comments_no_delete BEFORE DELETE ON access_request_comments
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('access_request_comments is append-only');
CREATE TRIGGER access_request_attachments_no_update BEFORE UPDATE ON access_request_attachments
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('access_request_attachments is append-only');
CREATE TRIGGER access_request_attachments_no_delete BEFORE DELETE ON access_request_attachments
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('access_request_attachments is append-only');
