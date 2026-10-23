-- Postgres dialect of schema/0764_email_suppressions.sql. See 0001_tenancy.sql.

-- +goose Up

CREATE TABLE email_suppressions (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  address TEXT NOT NULL CHECK (length(address) BETWEEN 3 AND 320),
  reason TEXT NOT NULL CHECK (reason IN ('hard_bounce', 'manual')),
  note TEXT NOT NULL DEFAULT '' CHECK (length(note) <= 300),
  message_id TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, address)
);
