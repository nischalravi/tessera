-- Postgres dialect of schema/0765_tenant_label_settings.sql. See 0001_tenancy.sql.

-- +goose Up

CREATE TABLE tenant_label_settings (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  default_language TEXT NOT NULL DEFAULT '' CHECK (length(default_language) <= 10),
  email_logo BIGINT NOT NULL DEFAULT 0 CHECK (email_logo IN (0, 1)),
  labels TEXT NOT NULL DEFAULT '{}' CHECK (labels IS JSON),
  version BIGINT NOT NULL DEFAULT 1,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
