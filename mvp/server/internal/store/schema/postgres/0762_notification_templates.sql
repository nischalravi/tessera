-- Postgres dialect of schema/0762_notification_templates.sql. See 0001_tenancy.sql.

-- +goose Up

CREATE TABLE notification_templates (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  kind TEXT NOT NULL CHECK (length(kind) BETWEEN 1 AND 100),
  subject_tpl TEXT NOT NULL CHECK (length(subject_tpl) <= 300),
  body_tpl TEXT NOT NULL CHECK (length(body_tpl) <= 4000),
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, kind)
);
