-- Postgres dialect of schema/0763_notification_policy.sql. See 0001_tenancy.sql.

-- +goose Up

CREATE TABLE notification_policy (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  review_remind_after_days BIGINT NOT NULL CHECK (review_remind_after_days BETWEEN 1 AND 90),
  review_remind_every_days BIGINT NOT NULL CHECK (review_remind_every_days BETWEEN 1 AND 90),
  request_warn_hours BIGINT NOT NULL CHECK (request_warn_hours BETWEEN 1 AND 720),
  jit_warn_minutes BIGINT NOT NULL CHECK (jit_warn_minutes BETWEEN 5 AND 1440),
  escalate_after_hours BIGINT NOT NULL CHECK (escalate_after_hours BETWEEN 1 AND 720),
  version BIGINT NOT NULL DEFAULT 1,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
