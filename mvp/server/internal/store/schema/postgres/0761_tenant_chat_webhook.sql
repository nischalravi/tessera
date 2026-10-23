-- Postgres dialect of schema/0761_tenant_chat_webhook.sql. See 0001_tenancy.sql. webhook_sealed is BYTEA.

-- +goose Up

CREATE TABLE tenant_chat_webhook (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  provider TEXT NOT NULL CHECK (provider IN ('slack', 'teams')),
  enabled BIGINT NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
  webhook_sealed BYTEA NOT NULL,
  webhook_host TEXT NOT NULL CHECK (length(webhook_host) BETWEEN 1 AND 253),
  kinds TEXT NOT NULL DEFAULT '[]' CHECK (kinds IS JSON),
  cursor_at TEXT NOT NULL,
  cursor_id TEXT NOT NULL DEFAULT '',
  cursor_key TEXT NOT NULL DEFAULT '',
  fail_count BIGINT NOT NULL DEFAULT 0 CHECK (fail_count >= 0),
  last_error TEXT NOT NULL DEFAULT '' CHECK (length(last_error) <= 300),
  last_post_at TEXT,
  version BIGINT NOT NULL DEFAULT 1,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
