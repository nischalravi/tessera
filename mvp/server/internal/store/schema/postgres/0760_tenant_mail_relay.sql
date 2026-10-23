-- Postgres dialect of schema/0760_tenant_mail_relay.sql. See 0001_tenancy.sql. password_sealed is BYTEA.

-- +goose Up

CREATE TABLE tenant_mail_relay (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  enabled BIGINT NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
  host TEXT NOT NULL CHECK (length(host) BETWEEN 1 AND 253),
  port BIGINT NOT NULL CHECK (port BETWEEN 1 AND 65535),
  tls TEXT NOT NULL CHECK (tls IN ('starttls', 'tls', 'none')),
  username TEXT NOT NULL DEFAULT '' CHECK (length(username) <= 256),
  password_sealed BYTEA,
  from_address TEXT NOT NULL CHECK (length(from_address) BETWEEN 3 AND 320),
  last_test_at TEXT,
  last_test_outcome TEXT NOT NULL DEFAULT '' CHECK (length(last_test_outcome) <= 300),
  version BIGINT NOT NULL DEFAULT 1,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
