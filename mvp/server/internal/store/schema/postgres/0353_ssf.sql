-- Postgres dialect of schema/0353_ssf.sql (kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE ssf_transmitters (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  name TEXT NOT NULL,
  issuer TEXT NOT NULL,
  audience TEXT NOT NULL,
  jwks_url TEXT NOT NULL DEFAULT '',
  jwks_inline TEXT NOT NULL DEFAULT '',
  delivery TEXT NOT NULL CHECK (delivery IN ('push','poll')),
  poll_url TEXT NOT NULL DEFAULT '',
  verification_url TEXT NOT NULL DEFAULT '',
  secret_enc BYTEA,
  api_token_enc BYTEA,
  subject_system TEXT NOT NULL,
  connection_id TEXT,
  status TEXT NOT NULL DEFAULT 'enabled' CHECK (status IN ('enabled','paused','disabled')),
  last_event_at TEXT,
  last_error TEXT NOT NULL DEFAULT '',
  last_error_at TEXT,
  last_polled_at TEXT,
  pending_acks TEXT NOT NULL DEFAULT '[]',
  pending_errs TEXT NOT NULL DEFAULT '{}',
  verification_state TEXT NOT NULL DEFAULT '',
  verification_requested_at TEXT,
  verified_at TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (tenant_id, connection_id) REFERENCES connections (tenant_id, id),
  UNIQUE (tenant_id, id)
);
CREATE UNIQUE INDEX ux_ssf_transmitters_name ON ssf_transmitters (tenant_id, name);

CREATE TABLE ssf_events (
  rowid BIGINT GENERATED ALWAYS AS IDENTITY,
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  transmitter_id TEXT NOT NULL,
  jti TEXT NOT NULL,
  via TEXT NOT NULL CHECK (via IN ('push','poll')),
  event_type TEXT NOT NULL,
  subject_format TEXT NOT NULL DEFAULT '',
  subject TEXT NOT NULL DEFAULT '',
  identity_id BIGINT,
  account_id BIGINT,
  status TEXT NOT NULL CHECK (status IN ('received','matched','actioned','no_action','unmatched','ignored','failed')),
  outcome TEXT NOT NULL DEFAULT '',
  steps BIGINT NOT NULL DEFAULT 0,
  steps_failed BIGINT NOT NULL DEFAULT 0,
  received_at TEXT NOT NULL,
  iat_at TEXT NOT NULL,
  actioned_at TEXT,
  latency_ms BIGINT,
  iat_latency_ms BIGINT,
  FOREIGN KEY (tenant_id, transmitter_id) REFERENCES ssf_transmitters (tenant_id, id),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, account_id) REFERENCES accounts (tenant_id, id)
);
CREATE UNIQUE INDEX ux_ssf_events_jti ON ssf_events (tenant_id, transmitter_id, jti);
CREATE INDEX ix_ssf_events_recent ON ssf_events (tenant_id, transmitter_id, received_at);
