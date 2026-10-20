-- Shared Signals receiver (issue #114): the transmitters a tenant accepts
-- OpenID Shared Signals Framework (SSF) events from, and every event received.
-- CAEP session-revoked and credential-change and RISC account-disabled run the
-- kill switch (internal/containment) on the subject's other linked accounts.
--
-- ssf_transmitters: one row per transmitter. secret_enc is the push receiver
-- auth secret (or, for a poll stream, the poll bearer token) and api_token_enc
-- the optional token for the transmitter's own API (verification requests);
-- both are sealed with internal/seal (AES-256-GCM, AAD bound to tenant, table,
-- column and transmitter id) and never stored or logged in the clear. The JWKS
-- is public. pending_acks and pending_errs hold what the next poll request
-- sends (RFC 8936 "ack" and "setErrs"): a jti is acknowledged only after its
-- event row is committed.
--
-- ssf_events: one row per SET that passed signature and claim validation.
-- UNIQUE (tenant_id, transmitter_id, jti) is the replay table: a jti is
-- accepted once. latency_ms is receipt to the last action done, iat_latency_ms
-- the SET's iat to the last action done.
--
-- Tenant-owned like 0001_tenancy.sql: the guard triggers at the end refuse a
-- reference to another tenant's connection, identity, account or transmitter.
CREATE TABLE IF NOT EXISTS ssf_transmitters (
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
  secret_enc BLOB,
  api_token_enc BLOB,
  subject_system TEXT NOT NULL,
  connection_id TEXT REFERENCES connections (id),
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
  updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_ssf_transmitters_name ON ssf_transmitters (tenant_id, name);

CREATE TABLE IF NOT EXISTS ssf_events (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  transmitter_id TEXT NOT NULL REFERENCES ssf_transmitters (id),
  jti TEXT NOT NULL,
  via TEXT NOT NULL CHECK (via IN ('push','poll')),
  event_type TEXT NOT NULL,
  subject_format TEXT NOT NULL DEFAULT '',
  subject TEXT NOT NULL DEFAULT '',
  identity_id INTEGER REFERENCES identities (id),
  account_id INTEGER REFERENCES accounts (id),
  status TEXT NOT NULL CHECK (status IN ('received','matched','actioned','no_action','unmatched','ignored','failed')),
  outcome TEXT NOT NULL DEFAULT '',
  steps INTEGER NOT NULL DEFAULT 0,
  steps_failed INTEGER NOT NULL DEFAULT 0,
  received_at TEXT NOT NULL,
  iat_at TEXT NOT NULL,
  actioned_at TEXT,
  latency_ms INTEGER,
  iat_latency_ms INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_ssf_events_jti ON ssf_events (tenant_id, transmitter_id, jti);
CREATE INDEX IF NOT EXISTS ix_ssf_events_recent ON ssf_events (tenant_id, transmitter_id, received_at);

CREATE TRIGGER IF NOT EXISTS tg_ssf_transmitters_xtenant_ins BEFORE INSERT ON ssf_transmitters
WHEN NEW.connection_id IS NOT NULL AND EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: ssf_transmitters'); END;

CREATE TRIGGER IF NOT EXISTS tg_ssf_transmitters_xtenant_upd BEFORE UPDATE OF tenant_id, connection_id ON ssf_transmitters
WHEN NEW.connection_id IS NOT NULL AND EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: ssf_transmitters'); END;

CREATE TRIGGER IF NOT EXISTS tg_ssf_events_xtenant_ins BEFORE INSERT ON ssf_events
WHEN EXISTS (SELECT 1 FROM ssf_transmitters p WHERE p.id = NEW.transmitter_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.account_id IS NOT NULL AND EXISTS (SELECT 1 FROM accounts p WHERE p.id = NEW.account_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: ssf_events'); END;

CREATE TRIGGER IF NOT EXISTS tg_ssf_events_xtenant_upd BEFORE UPDATE OF tenant_id, transmitter_id, identity_id, account_id ON ssf_events
WHEN EXISTS (SELECT 1 FROM ssf_transmitters p WHERE p.id = NEW.transmitter_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.account_id IS NOT NULL AND EXISTS (SELECT 1 FROM accounts p WHERE p.id = NEW.account_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: ssf_events'); END;
