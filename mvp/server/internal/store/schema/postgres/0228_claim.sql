-- Postgres dialect of schema/0228_claim.sql (guest claim, issue #69 / GU-6; kept in parity with the
-- SQLite file by TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE claim_tokens (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  intake_id TEXT NOT NULL,
  identity_id BIGINT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('link','code')),
  purpose TEXT NOT NULL CHECK (purpose IN ('claim','renewal_stepup','recovery')),
  token_hash TEXT NOT NULL CHECK (length(token_hash) = 64),
  email_hmac TEXT NOT NULL CHECK (email_hmac <> ''),
  failed_attempts BIGINT NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
  status TEXT NOT NULL CHECK (status IN ('issued','consumed','revoked','expired','locked')),
  not_before TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  created_at TEXT NOT NULL,
  CHECK (expires_at > not_before),
  CHECK ((status = 'consumed') = (consumed_at IS NOT NULL)),
  UNIQUE (tenant_id, token_hash),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, intake_id) REFERENCES intake_records (tenant_id, id),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id)
);
CREATE INDEX ix_claim_tokens_intake ON claim_tokens (tenant_id, intake_id, status);
CREATE INDEX ix_claim_tokens_email ON claim_tokens (tenant_id, email_hmac, created_at);

CREATE TABLE claim_sessions (
  id_hash TEXT PRIMARY KEY CHECK (length(id_hash) = 64),
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  token_id TEXT NOT NULL,
  intake_id TEXT NOT NULL,
  identity_id BIGINT NOT NULL,
  key_jwk TEXT NOT NULL,
  key_jkt TEXT NOT NULL,
  nonce TEXT NOT NULL CHECK (length(nonce) >= 16),
  step TEXT NOT NULL CHECK (step IN ('verify_contact','verify_identity','existing_account','credential','complete')),
  verified TEXT NOT NULL DEFAULT '{}',
  credential_subject TEXT,
  login_txn_id TEXT,
  created_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  completed_at TEXT,
  CHECK (expires_at > created_at),
  UNIQUE (tenant_id, id_hash),
  FOREIGN KEY (tenant_id, token_id) REFERENCES claim_tokens (tenant_id, id),
  FOREIGN KEY (tenant_id, intake_id) REFERENCES intake_records (tenant_id, id),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id)
);
CREATE INDEX ix_claim_sessions_intake ON claim_sessions (tenant_id, intake_id);
CREATE INDEX ix_claim_sessions_txn ON claim_sessions (tenant_id, login_txn_id);

CREATE TABLE confirmation_codes (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  session_id_hash TEXT NOT NULL,
  channel TEXT NOT NULL CHECK (channel IN ('email','sms','voice')),
  destination_hmac TEXT NOT NULL CHECK (destination_hmac <> ''),
  code_hash TEXT NOT NULL CHECK (length(code_hash) = 64),
  attempts BIGINT NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  voided_at TEXT,
  CHECK (expires_at > created_at),
  FOREIGN KEY (tenant_id, session_id_hash) REFERENCES claim_sessions (tenant_id, id_hash)
);
CREATE INDEX ix_confirmation_codes_session ON confirmation_codes (tenant_id, session_id_hash, created_at);

-- A token's binding never changes and a final token is final; sessions keep their key.
CREATE TRIGGER claim_tokens_immutable BEFORE UPDATE ON claim_tokens
	FOR EACH ROW WHEN (OLD.status <> 'issued' OR NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.intake_id <> OLD.intake_id
		OR NEW.identity_id <> OLD.identity_id OR NEW.kind <> OLD.kind OR NEW.purpose <> OLD.purpose
		OR NEW.token_hash <> OLD.token_hash OR NEW.email_hmac <> OLD.email_hmac OR NEW.not_before <> OLD.not_before
		OR NEW.expires_at <> OLD.expires_at OR NEW.created_at <> OLD.created_at)
	EXECUTE FUNCTION tessera_abort('claim_tokens: final rows and binding columns are immutable');

CREATE TRIGGER claim_tokens_no_delete BEFORE DELETE ON claim_tokens
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('claim_tokens are append-only');

CREATE TRIGGER claim_sessions_immutable BEFORE UPDATE ON claim_sessions
	FOR EACH ROW WHEN (NEW.id_hash <> OLD.id_hash OR NEW.tenant_id <> OLD.tenant_id OR NEW.token_id <> OLD.token_id
		OR NEW.intake_id <> OLD.intake_id OR NEW.identity_id <> OLD.identity_id OR NEW.key_jwk <> OLD.key_jwk
		OR NEW.key_jkt <> OLD.key_jkt OR NEW.nonce <> OLD.nonce OR NEW.created_at <> OLD.created_at
		OR (OLD.completed_at IS NOT NULL AND NEW.completed_at IS DISTINCT FROM OLD.completed_at))
	EXECUTE FUNCTION tessera_abort('claim_sessions: key, binding and completion are immutable');

CREATE TRIGGER claim_sessions_no_delete BEFORE DELETE ON claim_sessions
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('claim_sessions are append-only');

CREATE TRIGGER confirmation_codes_immutable BEFORE UPDATE ON confirmation_codes
	FOR EACH ROW WHEN (NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.session_id_hash <> OLD.session_id_hash
		OR NEW.channel <> OLD.channel OR NEW.destination_hmac <> OLD.destination_hmac OR NEW.code_hash <> OLD.code_hash
		OR NEW.created_at <> OLD.created_at OR NEW.expires_at <> OLD.expires_at
		OR (OLD.used_at IS NOT NULL AND NEW.used_at IS DISTINCT FROM OLD.used_at))
	EXECUTE FUNCTION tessera_abort('confirmation_codes: binding columns and use are immutable');

CREATE TRIGGER confirmation_codes_no_delete BEFORE DELETE ON confirmation_codes
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('confirmation_codes are append-only');
