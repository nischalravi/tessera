-- Guest claim: tokens, sessions and confirmation codes (guest accounts design
-- §6.2, §6.4, §9.1, issue #69 / GU-6).
--
-- claim_tokens: the single-use continuation secret in the invitation link. Only
-- SHA-256("tessera-claim-v1|" || tenant || "|" || token) is stored, never the
-- token. A token is bound to the intake record and to the invited email's
-- tenant-keyed hash (email_hmac), has a lifetime per population and is consumed
-- by one atomic UPDATE ... WHERE status = 'issued' AND expires_at > now. A new
-- invitation revokes every earlier token of the intake.
--
-- claim_sessions: what the consumed token buys. The cookie value is stored as
-- a hash (id_hash). The session is bound to a public key held by the claimant's
-- page (a WebCrypto non-extractable key, key_jwk / key_jkt); every request must
-- carry a signature by it (DPoP style), so a stolen cookie alone does not work.
-- 'step' says where the claim stands; 'verified' records what was proven.
-- credential_subject is the subject the credential authority was told to expect;
-- login_txn_id the OIDC login transaction that carries the sign-in.
--
-- confirmation_codes: the 6-digit code mailed to the invited address (only its
-- hash is stored), valid 10 minutes, 5 attempts, then void.
--
-- Tenant-owned like 0001_tenancy.sql: every UNIQUE starts with tenant_id and
-- guard triggers refuse a reference to another tenant's row. Created with IF
-- NOT EXISTS; a reseed drops and recreates (store.tables).

CREATE TABLE IF NOT EXISTS claim_tokens (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  intake_id TEXT NOT NULL REFERENCES intake_records (id),
  identity_id INTEGER NOT NULL REFERENCES identities (id),
  kind TEXT NOT NULL CHECK (kind IN ('link','code')),
  purpose TEXT NOT NULL CHECK (purpose IN ('claim','renewal_stepup','recovery')),
  token_hash TEXT NOT NULL CHECK (length(token_hash) = 64),
  email_hmac TEXT NOT NULL CHECK (email_hmac <> ''),
  failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
  status TEXT NOT NULL CHECK (status IN ('issued','consumed','revoked','expired','locked')),
  not_before TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  created_at TEXT NOT NULL,
  CHECK (expires_at > not_before),
  CHECK ((status = 'consumed') = (consumed_at IS NOT NULL)),
  UNIQUE (tenant_id, token_hash)
);
CREATE INDEX IF NOT EXISTS ix_claim_tokens_intake ON claim_tokens (tenant_id, intake_id, status);
CREATE INDEX IF NOT EXISTS ix_claim_tokens_email ON claim_tokens (tenant_id, email_hmac, created_at);

CREATE TABLE IF NOT EXISTS claim_sessions (
  id_hash TEXT PRIMARY KEY CHECK (length(id_hash) = 64),
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  token_id TEXT NOT NULL REFERENCES claim_tokens (id),
  intake_id TEXT NOT NULL REFERENCES intake_records (id),
  identity_id INTEGER NOT NULL REFERENCES identities (id),
  key_jwk TEXT NOT NULL,
  key_jkt TEXT NOT NULL,
  nonce TEXT NOT NULL CHECK (length(nonce) >= 16),
  step TEXT NOT NULL CHECK (step IN ('verify_contact','existing_account','credential','complete')),
  verified TEXT NOT NULL DEFAULT '{}',
  credential_subject TEXT,
  login_txn_id TEXT,
  created_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  completed_at TEXT,
  CHECK (expires_at > created_at)
);
CREATE INDEX IF NOT EXISTS ix_claim_sessions_intake ON claim_sessions (tenant_id, intake_id);
CREATE INDEX IF NOT EXISTS ix_claim_sessions_txn ON claim_sessions (tenant_id, login_txn_id);

CREATE TABLE IF NOT EXISTS confirmation_codes (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  session_id_hash TEXT NOT NULL REFERENCES claim_sessions (id_hash),
  channel TEXT NOT NULL CHECK (channel IN ('email','sms','voice')),
  destination_hmac TEXT NOT NULL CHECK (destination_hmac <> ''),
  code_hash TEXT NOT NULL CHECK (length(code_hash) = 64),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  voided_at TEXT,
  CHECK (expires_at > created_at)
);
CREATE INDEX IF NOT EXISTS ix_confirmation_codes_session ON confirmation_codes (tenant_id, session_id_hash, created_at);

-- A token's binding never changes and a final token is final; sessions keep their key.
CREATE TRIGGER IF NOT EXISTS tg_claim_tokens_immutable BEFORE UPDATE ON claim_tokens
WHEN OLD.status <> 'issued' OR NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.intake_id <> OLD.intake_id
	OR NEW.identity_id <> OLD.identity_id OR NEW.kind <> OLD.kind OR NEW.purpose <> OLD.purpose
	OR NEW.token_hash <> OLD.token_hash OR NEW.email_hmac <> OLD.email_hmac OR NEW.not_before <> OLD.not_before
	OR NEW.expires_at <> OLD.expires_at OR NEW.created_at <> OLD.created_at
BEGIN SELECT RAISE(ABORT, 'claim_tokens: final rows and binding columns are immutable'); END;

CREATE TRIGGER IF NOT EXISTS tg_claim_tokens_no_delete BEFORE DELETE ON claim_tokens
BEGIN SELECT RAISE(ABORT, 'claim_tokens are append-only'); END;

CREATE TRIGGER IF NOT EXISTS tg_claim_sessions_immutable BEFORE UPDATE ON claim_sessions
WHEN NEW.id_hash <> OLD.id_hash OR NEW.tenant_id <> OLD.tenant_id OR NEW.token_id <> OLD.token_id
	OR NEW.intake_id <> OLD.intake_id OR NEW.identity_id <> OLD.identity_id OR NEW.key_jwk <> OLD.key_jwk
	OR NEW.key_jkt <> OLD.key_jkt OR NEW.nonce <> OLD.nonce OR NEW.created_at <> OLD.created_at
	OR (OLD.completed_at IS NOT NULL AND NEW.completed_at IS NOT OLD.completed_at)
BEGIN SELECT RAISE(ABORT, 'claim_sessions: key, binding and completion are immutable'); END;

CREATE TRIGGER IF NOT EXISTS tg_claim_sessions_no_delete BEFORE DELETE ON claim_sessions
BEGIN SELECT RAISE(ABORT, 'claim_sessions are append-only'); END;

CREATE TRIGGER IF NOT EXISTS tg_confirmation_codes_immutable BEFORE UPDATE ON confirmation_codes
WHEN NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.session_id_hash <> OLD.session_id_hash
	OR NEW.channel <> OLD.channel OR NEW.destination_hmac <> OLD.destination_hmac OR NEW.code_hash <> OLD.code_hash
	OR NEW.created_at <> OLD.created_at OR NEW.expires_at <> OLD.expires_at
	OR (OLD.used_at IS NOT NULL AND NEW.used_at IS NOT OLD.used_at)
BEGIN SELECT RAISE(ABORT, 'confirmation_codes: binding columns and use are immutable'); END;

CREATE TRIGGER IF NOT EXISTS tg_confirmation_codes_no_delete BEFORE DELETE ON confirmation_codes
BEGIN SELECT RAISE(ABORT, 'confirmation_codes are append-only'); END;

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_claim_tokens_xtenant_ins BEFORE INSERT ON claim_tokens
WHEN EXISTS (SELECT 1 FROM intake_records p WHERE p.id = NEW.intake_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: claim_tokens'); END;

CREATE TRIGGER IF NOT EXISTS tg_claim_tokens_xtenant_upd BEFORE UPDATE OF tenant_id, intake_id, identity_id ON claim_tokens
WHEN EXISTS (SELECT 1 FROM intake_records p WHERE p.id = NEW.intake_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: claim_tokens'); END;

CREATE TRIGGER IF NOT EXISTS tg_claim_sessions_xtenant_ins BEFORE INSERT ON claim_sessions
WHEN EXISTS (SELECT 1 FROM claim_tokens p WHERE p.id = NEW.token_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM intake_records p WHERE p.id = NEW.intake_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: claim_sessions'); END;

CREATE TRIGGER IF NOT EXISTS tg_claim_sessions_xtenant_upd BEFORE UPDATE OF tenant_id, token_id, intake_id, identity_id ON claim_sessions
WHEN EXISTS (SELECT 1 FROM claim_tokens p WHERE p.id = NEW.token_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM intake_records p WHERE p.id = NEW.intake_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: claim_sessions'); END;

CREATE TRIGGER IF NOT EXISTS tg_confirmation_codes_xtenant_ins BEFORE INSERT ON confirmation_codes
WHEN EXISTS (SELECT 1 FROM claim_sessions p WHERE p.id_hash = NEW.session_id_hash AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: confirmation_codes'); END;

CREATE TRIGGER IF NOT EXISTS tg_confirmation_codes_xtenant_upd BEFORE UPDATE OF tenant_id, session_id_hash ON confirmation_codes
WHEN EXISTS (SELECT 1 FROM claim_sessions p WHERE p.id_hash = NEW.session_id_hash AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: confirmation_codes'); END;
