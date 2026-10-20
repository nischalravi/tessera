-- Phase 0 PR13: break-glass (design §9.6, §15.4, §19 PR13).
--
-- A break-glass credential is a hardware WebAuthn key that signs a user in
-- when the tenant's IdP is down, misconfigured or compromised. Every table is
-- tenant-owned: tenant_id references tenants(id), every UNIQUE constraint
-- starts with tenant_id, and the guard triggers at the end refuse a reference
-- to another tenant's row. UUID text primary keys; RFC 3339 UTC timestamps
-- with microseconds (store.RT).
--
-- The change-request type CHECK that admits breakglass.register and
-- breakglass.revoke is in 0008_admin_changes.sql, where the table is created.

-- break_glass_credentials: one registered key (§15.4). backup_eligible is
-- always 0 (a synced passkey is refused at registration), and the attestation
-- is never "none". change_request_id is the applied breakglass.register
-- request that allowed the enrolment: one key per request. sign_count only
-- ever rises (a statement guard); a regression is a cloned authenticator.
CREATE TABLE IF NOT EXISTS break_glass_credentials (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  user_id TEXT NOT NULL REFERENCES platform_users (id),
  change_request_id TEXT NOT NULL REFERENCES admin_change_requests (id),
  credential_id BLOB NOT NULL CHECK (length(credential_id) BETWEEN 1 AND 1023),
  public_key BLOB NOT NULL CHECK (length(public_key) > 0),
  sign_count INTEGER NOT NULL DEFAULT 0 CHECK (sign_count BETWEEN 0 AND 4294967295),
  aaguid TEXT NOT NULL CHECK (length(aaguid) = 36),
  attestation_format TEXT NOT NULL CHECK (attestation_format <> 'none'),
  attestation_trust TEXT NOT NULL CHECK (attestation_trust IN ('basic','attca','mds_verified')),
  backup_eligible INTEGER NOT NULL CHECK (backup_eligible = 0),
  transports TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(transports) AND json_type(transports) = 'array'),
  label TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 100),
  custodian TEXT NOT NULL CHECK (length(custodian) BETWEEN 1 AND 200),
  created_at TEXT NOT NULL, last_used_at TEXT, revoked_at TEXT,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, credential_id),
  UNIQUE (tenant_id, change_request_id)
);
CREATE INDEX IF NOT EXISTS break_glass_credentials_tenant ON break_glass_credentials(tenant_id, user_id);

-- break_glass_challenges: the server side of one WebAuthn ceremony. The
-- challenge is stored only as its SHA-256 (the client echoes it in
-- clientDataJSON, which is how the verify call finds its row); session_data
-- is the go-webauthn SessionData JSON, which holds nothing secret (the
-- challenge itself goes to the client). Single use: consumed_at is set
-- before the response is verified, so a replay finds nothing. A registration
-- challenge names the enrolment request, the key's user and the requester;
-- an assertion challenge is anonymous (the caller is not signed in yet).
CREATE TABLE IF NOT EXISTS break_glass_challenges (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  purpose TEXT NOT NULL CHECK (purpose IN ('registration','assertion')),
  challenge_hash TEXT NOT NULL CHECK (length(challenge_hash) = 64),
  session_data TEXT NOT NULL CHECK (json_valid(session_data)),
  change_request_id TEXT REFERENCES admin_change_requests (id),
  user_id TEXT REFERENCES platform_users (id),
  created_by_user_id TEXT REFERENCES platform_users (id),
  created_at TEXT NOT NULL, expires_at TEXT NOT NULL, consumed_at TEXT,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, challenge_hash),
  CHECK (created_at < expires_at),
  CHECK ((purpose = 'registration') = (change_request_id IS NOT NULL AND user_id IS NOT NULL AND created_by_user_id IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS break_glass_challenges_tenant ON break_glass_challenges(tenant_id, purpose, expires_at);

-- break_glass_uses: one row per break-glass sign-in. It is what the dashboard
-- lists for 30 days and what the attestation form answers ("why was
-- break-glass used", §15.4): the next normal admin sign-in shows every use
-- with no answer. The answer is all-or-nothing (reason, who, when).
CREATE TABLE IF NOT EXISTS break_glass_uses (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  credential_row_id TEXT NOT NULL REFERENCES break_glass_credentials (id),
  user_id TEXT NOT NULL REFERENCES platform_users (id),
  session_id TEXT NOT NULL REFERENCES sessions (id),
  used_at TEXT NOT NULL, ip TEXT, user_agent TEXT,
  answered_at TEXT, answered_by_user_id TEXT REFERENCES platform_users (id),
  reason TEXT CHECK (reason IS NULL OR length(reason) BETWEEN 1 AND 2000),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, session_id),
  CHECK ((answered_at IS NULL) = (answered_by_user_id IS NULL) AND (answered_at IS NULL) = (reason IS NULL))
);
CREATE INDEX IF NOT EXISTS break_glass_uses_tenant ON break_glass_uses(tenant_id, used_at);

-- ---------------------------------------------------------------- guard triggers

CREATE TRIGGER IF NOT EXISTS tg_break_glass_credentials_xtenant_ins BEFORE INSERT ON break_glass_credentials
WHEN EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.user_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM admin_change_requests p WHERE p.id = NEW.change_request_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: break_glass_credentials'); END;

CREATE TRIGGER IF NOT EXISTS tg_break_glass_credentials_xtenant_upd BEFORE UPDATE OF tenant_id, user_id, change_request_id ON break_glass_credentials
WHEN EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.user_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM admin_change_requests p WHERE p.id = NEW.change_request_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: break_glass_credentials'); END;

CREATE TRIGGER IF NOT EXISTS tg_break_glass_challenges_xtenant_ins BEFORE INSERT ON break_glass_challenges
WHEN (NEW.change_request_id IS NOT NULL AND EXISTS (SELECT 1 FROM admin_change_requests p WHERE p.id = NEW.change_request_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.user_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.created_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.created_by_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: break_glass_challenges'); END;

CREATE TRIGGER IF NOT EXISTS tg_break_glass_challenges_xtenant_upd BEFORE UPDATE OF tenant_id, change_request_id, user_id, created_by_user_id ON break_glass_challenges
WHEN (NEW.change_request_id IS NOT NULL AND EXISTS (SELECT 1 FROM admin_change_requests p WHERE p.id = NEW.change_request_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.user_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.created_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.created_by_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: break_glass_challenges'); END;

CREATE TRIGGER IF NOT EXISTS tg_break_glass_uses_xtenant_ins BEFORE INSERT ON break_glass_uses
WHEN EXISTS (SELECT 1 FROM break_glass_credentials p WHERE p.id = NEW.credential_row_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.user_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM sessions p WHERE p.id = NEW.session_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.answered_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.answered_by_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: break_glass_uses'); END;

CREATE TRIGGER IF NOT EXISTS tg_break_glass_uses_xtenant_upd BEFORE UPDATE OF tenant_id, credential_row_id, user_id, session_id, answered_by_user_id ON break_glass_uses
WHEN EXISTS (SELECT 1 FROM break_glass_credentials p WHERE p.id = NEW.credential_row_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.user_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM sessions p WHERE p.id = NEW.session_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.answered_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.answered_by_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: break_glass_uses'); END;
