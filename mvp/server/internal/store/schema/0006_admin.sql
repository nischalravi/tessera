-- Phase 0 PR6: operator bootstrap (design §15.3).
--
-- A bootstrap invitation is the one-time code `tessera admin invite-admin`
-- prints: redeeming it at /t/{slug}/bootstrap?code= starts a phishing-
-- resistant sign-in through the named connection (purpose bootstrap), and the
-- user it signs in becomes tenant_admin with source bootstrap. The code is
-- stored only as SHA-256 hex; it is looked up inside its tenant (the slug is
-- in the URL), so it needs no global lookup.

CREATE TABLE IF NOT EXISTS bootstrap_invitations (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  code_hash TEXT NOT NULL CHECK (length(code_hash) = 64),
  idp_connection_id TEXT NOT NULL REFERENCES idp_connections (id),
  email TEXT NOT NULL CHECK (length(email) BETWEEN 3 AND 320),
  role TEXT NOT NULL DEFAULT 'tenant_admin' CHECK (role = 'tenant_admin'),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
  consumed_at TEXT, consumed_by_user_id TEXT REFERENCES platform_users (id),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, code_hash),
  CHECK (created_at < expires_at),
  CHECK ((consumed_at IS NULL) = (consumed_by_user_id IS NULL))
);
CREATE INDEX IF NOT EXISTS bootstrap_invitations_tenant ON bootstrap_invitations(tenant_id);

CREATE TRIGGER IF NOT EXISTS tg_bootstrap_invitations_xtenant_ins BEFORE INSERT ON bootstrap_invitations
WHEN EXISTS (SELECT 1 FROM idp_connections p WHERE p.id = NEW.idp_connection_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.consumed_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.consumed_by_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: bootstrap_invitations'); END;

CREATE TRIGGER IF NOT EXISTS tg_bootstrap_invitations_xtenant_upd BEFORE UPDATE OF tenant_id, idp_connection_id, consumed_by_user_id ON bootstrap_invitations
WHEN EXISTS (SELECT 1 FROM idp_connections p WHERE p.id = NEW.idp_connection_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.consumed_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.consumed_by_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: bootstrap_invitations'); END;

-- login_transactions.bootstrap_invitation_id (0005) names an invitation of the
-- same tenant.
CREATE TRIGGER IF NOT EXISTS tg_login_transactions_bootstrap_xtenant_ins BEFORE INSERT ON login_transactions
WHEN NEW.bootstrap_invitation_id IS NOT NULL
	AND NOT EXISTS (SELECT 1 FROM bootstrap_invitations p WHERE p.id = NEW.bootstrap_invitation_id AND p.tenant_id = NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: login_transactions'); END;

CREATE TRIGGER IF NOT EXISTS tg_login_transactions_bootstrap_xtenant_upd BEFORE UPDATE OF tenant_id, bootstrap_invitation_id ON login_transactions
WHEN NEW.bootstrap_invitation_id IS NOT NULL
	AND NOT EXISTS (SELECT 1 FROM bootstrap_invitations p WHERE p.id = NEW.bootstrap_invitation_id AND p.tenant_id = NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: login_transactions'); END;
