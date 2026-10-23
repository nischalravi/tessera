-- GitHub and CI token inventory (issue #476). Stolen GitHub CLI OAuth tokens
-- published a malicious LiteLLM release, and GhostAction stole CI secrets, so
-- the non-human identity inventory also lists the credentials of a GitHub
-- organization: fine-grained and classic personal access tokens, OAuth app
-- tokens (the GitHub CLI among them) and Actions secrets.
--
-- github_tokens has one row per credential, keyed by token_key (unique per
-- tenant). Only metadata is stored: names, owner login, scopes or permissions,
-- dates. A token or secret VALUE is never read, so there is no column for one.
-- kind is classic_pat, fine_grained_pat, oauth_app_token or actions_secret.
-- owner_identity_id is set when the owner's GitHub login was correlated to an
-- account. created_at is when the credential was authorized or created;
-- rotated_at is when an Actions secret was last updated. A credential that
-- disappears from a full successful read is marked 'removed', never deleted.
--
-- Tenant-owned like 0001_tenancy.sql: the guard triggers at the end refuse a
-- reference to another tenant's identity.
CREATE TABLE IF NOT EXISTS github_tokens (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  token_key TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('classic_pat','fine_grained_pat','oauth_app_token','actions_secret')),
  name TEXT NOT NULL,
  owner_login TEXT NOT NULL DEFAULT '',
  owner_identity_id INTEGER REFERENCES identities (id),
  scopes TEXT NOT NULL DEFAULT '[]',
  visibility TEXT NOT NULL DEFAULT '',
  created_at TEXT,
  rotated_at TEXT,
  expires_at TEXT,
  last_used_at TEXT,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','removed'))
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_github_tokens_key ON github_tokens (tenant_id, token_key);
CREATE INDEX IF NOT EXISTS ix_github_tokens_status ON github_tokens (tenant_id, status);

CREATE TRIGGER IF NOT EXISTS tg_github_tokens_xtenant_ins BEFORE INSERT ON github_tokens
WHEN NEW.owner_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.owner_identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: github_tokens'); END;

CREATE TRIGGER IF NOT EXISTS tg_github_tokens_xtenant_upd BEFORE UPDATE OF tenant_id, owner_identity_id ON github_tokens
WHEN NEW.owner_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.owner_identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: github_tokens'); END;
