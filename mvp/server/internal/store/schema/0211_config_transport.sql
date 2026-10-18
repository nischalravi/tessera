-- Configuration transport between tenants and environments (issue #170).
--
-- A tenant exports its configuration (connections without secrets,
-- readiness overlays, sign-in connections without secrets) as a bundle
-- signed with its config signing key: Ed25519, the private key sealed under
-- the KEK (AAD config_signing_keys.private_sealed.<kid>). Another tenant, on
-- the same or another Tessera, imports a bundle only when its signer is in
-- config_trusted_signers. Each applied import is recorded with the hash of
-- the bundle it applied.
CREATE TABLE IF NOT EXISTS config_signing_keys (
  kid TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  public_key BLOB NOT NULL CHECK (length(public_key) = 32),
  private_sealed BLOB NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','retired')),
  created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_config_signing_keys_active ON config_signing_keys (tenant_id) WHERE status = 'active';

CREATE TABLE IF NOT EXISTS config_trusted_signers (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  kid TEXT NOT NULL,
  public_key BLOB NOT NULL CHECK (length(public_key) = 32),
  label TEXT NOT NULL,
  added_by TEXT REFERENCES platform_users (id),
  added_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, kid)
);

CREATE TABLE IF NOT EXISTS config_imports (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  bundle_hash TEXT NOT NULL,
  signer_kid TEXT NOT NULL,
  source TEXT NOT NULL,
  exported_at TEXT NOT NULL,
  summary TEXT NOT NULL DEFAULT '{}',
  applied_by TEXT REFERENCES platform_users (id),
  applied_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_config_imports_tenant ON config_imports (tenant_id, applied_at);

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_config_trusted_signers_xtenant_ins BEFORE INSERT ON config_trusted_signers
WHEN NEW.added_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.added_by AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: config_trusted_signers'); END;

CREATE TRIGGER IF NOT EXISTS tg_config_trusted_signers_xtenant_upd BEFORE UPDATE OF tenant_id, added_by ON config_trusted_signers
WHEN NEW.added_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.added_by AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: config_trusted_signers'); END;

CREATE TRIGGER IF NOT EXISTS tg_config_imports_xtenant_ins BEFORE INSERT ON config_imports
WHEN NEW.applied_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.applied_by AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: config_imports'); END;

CREATE TRIGGER IF NOT EXISTS tg_config_imports_xtenant_upd BEFORE UPDATE OF tenant_id, applied_by ON config_imports
WHEN NEW.applied_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.applied_by AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: config_imports'); END;
