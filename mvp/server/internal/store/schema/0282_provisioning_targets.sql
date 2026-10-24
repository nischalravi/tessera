-- Closed-loop provisioning (issue #103): the target system behind a
-- connection. One target per connection. credential_enc is the bearer or API
-- token sealed under the KEK (internal/seal, AAD-bound to tenant, table,
-- column and row id); it is write-only and never returned by the API.
-- write_back is the per-connection switch: 0 (the default) keeps the
-- immediate graph change of JML, reviews, JIT and least-privilege revokes;
-- 1 sends the change to the target through the provisioning engine and edits
-- the graph only after a re-read of the target confirms it.
CREATE TABLE IF NOT EXISTS provisioning_targets (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  connection_id TEXT NOT NULL REFERENCES connections (id),
  kind TEXT NOT NULL CHECK (kind IN ('scim','okta','fake','cyberark','delinea','beyondtrust','sap','oracle','rest','sql','salesforce','servicenow','atlassian','ldap','ad')),
  base_url TEXT NOT NULL,
  settings TEXT NOT NULL DEFAULT '{}',
  credential_enc BLOB,
  credential_version TEXT,
  write_back INTEGER NOT NULL DEFAULT 0 CHECK (write_back IN (0,1)),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, connection_id)
);
CREATE INDEX IF NOT EXISTS provisioning_targets_tenant ON provisioning_targets(tenant_id);

CREATE TRIGGER IF NOT EXISTS tg_provisioning_targets_xtenant_ins BEFORE INSERT ON provisioning_targets
WHEN EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: provisioning_targets'); END;

CREATE TRIGGER IF NOT EXISTS tg_provisioning_targets_xtenant_upd BEFORE UPDATE OF tenant_id, connection_id ON provisioning_targets
WHEN EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: provisioning_targets'); END;
