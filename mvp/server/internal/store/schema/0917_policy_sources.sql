-- Per-tenant policy sources (access-as-code AC-3, issue #649; design
-- docs/design/access-as-code-repo.md sections 3.6 and 5).
--
-- policy_sources holds the Cedar of one source file per row: today kind
-- 'invariant' (invariants/<id>.cedar), keyed by the file's id. A tenant with
-- an active invariant source evaluates it in place of the embedded YAML policy
-- of the same @id (internal/policy.OverlayInvariants); a tenant with none, or
-- whose sources do not load, evaluates the embedded YAML. status 'disabled'
-- keeps the row and switches that policy off. sha256 is the digest of cedar,
-- set by the store, so a reader can tell a row that was altered outside it.
-- policy_ref is the JSON {commit, path, bundle_sha256} of the repository apply
-- that wrote the row, or ''.
--
-- policy_versions is the append-only history: one row per change of a source,
-- never updated or deleted. A source is retired (status), never deleted.
--
-- Tenant-owned like 0001_tenancy.sql: tenant_id on every row, every unique
-- index starts with it, every statement binds it.
CREATE TABLE IF NOT EXISTS policy_sources (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  kind TEXT NOT NULL CHECK (kind IN ('invariant')),
  src_key TEXT NOT NULL CHECK (length(src_key) BETWEEN 1 AND 64),
  cedar TEXT NOT NULL CHECK (length(cedar) BETWEEN 1 AND 262144),
  sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
  status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
  version INTEGER NOT NULL CHECK (version >= 1),
  policy_ref TEXT NOT NULL DEFAULT '',
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, kind, src_key)
);

CREATE TABLE IF NOT EXISTS policy_versions (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  kind TEXT NOT NULL,
  src_key TEXT NOT NULL,
  version INTEGER NOT NULL CHECK (version >= 1),
  cedar TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
  policy_ref TEXT NOT NULL DEFAULT '',
  actor TEXT NOT NULL,
  at TEXT NOT NULL,
  FOREIGN KEY (tenant_id, kind, src_key) REFERENCES policy_sources (tenant_id, kind, src_key)
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_policy_versions_source ON policy_versions (tenant_id, kind, src_key, version);

CREATE TRIGGER IF NOT EXISTS tg_policy_versions_no_update BEFORE UPDATE ON policy_versions
BEGIN SELECT RAISE(ABORT, 'policy_versions is append-only'); END;
CREATE TRIGGER IF NOT EXISTS tg_policy_versions_no_delete BEFORE DELETE ON policy_versions
BEGIN SELECT RAISE(ABORT, 'policy_versions is append-only'); END;

-- Cross-tenant reference guard (same pattern as 0001_tenancy.sql): a version names a source of its own tenant.
CREATE TRIGGER IF NOT EXISTS tg_policy_versions_xtenant_ins BEFORE INSERT ON policy_versions
WHEN NOT EXISTS (SELECT 1 FROM policy_sources p WHERE p.tenant_id = NEW.tenant_id AND p.kind = NEW.kind AND p.src_key = NEW.src_key)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: policy_versions'); END;

CREATE TRIGGER IF NOT EXISTS tg_policy_versions_xtenant_upd BEFORE UPDATE OF tenant_id, kind, src_key ON policy_versions
WHEN NOT EXISTS (SELECT 1 FROM policy_sources p WHERE p.tenant_id = NEW.tenant_id AND p.kind = NEW.kind AND p.src_key = NEW.src_key)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: policy_versions'); END;
