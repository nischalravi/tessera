-- SoD rules as code (issue #652, AC-6; design docs/design/access-as-code-repo.md sections 3.4, 5 and 6.2): which
-- repository change last wrote each ruleset. One append-only row per ruleset written by an apply: the ruleset's
-- version after the write and the policy_ref {commit, path, bundle_sha256}. A ruleset with a row here is one the
-- repository manages: full mode may retire it when a later bundle no longer lists it; a ruleset made in the UI has no
-- row and is never retired by an apply. The ruleset, its risks and functions are written by internal/sod.
--
-- Tenant-owned: tenant_id on every row, guard triggers at the end refuse a ruleset of another tenant.
-- Postgres: migration 0961.
CREATE TABLE IF NOT EXISTS sod_policy_refs (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  ruleset_id TEXT NOT NULL REFERENCES sod_rulesets (id),
  ruleset_version INTEGER NOT NULL,
  policy_ref TEXT NOT NULL,
  actor TEXT NOT NULL,
  applied_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_sod_policy_refs_tenant_ruleset ON sod_policy_refs (tenant_id, ruleset_id);

CREATE TRIGGER IF NOT EXISTS tg_sod_policy_refs_no_update BEFORE UPDATE ON sod_policy_refs
BEGIN SELECT RAISE(ABORT, 'sod_policy_refs is append-only'); END;
CREATE TRIGGER IF NOT EXISTS tg_sod_policy_refs_no_delete BEFORE DELETE ON sod_policy_refs
BEGIN SELECT RAISE(ABORT, 'sod_policy_refs is append-only'); END;

CREATE TRIGGER IF NOT EXISTS tg_sod_policy_refs_xtenant_ins BEFORE INSERT ON sod_policy_refs
WHEN EXISTS (SELECT 1 FROM sod_rulesets p WHERE p.id = NEW.ruleset_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: sod_policy_refs'); END;

CREATE TRIGGER IF NOT EXISTS tg_sod_policy_refs_xtenant_upd BEFORE UPDATE OF tenant_id, ruleset_id ON sod_policy_refs
WHEN EXISTS (SELECT 1 FROM sod_rulesets p WHERE p.id = NEW.ruleset_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: sod_policy_refs'); END;
