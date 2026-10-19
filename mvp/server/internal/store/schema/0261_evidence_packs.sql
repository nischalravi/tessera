-- Framework evidence packs (issue #111): a generated ZIP (users, JML timings,
-- review campaigns, privileged access, revocations) with a SHA-256 manifest.
-- The ledger event that records a pack is appended in the same transaction as
-- this row. A pack is immutable: it is evidence of what Tessera knew when it
-- was generated, so no column is ever updated.
--
-- Tenant-owned: see 0001_tenancy.sql. It names no row of another table, so
-- there is nothing to guard across tenants.
CREATE TABLE IF NOT EXISTS evidence_packs (
  id TEXT NOT NULL,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  framework TEXT NOT NULL,
  period_from TEXT NOT NULL, period_to TEXT NOT NULL,
  generated_at TEXT NOT NULL, generated_by TEXT NOT NULL,
  manifest_sha256 TEXT NOT NULL,
  manifest TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  content BLOB NOT NULL,
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS ix_evidence_packs_tenant_generated ON evidence_packs (tenant_id, generated_at);

CREATE TRIGGER IF NOT EXISTS tg_evidence_packs_immutable BEFORE UPDATE ON evidence_packs
BEGIN SELECT RAISE(ABORT, 'evidence_packs: a pack is immutable'); END;
