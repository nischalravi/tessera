-- Postgres dialect of schema/0261_evidence_packs.sql (kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres). src and dst are graph node keys, so there is
-- no foreign key; see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE evidence_packs (
  id TEXT NOT NULL,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  framework TEXT NOT NULL,
  period_from TEXT NOT NULL, period_to TEXT NOT NULL,
  generated_at TEXT NOT NULL, generated_by TEXT NOT NULL,
  manifest_sha256 TEXT NOT NULL,
  manifest TEXT NOT NULL,
  size_bytes BIGINT NOT NULL,
  content BYTEA NOT NULL,
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX ix_evidence_packs_tenant_generated ON evidence_packs (tenant_id, generated_at);

CREATE TRIGGER tg_evidence_packs_immutable BEFORE UPDATE ON evidence_packs
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('evidence_packs: a pack is immutable');
