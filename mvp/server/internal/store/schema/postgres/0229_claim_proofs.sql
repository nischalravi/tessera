-- Postgres dialect of schema/0229_claim_proofs.sql (kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres).

-- +goose Up

CREATE TABLE claim_proof_uses (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  proof_id TEXT NOT NULL CHECK (length(proof_id) = 64),
  expires_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, proof_id)
);
CREATE INDEX ix_claim_proof_uses_expiry ON claim_proof_uses (tenant_id, expires_at);
