-- Claim proof one-use memory (issue #69 / GU-6, review on #202). A claim
-- request's X-Claim-Proof may be used once. proof_id is SHA-256 of the
-- signature's r value (see guests/claim/proof.go): a signature and its
-- malleated form (r, N-s) share it. Rows expire after twice the proof window
-- and are pruned when a new proof is recorded. Recording in the tenant's
-- database makes one-use hold across restarts and server processes.
--
-- Tenant-owned like 0001_tenancy.sql; no references to other rows.
CREATE TABLE IF NOT EXISTS claim_proof_uses (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  proof_id TEXT NOT NULL CHECK (length(proof_id) = 64),
  expires_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, proof_id)
);
CREATE INDEX IF NOT EXISTS ix_claim_proof_uses_expiry ON claim_proof_uses (tenant_id, expires_at);
