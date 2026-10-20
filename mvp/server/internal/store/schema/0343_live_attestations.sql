-- Attestation in place of a live check the system cannot answer (the check
-- reported "unsupported"; issue #217). One per item and revision. item_hash
-- binds it to the config fields the item depends on, so a config change makes
-- it stale; it also expires like live results (the gate reads attested_at).
CREATE TABLE IF NOT EXISTS readiness_live_attestations (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  revision_id TEXT NOT NULL REFERENCES connection_revisions (id),
  item_id TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  attester TEXT NOT NULL CHECK (length(attester) >= 2),
  reason TEXT NOT NULL CHECK (length(reason) >= 20),
  evidence TEXT NOT NULL CHECK (length(evidence) >= 1),
  item_hash TEXT NOT NULL,
  config_hash TEXT NOT NULL,
  attested_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, revision_id, item_id)
);

CREATE TRIGGER IF NOT EXISTS tg_readiness_live_attestations_xtenant_ins BEFORE INSERT ON readiness_live_attestations
WHEN (NEW.revision_id IS NOT NULL AND EXISTS (SELECT 1 FROM connection_revisions p WHERE p.id = NEW.revision_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: readiness_live_attestations'); END;

CREATE TRIGGER IF NOT EXISTS tg_readiness_live_attestations_xtenant_upd BEFORE UPDATE OF tenant_id, revision_id ON readiness_live_attestations
WHEN (NEW.revision_id IS NOT NULL AND EXISTS (SELECT 1 FROM connection_revisions p WHERE p.id = NEW.revision_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: readiness_live_attestations'); END;
