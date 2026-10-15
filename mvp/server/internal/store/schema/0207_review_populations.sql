-- Frozen review populations (issue #110). When a campaign is launched, the
-- full population of grants in scope is snapshotted here, in the launch
-- transaction, with a SHA-256 over a documented canonical serialization (see
-- internal/reviews/population.go and mvp/README.md). Auditors test the
-- completeness and accuracy of a review population (IPE) from these rows.
--
--   review_populations      one immutable header per campaign
--   review_population_rows  one immutable row per in-scope grant
--   review_auto_decisions   one row per auto-certified grant with the rule that
--                           decided it; only the qa_* columns of a sampled row
--                           change, once, when a human QA reviewer decides
--   tenant_settings         per-tenant key/value settings (qa_sample_pct)
--
-- Tenant-owned like 0001_tenancy.sql: the guard triggers refuse a reference to
-- another tenant's row. edge_id names a grant edge without a foreign key (an
-- edge is deleted when a review revokes it; the population keeps its id).

CREATE TABLE IF NOT EXISTS review_populations (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  campaign_id INTEGER NOT NULL REFERENCES review_campaigns (id),
  created_at TEXT NOT NULL,
  population_hash TEXT NOT NULL,
  item_count INTEGER NOT NULL,
  system_counts TEXT NOT NULL,
  source_syncs TEXT NOT NULL,
  scope TEXT NOT NULL,
  rules_version TEXT NOT NULL,
  qa_sample_pct INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, campaign_id)
);

CREATE TABLE IF NOT EXISTS review_population_rows (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  campaign_id INTEGER NOT NULL REFERENCES review_campaigns (id),
  ordinal INTEGER NOT NULL CHECK (ordinal >= 1),
  edge_id INTEGER NOT NULL,
  identity_id INTEGER NOT NULL REFERENCES identities (id),
  identity_ref TEXT NOT NULL,
  account_ref TEXT NOT NULL,
  system TEXT NOT NULL,
  entitlement TEXT NOT NULL,
  edge_src TEXT NOT NULL,
  edge_dst TEXT NOT NULL,
  in_scope_reason TEXT NOT NULL,
  disposition TEXT NOT NULL CHECK (disposition IN ('review','auto_certified')),
  PRIMARY KEY (tenant_id, campaign_id, ordinal)
);
CREATE INDEX IF NOT EXISTS ix_review_population_rows_edge ON review_population_rows (tenant_id, campaign_id, edge_id);

CREATE TABLE IF NOT EXISTS review_auto_decisions (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  campaign_id INTEGER NOT NULL REFERENCES review_campaigns (id),
  ordinal INTEGER NOT NULL,
  edge_id INTEGER NOT NULL,
  identity_id INTEGER NOT NULL REFERENCES identities (id),
  decided_by_rule TEXT NOT NULL,
  qa_sample INTEGER NOT NULL DEFAULT 0 CHECK (qa_sample IN (0,1)),
  qa_reviewer_id INTEGER REFERENCES identities (id),
  qa_decision TEXT CHECK (qa_decision IN ('keep','revoke')),
  qa_comment TEXT,
  qa_decided_at TEXT,
  qa_decided_by_user_id TEXT,
  overturned INTEGER NOT NULL DEFAULT 0 CHECK (overturned IN (0,1)),
  UNIQUE (tenant_id, campaign_id, ordinal)
);
CREATE INDEX IF NOT EXISTS ix_review_auto_decisions_campaign ON review_auto_decisions (tenant_id, campaign_id);

CREATE TABLE IF NOT EXISTS tenant_settings (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  key TEXT NOT NULL CHECK (length(key) BETWEEN 1 AND 64),
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, key)
);

-- Immutability: a frozen population never changes (the audit ledger's
-- append-only pattern, schema/0004_audit.sql).
CREATE TRIGGER IF NOT EXISTS review_populations_no_update BEFORE UPDATE ON review_populations
BEGIN SELECT RAISE(ABORT, 'review_populations is immutable'); END;
CREATE TRIGGER IF NOT EXISTS review_populations_no_delete BEFORE DELETE ON review_populations
BEGIN SELECT RAISE(ABORT, 'review_populations is immutable'); END;
CREATE TRIGGER IF NOT EXISTS review_population_rows_no_update BEFORE UPDATE ON review_population_rows
BEGIN SELECT RAISE(ABORT, 'review_population_rows is immutable'); END;
CREATE TRIGGER IF NOT EXISTS review_population_rows_no_delete BEFORE DELETE ON review_population_rows
BEGIN SELECT RAISE(ABORT, 'review_population_rows is immutable'); END;

-- An auto-decision keeps its rule and sample flag forever; a QA decision is
-- recorded once.
CREATE TRIGGER IF NOT EXISTS review_auto_decisions_core_immutable BEFORE UPDATE OF tenant_id, campaign_id, ordinal, edge_id, identity_id, decided_by_rule, qa_sample, qa_reviewer_id ON review_auto_decisions
BEGIN SELECT RAISE(ABORT, 'review_auto_decisions core fields are immutable'); END;
CREATE TRIGGER IF NOT EXISTS review_auto_decisions_qa_once BEFORE UPDATE OF qa_decision ON review_auto_decisions
WHEN OLD.qa_decision IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'review_auto_decisions QA decision already recorded'); END;
CREATE TRIGGER IF NOT EXISTS review_auto_decisions_no_delete BEFORE DELETE ON review_auto_decisions
BEGIN SELECT RAISE(ABORT, 'review_auto_decisions is append-only'); END;

-- Cross-tenant reference guards (see schema/0001_tenancy.sql).
CREATE TRIGGER IF NOT EXISTS tg_review_populations_xtenant_ins BEFORE INSERT ON review_populations
WHEN EXISTS (SELECT 1 FROM review_campaigns p WHERE p.id = NEW.campaign_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: review_populations'); END;

CREATE TRIGGER IF NOT EXISTS tg_review_populations_xtenant_upd BEFORE UPDATE OF tenant_id, campaign_id ON review_populations
WHEN EXISTS (SELECT 1 FROM review_campaigns p WHERE p.id = NEW.campaign_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: review_populations'); END;

CREATE TRIGGER IF NOT EXISTS tg_review_population_rows_xtenant_ins BEFORE INSERT ON review_population_rows
WHEN EXISTS (SELECT 1 FROM review_campaigns p WHERE p.id = NEW.campaign_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM grant_edges p WHERE p.id = NEW.edge_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: review_population_rows'); END;

CREATE TRIGGER IF NOT EXISTS tg_review_population_rows_xtenant_upd BEFORE UPDATE OF tenant_id, campaign_id, identity_id, edge_id ON review_population_rows
WHEN EXISTS (SELECT 1 FROM review_campaigns p WHERE p.id = NEW.campaign_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM grant_edges p WHERE p.id = NEW.edge_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: review_population_rows'); END;

CREATE TRIGGER IF NOT EXISTS tg_review_auto_decisions_xtenant_ins BEFORE INSERT ON review_auto_decisions
WHEN EXISTS (SELECT 1 FROM review_campaigns p WHERE p.id = NEW.campaign_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.qa_reviewer_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.qa_reviewer_id AND p.tenant_id <> NEW.tenant_id))
	OR EXISTS (SELECT 1 FROM grant_edges p WHERE p.id = NEW.edge_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.qa_decided_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.qa_decided_by_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: review_auto_decisions'); END;

CREATE TRIGGER IF NOT EXISTS tg_review_auto_decisions_xtenant_upd BEFORE UPDATE OF tenant_id, campaign_id, identity_id, qa_reviewer_id, edge_id, qa_decided_by_user_id ON review_auto_decisions
WHEN EXISTS (SELECT 1 FROM review_campaigns p WHERE p.id = NEW.campaign_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.qa_reviewer_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.qa_reviewer_id AND p.tenant_id <> NEW.tenant_id))
	OR EXISTS (SELECT 1 FROM grant_edges p WHERE p.id = NEW.edge_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.qa_decided_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.qa_decided_by_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: review_auto_decisions'); END;
