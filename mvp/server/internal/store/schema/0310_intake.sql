-- SIS and HRIS intake for applicants, admits and pre-hires (guest accounts
-- design §4.1, §8.4 and §9.1, issue #67 / GU-4). A feed record becomes an
-- intake record; the intake decides which person it belongs to (by an
-- authoritative identifier only) and opens or ends affiliations. A change of
-- relationship (applicant to admit to student, pre-hire to employee) is a
-- conversion: the old affiliation ends and the new one starts on the same
-- identity, and the pair is recorded here.
--
-- Tenant-owned like 0001_tenancy.sql: guard triggers at the end refuse a
-- reference to another tenant's row. Created with IF NOT EXISTS; a reseed
-- drops and recreates (store.tables).

-- An organizational sponsor stands behind a population when no individual
-- does: admissions for applicants and admits, HR for pre-hires (design §3).
-- GU-2's sponsorships name one in sponsor_org.
CREATE TABLE IF NOT EXISTS org_sponsors (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  key TEXT NOT NULL CHECK (key <> ''),
  name TEXT NOT NULL,
  population TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, key)
);

-- One feed event received. event_key makes a replay a no-op: it names the
-- source system, the event and its phase (an HRIS hire is first announced,
-- later effective). status 'review' holds a record whose person could not be
-- decided without matching (GU-5); no identity or affiliation exists for it.
-- detail is a JSON object without personal data (counts, outcomes, ids).
CREATE TABLE IF NOT EXISTS intake_records (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  channel TEXT NOT NULL CHECK (channel IN ('sponsor_invite','bulk_invite','self_registration','sis','hris','vms',
    'partner_invite','partner_scim')),
  match_mode TEXT NOT NULL CHECK (match_mode IN ('authoritative','self_asserted','federated')),
  source_record_id TEXT REFERENCES identity_source_records (id),
  identity_id INTEGER REFERENCES identities (id),
  sponsor_org TEXT,
  submitted_by TEXT,
  event_key TEXT NOT NULL CHECK (event_key <> ''),
  event_type TEXT NOT NULL,
  effective_at TEXT,
  status TEXT NOT NULL CHECK (status IN ('received','matching','review','resolved','rejected')),
  detail TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  UNIQUE (tenant_id, event_key)
);
CREATE INDEX IF NOT EXISTS ix_intake_records_identity ON intake_records (tenant_id, identity_id);
CREATE INDEX IF NOT EXISTS ix_intake_records_status ON intake_records (tenant_id, status);

-- A conversion: from_affiliation_id ended and to_affiliation_id began for the
-- same person, caused by intake_id. Append-only history.
CREATE TABLE IF NOT EXISTS identity_conversions (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id INTEGER NOT NULL REFERENCES identities (id),
  from_affiliation_id TEXT NOT NULL REFERENCES affiliations (id),
  to_affiliation_id TEXT NOT NULL REFERENCES affiliations (id),
  from_type TEXT NOT NULL,
  to_type TEXT NOT NULL,
  trigger TEXT NOT NULL CHECK (trigger IN ('sis_status','hris_hire')),
  intake_id TEXT REFERENCES intake_records (id),
  effective_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_identity_conversions_identity ON identity_conversions (tenant_id, identity_id);

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_intake_records_xtenant_ins BEFORE INSERT ON intake_records
WHEN (NEW.identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.source_record_id IS NOT NULL AND EXISTS (SELECT 1 FROM identity_source_records p WHERE p.id = NEW.source_record_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: intake_records'); END;

CREATE TRIGGER IF NOT EXISTS tg_intake_records_xtenant_upd BEFORE UPDATE OF tenant_id, identity_id, source_record_id ON intake_records
WHEN (NEW.identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.source_record_id IS NOT NULL AND EXISTS (SELECT 1 FROM identity_source_records p WHERE p.id = NEW.source_record_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: intake_records'); END;

-- sponsor_org names an org_sponsors row of the same tenant (the store runs
-- without PRAGMA foreign_keys, so a composite foreign key would not hold).
CREATE TRIGGER IF NOT EXISTS tg_intake_records_sponsor_ins BEFORE INSERT ON intake_records
WHEN NEW.sponsor_org IS NOT NULL AND NOT EXISTS (SELECT 1 FROM org_sponsors p WHERE p.tenant_id = NEW.tenant_id AND p.key = NEW.sponsor_org)
BEGIN SELECT RAISE(ABORT, 'unknown organizational sponsor: intake_records'); END;

CREATE TRIGGER IF NOT EXISTS tg_intake_records_sponsor_upd BEFORE UPDATE OF tenant_id, sponsor_org ON intake_records
WHEN NEW.sponsor_org IS NOT NULL AND NOT EXISTS (SELECT 1 FROM org_sponsors p WHERE p.tenant_id = NEW.tenant_id AND p.key = NEW.sponsor_org)
BEGIN SELECT RAISE(ABORT, 'unknown organizational sponsor: intake_records'); END;

-- An intake record is an event received: only its outcome (status, person,
-- detail) may change, and never the event it names.
CREATE TRIGGER IF NOT EXISTS tg_intake_records_immutable BEFORE UPDATE ON intake_records
WHEN NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.channel <> OLD.channel OR NEW.event_key <> OLD.event_key
	OR NEW.created_at <> OLD.created_at
BEGIN SELECT RAISE(ABORT, 'intake_records: the event columns are immutable'); END;

CREATE TRIGGER IF NOT EXISTS tg_intake_records_no_delete BEFORE DELETE ON intake_records
BEGIN SELECT RAISE(ABORT, 'intake records are append-only'); END;

CREATE TRIGGER IF NOT EXISTS tg_identity_conversions_xtenant_ins BEFORE INSERT ON identity_conversions
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM affiliations p WHERE p.id IN (NEW.from_affiliation_id, NEW.to_affiliation_id) AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.intake_id IS NOT NULL AND EXISTS (SELECT 1 FROM intake_records p WHERE p.id = NEW.intake_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: identity_conversions'); END;

CREATE TRIGGER IF NOT EXISTS tg_identity_conversions_xtenant_upd BEFORE UPDATE OF tenant_id, identity_id, from_affiliation_id, to_affiliation_id, intake_id ON identity_conversions
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM affiliations p WHERE p.id IN (NEW.from_affiliation_id, NEW.to_affiliation_id) AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.intake_id IS NOT NULL AND EXISTS (SELECT 1 FROM intake_records p WHERE p.id = NEW.intake_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: identity_conversions'); END;

CREATE TRIGGER IF NOT EXISTS tg_identity_conversions_immutable BEFORE UPDATE ON identity_conversions
BEGIN SELECT RAISE(ABORT, 'identity conversions are append-only'); END;

CREATE TRIGGER IF NOT EXISTS tg_identity_conversions_no_delete BEFORE DELETE ON identity_conversions
BEGIN SELECT RAISE(ABORT, 'identity conversions are append-only'); END;
