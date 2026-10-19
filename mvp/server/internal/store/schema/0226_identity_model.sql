-- Identity data model for guests and other non-employee people (guest
-- accounts design §3 and §9.1, issue #64 / GU-1): affiliations, source
-- records and identifiers hang off one person (identities.id), so a person
-- with several relationships to the organization is still one identity.
--
-- This file only adds tables. It does not add columns to identities: the
-- worker type, sponsor, end dates and lifecycle state of a person belong to
-- identity_lifecycle (issue #159). An affiliation is one relationship (kind,
-- population, dates, source); a person has many. The person's lifecycle state
-- is derived from them in code (internal/identity/affiliations).
--
-- Tenant-owned like 0001_tenancy.sql: guard triggers at the end refuse a
-- reference to another tenant's row. Created with IF NOT EXISTS; a reseed
-- drops and recreates (store.tables).

-- Per-population settings (typed, edited by an admin in a later PR). GU-1
-- seeds the four populations of §3 and uses max_duration_days to bound
-- manually added affiliations.
CREATE TABLE IF NOT EXISTS guest_populations (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  key TEXT NOT NULL,
  name TEXT NOT NULL,
  max_duration_days INTEGER NOT NULL CHECK (max_duration_days > 0),
  default_ial INTEGER NOT NULL DEFAULT 0 CHECK (default_ial IN (0,1,2)),
  default_aal INTEGER NOT NULL DEFAULT 1 CHECK (default_aal IN (1,2,3)),
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, key)
);

-- What one system of record said about a person. identity_id is NULL while
-- the record is pending review (matching arrives in GU-5). attributes is a
-- JSON object of non-sensitive attributes; date of birth, phone and similar
-- are sealed by the PR that first stores them, never written here in clear.
CREATE TABLE IF NOT EXISTS identity_source_records (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id INTEGER REFERENCES identities (id),
  sor TEXT NOT NULL CHECK (sor <> ''),
  sorid TEXT NOT NULL CHECK (sorid <> ''),
  attributes TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','retired')),
  received_at TEXT NOT NULL,
  UNIQUE (tenant_id, sor, sorid)
);
CREATE INDEX IF NOT EXISTS ix_identity_source_records_identity ON identity_source_records (tenant_id, identity_id);

-- Identifiers a person is known by. value_hmac is HMAC-SHA256 under a
-- per-tenant key derived from the KEK (internal/identity/identifiers) over
-- type, issuer and the normalized value, so a matching service can compare
-- without the value; value_norm is NULL for hashed-only types (national_id_hmac).
CREATE TABLE IF NOT EXISTS identity_identifiers (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id INTEGER NOT NULL REFERENCES identities (id),
  type TEXT NOT NULL CHECK (type IN ('email','phone','employee_id','student_id','applicant_id','netid','eppn',
    'saml_subject_id','saml_pairwise_id','oidc_sub','national_id_hmac')),
  issuer TEXT NOT NULL DEFAULT '',
  value_norm TEXT,
  value_hmac TEXT NOT NULL CHECK (value_hmac <> ''),
  verified_at TEXT,
  verified_by TEXT CHECK (verified_by IS NULL OR verified_by IN ('confirmation_code','federation','authoritative_source','proofing_agent')),
  source_record_id TEXT REFERENCES identity_source_records (id),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','retired')),
  created_at TEXT NOT NULL,
  CHECK ((verified_at IS NULL) = (verified_by IS NULL)),
  UNIQUE (tenant_id, type, issuer, value_hmac)
);
CREATE INDEX IF NOT EXISTS ix_identity_identifiers_identity ON identity_identifiers (tenant_id, identity_id);

-- One relationship between a person and the organization. type is the kind
-- (employee, guest_visitor, ...); population names the guest_populations row
-- of the same tenant that bounds it (NULL for HRIS/SIS affiliations); partner_org_id waits for
-- the partner organizations table (GU-14). status 'pending' is not yet
-- started, 'ended' ran out or was ended by an admin, 'revoked' was cut short.
CREATE TABLE IF NOT EXISTS affiliations (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id INTEGER NOT NULL REFERENCES identities (id),
  type TEXT NOT NULL CHECK (type IN ('employee','student','applicant','admit','prehire','contractor',
    'guest_visitor','volunteer','partner','alum','retiree')),
  source TEXT NOT NULL CHECK (source IN ('hris','sis','sponsorship','partner_org','manual')),
  source_ref TEXT,
  org_unit TEXT,
  partner_org_id TEXT,
  population TEXT,
  starts_at TEXT NOT NULL,
  ends_at TEXT,
  status TEXT NOT NULL CHECK (status IN ('pending','active','ended','revoked')),
  created_by TEXT REFERENCES platform_users (id),
  created_at TEXT NOT NULL,
  ended_by TEXT REFERENCES platform_users (id),
  end_reason TEXT
);
CREATE INDEX IF NOT EXISTS ix_affiliations_identity ON affiliations (tenant_id, identity_id, status);
CREATE INDEX IF NOT EXISTS ix_affiliations_ending ON affiliations (tenant_id, ends_at) WHERE status = 'active';

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_identity_source_records_xtenant_ins BEFORE INSERT ON identity_source_records
WHEN NEW.identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: identity_source_records'); END;

CREATE TRIGGER IF NOT EXISTS tg_identity_source_records_xtenant_upd BEFORE UPDATE OF tenant_id, identity_id ON identity_source_records
WHEN NEW.identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: identity_source_records'); END;

CREATE TRIGGER IF NOT EXISTS tg_identity_identifiers_xtenant_ins BEFORE INSERT ON identity_identifiers
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.source_record_id IS NOT NULL AND EXISTS (SELECT 1 FROM identity_source_records p WHERE p.id = NEW.source_record_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: identity_identifiers'); END;

CREATE TRIGGER IF NOT EXISTS tg_identity_identifiers_xtenant_upd BEFORE UPDATE OF tenant_id, identity_id, source_record_id ON identity_identifiers
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.source_record_id IS NOT NULL AND EXISTS (SELECT 1 FROM identity_source_records p WHERE p.id = NEW.source_record_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: identity_identifiers'); END;

CREATE TRIGGER IF NOT EXISTS tg_affiliations_xtenant_ins BEFORE INSERT ON affiliations
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.created_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.created_by AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.ended_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.ended_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: affiliations'); END;

CREATE TRIGGER IF NOT EXISTS tg_affiliations_xtenant_upd BEFORE UPDATE OF tenant_id, identity_id, created_by, ended_by ON affiliations
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.created_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.created_by AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.ended_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.ended_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: affiliations'); END;

-- population names a guest_populations row of the same tenant (a composite
-- foreign key would not be enforced: the store runs without PRAGMA foreign_keys).
CREATE TRIGGER IF NOT EXISTS tg_affiliations_population_ins BEFORE INSERT ON affiliations
WHEN NEW.population IS NOT NULL AND NOT EXISTS (SELECT 1 FROM guest_populations p WHERE p.tenant_id = NEW.tenant_id AND p.key = NEW.population)
BEGIN SELECT RAISE(ABORT, 'unknown population: affiliations'); END;

CREATE TRIGGER IF NOT EXISTS tg_affiliations_population_upd BEFORE UPDATE OF tenant_id, population ON affiliations
WHEN NEW.population IS NOT NULL AND NOT EXISTS (SELECT 1 FROM guest_populations p WHERE p.tenant_id = NEW.tenant_id AND p.key = NEW.population)
BEGIN SELECT RAISE(ABORT, 'unknown population: affiliations'); END;

-- An affiliation is history once ended: only the end columns change, once.
CREATE TRIGGER IF NOT EXISTS tg_affiliations_immutable BEFORE UPDATE ON affiliations
WHEN OLD.status IN ('ended','revoked') OR NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id
	OR NEW.identity_id <> OLD.identity_id OR NEW.type <> OLD.type OR NEW.source <> OLD.source
	OR NEW.starts_at <> OLD.starts_at OR NEW.created_at <> OLD.created_at
BEGIN SELECT RAISE(ABORT, 'affiliations: ended rows and identity columns are immutable'); END;

CREATE TRIGGER IF NOT EXISTS tg_affiliations_no_delete BEFORE DELETE ON affiliations
BEGIN SELECT RAISE(ABORT, 'affiliations are append-only'); END;
