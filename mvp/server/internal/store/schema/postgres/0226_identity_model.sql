-- Postgres dialect of schema/0226_identity_model.sql (Phase 0 PR14 dialect, kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE guest_populations (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  key TEXT NOT NULL,
  name TEXT NOT NULL,
  max_duration_days BIGINT NOT NULL CHECK (max_duration_days > 0),
  default_ial BIGINT NOT NULL DEFAULT 0 CHECK (default_ial IN (0,1,2)),
  default_aal BIGINT NOT NULL DEFAULT 1 CHECK (default_aal IN (1,2,3)),
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, key)
);

CREATE TABLE identity_source_records (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id BIGINT,
  sor TEXT NOT NULL CHECK (sor <> ''),
  sorid TEXT NOT NULL CHECK (sorid <> ''),
  attributes TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','retired')),
  received_at TEXT NOT NULL,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, sor, sorid),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id)
);

CREATE INDEX ix_identity_source_records_identity ON identity_source_records (tenant_id, identity_id);

CREATE TABLE identity_identifiers (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id BIGINT NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('email','phone','employee_id','student_id','applicant_id','netid','eppn',
    'saml_subject_id','saml_pairwise_id','oidc_sub','national_id_hmac')),
  issuer TEXT NOT NULL DEFAULT '',
  value_norm TEXT,
  value_hmac TEXT NOT NULL CHECK (value_hmac <> ''),
  verified_at TEXT,
  verified_by TEXT CHECK (verified_by IS NULL OR verified_by IN ('confirmation_code','federation','authoritative_source','proofing_agent')),
  source_record_id TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','retired')),
  created_at TEXT NOT NULL,
  CHECK ((verified_at IS NULL) = (verified_by IS NULL)),
  UNIQUE (tenant_id, type, issuer, value_hmac),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, source_record_id) REFERENCES identity_source_records (tenant_id, id)
);

CREATE INDEX ix_identity_identifiers_identity ON identity_identifiers (tenant_id, identity_id);

CREATE TABLE affiliations (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id BIGINT NOT NULL,
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
  created_by TEXT,
  created_at TEXT NOT NULL,
  ended_by TEXT,
  end_reason TEXT,
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id)
);

CREATE INDEX ix_affiliations_identity ON affiliations (tenant_id, identity_id, status);
CREATE INDEX ix_affiliations_ending ON affiliations (tenant_id, ends_at) WHERE status = 'active';

-- population names a guest_populations row of the same tenant (a trigger in SQLite, which
-- runs without foreign keys; a composite foreign key here). NULL stays allowed.
ALTER TABLE affiliations ADD FOREIGN KEY (tenant_id, population) REFERENCES guest_populations (tenant_id, key);

-- An affiliation is history once ended: only the end columns change, once.
CREATE TRIGGER affiliations_immutable BEFORE UPDATE ON affiliations
	FOR EACH ROW WHEN (OLD.status IN ('ended','revoked') OR NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id
		OR NEW.identity_id <> OLD.identity_id OR NEW.type <> OLD.type OR NEW.source <> OLD.source
		OR NEW.starts_at <> OLD.starts_at OR NEW.created_at <> OLD.created_at)
	EXECUTE FUNCTION tessera_abort('affiliations: ended rows and identity columns are immutable');

CREATE TRIGGER affiliations_no_delete BEFORE DELETE ON affiliations
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('affiliations are append-only');

-- Columns that name a user (or an edge that may expire) but are not foreign keys: SQLite never
-- enforced them, and they hold display strings or ids of rows that may be gone. The guard refuses an
-- id that belongs to ANOTHER tenant and tolerates one that does not exist (tessera_guard_soft_ref).
CREATE TRIGGER tg_affiliations_ended_by_xtenant BEFORE INSERT OR UPDATE OF tenant_id, ended_by ON affiliations
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('platform_users', 'ended_by', 'text');
CREATE TRIGGER tg_affiliations_created_by_xtenant BEFORE INSERT OR UPDATE OF tenant_id, created_by ON affiliations
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('platform_users', 'created_by', 'text');
