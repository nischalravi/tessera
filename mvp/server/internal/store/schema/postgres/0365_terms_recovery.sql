-- Postgres dialect of schema/0365_terms_recovery.sql (kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE terms_documents (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  document_key TEXT NOT NULL CHECK (length(document_key) BETWEEN 1 AND 64),
  version BIGINT NOT NULL CHECK (version >= 1),
  title TEXT NOT NULL CHECK (title <> ''),
  body TEXT NOT NULL CHECK (body <> ''),
  text_sha256 TEXT NOT NULL CHECK (length(text_sha256) = 64),
  grace_days BIGINT NOT NULL DEFAULT 14 CHECK (grace_days BETWEEN 0 AND 365),
  created_by TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  UNIQUE (tenant_id, document_key, version),
  UNIQUE (tenant_id, id)
);

CREATE TABLE terms_assignments (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  document_key TEXT NOT NULL CHECK (length(document_key) BETWEEN 1 AND 64),
  scope TEXT NOT NULL CHECK (scope <> ''),
  population TEXT CHECK (population IN ('visitor','contractor','volunteer','partner')),
  group_id BIGINT,
  created_at TEXT NOT NULL,
  CHECK ((population IS NULL) <> (group_id IS NULL)),
  UNIQUE (tenant_id, document_key, scope),
  FOREIGN KEY (tenant_id, group_id) REFERENCES groups (tenant_id, id)
);
CREATE INDEX ix_terms_assignments_scope ON terms_assignments (tenant_id, scope);

CREATE TABLE terms_acceptances (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id BIGINT NOT NULL,
  document_id TEXT NOT NULL,
  document_key TEXT NOT NULL,
  version BIGINT NOT NULL,
  text_sha256 TEXT NOT NULL CHECK (length(text_sha256) = 64),
  context TEXT NOT NULL CHECK (context IN ('claim','recovery','signin')),
  claim_session_hash TEXT,
  ip_hash TEXT NOT NULL DEFAULT '',
  ua_hash TEXT NOT NULL DEFAULT '',
  accepted_at TEXT NOT NULL,
  UNIQUE (tenant_id, identity_id, document_id),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, document_id) REFERENCES terms_documents (tenant_id, id),
  FOREIGN KEY (tenant_id, claim_session_hash) REFERENCES claim_sessions (tenant_id, id_hash)
);
CREATE INDEX ix_terms_acceptances_identity ON terms_acceptances (tenant_id, identity_id);

CREATE TABLE attribute_consents (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id BIGINT NOT NULL,
  claim_session_hash TEXT NOT NULL,
  authority TEXT NOT NULL,
  offered TEXT NOT NULL,
  consented TEXT NOT NULL,
  consented_at TEXT NOT NULL,
  UNIQUE (tenant_id, claim_session_hash),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, claim_session_hash) REFERENCES claim_sessions (tenant_id, id_hash)
);

CREATE TABLE recovery_cases (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id BIGINT NOT NULL,
  intake_id TEXT NOT NULL,
  token_id TEXT NOT NULL,
  session_id_hash TEXT,
  issued_by TEXT NOT NULL CHECK (issued_by <> ''),
  via TEXT NOT NULL CHECK (via IN ('sponsor','help_desk')),
  reason TEXT NOT NULL DEFAULT '',
  required_ial BIGINT NOT NULL CHECK (required_ial IN (0,1,2)),
  privileged BIGINT NOT NULL DEFAULT 0 CHECK (privileged IN (0,1)),
  status TEXT NOT NULL CHECK (status IN ('issued','started','cooling_off','completed','cancelled','expired')),
  pending_connection_id TEXT,
  pending_issuer TEXT,
  pending_subject TEXT,
  pending_email TEXT,
  cooling_until TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  completed_at TEXT,
  UNIQUE (tenant_id, token_id),
  CHECK (status <> 'cooling_off' OR cooling_until IS NOT NULL),
  CHECK ((status = 'completed') = (completed_at IS NOT NULL)),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, intake_id) REFERENCES intake_records (tenant_id, id),
  FOREIGN KEY (tenant_id, token_id) REFERENCES claim_tokens (tenant_id, id),
  FOREIGN KEY (tenant_id, session_id_hash) REFERENCES claim_sessions (tenant_id, id_hash)
);
CREATE INDEX ix_recovery_cases_identity ON recovery_cases (tenant_id, identity_id, status);
CREATE INDEX ix_recovery_cases_status ON recovery_cases (tenant_id, status, cooling_until);

CREATE TABLE recovery_codes (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id BIGINT NOT NULL,
  batch TEXT NOT NULL,
  code_hash TEXT NOT NULL CHECK (length(code_hash) = 64),
  created_at TEXT NOT NULL,
  used_at TEXT,
  voided_at TEXT,
  UNIQUE (tenant_id, code_hash),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id)
);
CREATE INDEX ix_recovery_codes_identity ON recovery_codes (tenant_id, identity_id, batch);

-- Versions, acceptances and consents are ledgers: never changed, never deleted
-- (the immutable triggers refuse every UPDATE, so they need no UPDATE guards).

-- Versions, acceptances and consents are ledgers: never changed, never deleted.
CREATE TRIGGER terms_documents_immutable BEFORE UPDATE ON terms_documents
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('terms_documents: versions are immutable');
CREATE TRIGGER terms_documents_no_delete BEFORE DELETE ON terms_documents
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('terms_documents are append-only');
CREATE TRIGGER terms_acceptances_immutable BEFORE UPDATE ON terms_acceptances
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('terms_acceptances are append-only');
CREATE TRIGGER terms_acceptances_no_delete BEFORE DELETE ON terms_acceptances
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('terms_acceptances are append-only');
CREATE TRIGGER attribute_consents_immutable BEFORE UPDATE ON attribute_consents
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('attribute_consents are append-only');
CREATE TRIGGER attribute_consents_no_delete BEFORE DELETE ON attribute_consents
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('attribute_consents are append-only');

-- A recovery case's binding never changes and a final case is final; a code is
-- spent or voided once and its hash never changes.
CREATE TRIGGER recovery_cases_immutable BEFORE UPDATE ON recovery_cases
	FOR EACH ROW WHEN (OLD.status IN ('completed','cancelled','expired') OR NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id
		OR NEW.identity_id <> OLD.identity_id OR NEW.intake_id <> OLD.intake_id OR NEW.token_id <> OLD.token_id
		OR NEW.issued_by <> OLD.issued_by OR NEW.via <> OLD.via OR NEW.required_ial <> OLD.required_ial
		OR NEW.privileged <> OLD.privileged OR NEW.created_at <> OLD.created_at)
	EXECUTE FUNCTION tessera_abort('recovery_cases: final rows and binding columns are immutable');
CREATE TRIGGER recovery_cases_no_delete BEFORE DELETE ON recovery_cases
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('recovery_cases are append-only');
CREATE TRIGGER recovery_codes_immutable BEFORE UPDATE ON recovery_codes
	FOR EACH ROW WHEN (NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.identity_id <> OLD.identity_id OR NEW.batch <> OLD.batch
		OR NEW.code_hash <> OLD.code_hash OR NEW.created_at <> OLD.created_at
		OR (OLD.used_at IS NOT NULL AND NEW.used_at IS DISTINCT FROM OLD.used_at) OR (OLD.voided_at IS NOT NULL AND NEW.voided_at IS DISTINCT FROM OLD.voided_at))
	EXECUTE FUNCTION tessera_abort('recovery_codes: binding columns and use are immutable');
CREATE TRIGGER recovery_codes_no_delete BEFORE DELETE ON recovery_codes
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('recovery_codes are append-only');
