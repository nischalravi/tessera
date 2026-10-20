-- Guest terms of use, attribute-release consent and account recovery (guest
-- accounts design §7.4, §7.5, issue #73 / GU-10).
--
-- terms_documents: one row per VERSION of a terms document (acceptable use,
-- privacy notice, a contractor confidentiality notice). document_key names the
-- document across versions; the highest version is the one in force. body is the
-- rendered text a person is shown and text_sha256 is the SHA-256 of exactly
-- those bytes, so an acceptance can be tied to the text. grace_days is how
-- long a person who accepted an earlier version keeps access after a new
-- version is published. A version never changes and is never deleted.
--
-- terms_assignments: which guest populations (population) or access bundles
-- (group_id: the catalog item's group) a document applies to. scope is the
-- unique key of the pair ('population:contractor', 'bundle:42').
--
-- terms_acceptances: the ledger of who accepted which version and when, with
-- the text hash, the claim session, and keyed hashes of the client address and
-- user agent. Append-only; the same fact is in the audit ledger.
--
-- attribute_consents: what a guest agreed to release at a federated sign-in
-- (the attributes offered and the subset consented to). Append-only.
--
-- recovery_cases: one account recovery (a purpose=recovery claim token issued
-- by a sponsor or the help desk). required_ial is the identity's recorded IAL
-- (never lower); privileged says the identity holds a privileged or high-risk
-- bundle, which puts a cooling-off between the new credential and its activation:
-- the credential to bind waits in pending_* until cooling_until.
--
-- recovery_codes: the single-use codes of a hosted identity. Only a tenant-keyed
-- hash is stored; the codes are shown once, when generated. A new batch voids
-- the earlier one.
--
-- Tenant-owned like 0001_tenancy.sql: every UNIQUE starts with tenant_id and
-- guard triggers refuse a reference to another tenant's row. Created with IF
-- NOT EXISTS; a reseed drops and recreates (store.tables).

CREATE TABLE IF NOT EXISTS terms_documents (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  document_key TEXT NOT NULL CHECK (length(document_key) BETWEEN 1 AND 64),
  version INTEGER NOT NULL CHECK (version >= 1),
  title TEXT NOT NULL CHECK (title <> ''),
  body TEXT NOT NULL CHECK (body <> ''),
  text_sha256 TEXT NOT NULL CHECK (length(text_sha256) = 64),
  grace_days INTEGER NOT NULL DEFAULT 14 CHECK (grace_days BETWEEN 0 AND 365),
  created_by TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  UNIQUE (tenant_id, document_key, version)
);

CREATE TABLE IF NOT EXISTS terms_assignments (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  document_key TEXT NOT NULL CHECK (length(document_key) BETWEEN 1 AND 64),
  scope TEXT NOT NULL CHECK (scope <> ''),
  population TEXT CHECK (population IN ('visitor','contractor','volunteer','partner')),
  group_id INTEGER REFERENCES groups (id),
  created_at TEXT NOT NULL,
  CHECK ((population IS NULL) <> (group_id IS NULL)),
  UNIQUE (tenant_id, document_key, scope)
);
CREATE INDEX IF NOT EXISTS ix_terms_assignments_scope ON terms_assignments (tenant_id, scope);

CREATE TABLE IF NOT EXISTS terms_acceptances (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id INTEGER NOT NULL REFERENCES identities (id),
  document_id TEXT NOT NULL REFERENCES terms_documents (id),
  document_key TEXT NOT NULL,
  version INTEGER NOT NULL,
  text_sha256 TEXT NOT NULL CHECK (length(text_sha256) = 64),
  context TEXT NOT NULL CHECK (context IN ('claim','recovery','signin')),
  claim_session_hash TEXT REFERENCES claim_sessions (id_hash),
  ip_hash TEXT NOT NULL DEFAULT '',
  ua_hash TEXT NOT NULL DEFAULT '',
  accepted_at TEXT NOT NULL,
  UNIQUE (tenant_id, identity_id, document_id)
);
CREATE INDEX IF NOT EXISTS ix_terms_acceptances_identity ON terms_acceptances (tenant_id, identity_id);

CREATE TABLE IF NOT EXISTS attribute_consents (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id INTEGER NOT NULL REFERENCES identities (id),
  claim_session_hash TEXT NOT NULL REFERENCES claim_sessions (id_hash),
  authority TEXT NOT NULL,
  offered TEXT NOT NULL,
  consented TEXT NOT NULL,
  consented_at TEXT NOT NULL,
  UNIQUE (tenant_id, claim_session_hash)
);

CREATE TABLE IF NOT EXISTS recovery_cases (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id INTEGER NOT NULL REFERENCES identities (id),
  intake_id TEXT NOT NULL REFERENCES intake_records (id),
  token_id TEXT NOT NULL REFERENCES claim_tokens (id),
  session_id_hash TEXT REFERENCES claim_sessions (id_hash),
  issued_by TEXT NOT NULL CHECK (issued_by <> ''),
  via TEXT NOT NULL CHECK (via IN ('sponsor','help_desk')),
  reason TEXT NOT NULL DEFAULT '',
  required_ial INTEGER NOT NULL CHECK (required_ial IN (0,1,2)),
  privileged INTEGER NOT NULL DEFAULT 0 CHECK (privileged IN (0,1)),
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
  CHECK ((status = 'completed') = (completed_at IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS ix_recovery_cases_identity ON recovery_cases (tenant_id, identity_id, status);
CREATE INDEX IF NOT EXISTS ix_recovery_cases_status ON recovery_cases (tenant_id, status, cooling_until);

CREATE TABLE IF NOT EXISTS recovery_codes (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id INTEGER NOT NULL REFERENCES identities (id),
  batch TEXT NOT NULL,
  code_hash TEXT NOT NULL CHECK (length(code_hash) = 64),
  created_at TEXT NOT NULL,
  used_at TEXT,
  voided_at TEXT,
  UNIQUE (tenant_id, code_hash)
);
CREATE INDEX IF NOT EXISTS ix_recovery_codes_identity ON recovery_codes (tenant_id, identity_id, batch);

-- Versions, acceptances and consents are ledgers: never changed, never deleted
-- (the immutable triggers refuse every UPDATE, so they need no UPDATE guards).
CREATE TRIGGER IF NOT EXISTS tg_terms_documents_immutable BEFORE UPDATE ON terms_documents
BEGIN SELECT RAISE(ABORT, 'terms_documents: versions are immutable'); END;
CREATE TRIGGER IF NOT EXISTS tg_terms_documents_no_delete BEFORE DELETE ON terms_documents
BEGIN SELECT RAISE(ABORT, 'terms_documents are append-only'); END;
CREATE TRIGGER IF NOT EXISTS tg_terms_acceptances_immutable BEFORE UPDATE ON terms_acceptances
BEGIN SELECT RAISE(ABORT, 'terms_acceptances are append-only'); END;
CREATE TRIGGER IF NOT EXISTS tg_terms_acceptances_no_delete BEFORE DELETE ON terms_acceptances
BEGIN SELECT RAISE(ABORT, 'terms_acceptances are append-only'); END;
CREATE TRIGGER IF NOT EXISTS tg_attribute_consents_immutable BEFORE UPDATE ON attribute_consents
BEGIN SELECT RAISE(ABORT, 'attribute_consents are append-only'); END;
CREATE TRIGGER IF NOT EXISTS tg_attribute_consents_no_delete BEFORE DELETE ON attribute_consents
BEGIN SELECT RAISE(ABORT, 'attribute_consents are append-only'); END;

-- A recovery case's binding never changes and a final case is final; a code is
-- spent or voided once and its hash never changes.
CREATE TRIGGER IF NOT EXISTS tg_recovery_cases_immutable BEFORE UPDATE ON recovery_cases
WHEN OLD.status IN ('completed','cancelled','expired') OR NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id
	OR NEW.identity_id <> OLD.identity_id OR NEW.intake_id <> OLD.intake_id OR NEW.token_id <> OLD.token_id
	OR NEW.issued_by <> OLD.issued_by OR NEW.via <> OLD.via OR NEW.required_ial <> OLD.required_ial
	OR NEW.privileged <> OLD.privileged OR NEW.created_at <> OLD.created_at
BEGIN SELECT RAISE(ABORT, 'recovery_cases: final rows and binding columns are immutable'); END;
CREATE TRIGGER IF NOT EXISTS tg_recovery_cases_no_delete BEFORE DELETE ON recovery_cases
BEGIN SELECT RAISE(ABORT, 'recovery_cases are append-only'); END;
CREATE TRIGGER IF NOT EXISTS tg_recovery_codes_immutable BEFORE UPDATE ON recovery_codes
WHEN NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.identity_id <> OLD.identity_id OR NEW.batch <> OLD.batch
	OR NEW.code_hash <> OLD.code_hash OR NEW.created_at <> OLD.created_at
	OR (OLD.used_at IS NOT NULL AND NEW.used_at IS NOT OLD.used_at) OR (OLD.voided_at IS NOT NULL AND NEW.voided_at IS NOT OLD.voided_at)
BEGIN SELECT RAISE(ABORT, 'recovery_codes: binding columns and use are immutable'); END;
CREATE TRIGGER IF NOT EXISTS tg_recovery_codes_no_delete BEFORE DELETE ON recovery_codes
BEGIN SELECT RAISE(ABORT, 'recovery_codes are append-only'); END;

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_terms_assignments_xtenant_ins BEFORE INSERT ON terms_assignments
WHEN EXISTS (SELECT 1 FROM groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: terms_assignments'); END;

CREATE TRIGGER IF NOT EXISTS tg_terms_assignments_xtenant_upd BEFORE UPDATE OF tenant_id, group_id ON terms_assignments
WHEN EXISTS (SELECT 1 FROM groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: terms_assignments'); END;

CREATE TRIGGER IF NOT EXISTS tg_terms_acceptances_xtenant_ins BEFORE INSERT ON terms_acceptances
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM terms_documents p WHERE p.id = NEW.document_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM claim_sessions p WHERE p.id_hash = NEW.claim_session_hash AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: terms_acceptances'); END;

CREATE TRIGGER IF NOT EXISTS tg_attribute_consents_xtenant_ins BEFORE INSERT ON attribute_consents
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM claim_sessions p WHERE p.id_hash = NEW.claim_session_hash AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: attribute_consents'); END;

CREATE TRIGGER IF NOT EXISTS tg_recovery_cases_xtenant_ins BEFORE INSERT ON recovery_cases
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM intake_records p WHERE p.id = NEW.intake_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM claim_tokens p WHERE p.id = NEW.token_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM claim_sessions p WHERE p.id_hash = NEW.session_id_hash AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: recovery_cases'); END;

CREATE TRIGGER IF NOT EXISTS tg_recovery_cases_xtenant_upd BEFORE UPDATE OF tenant_id, identity_id, intake_id, token_id, session_id_hash ON recovery_cases
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM intake_records p WHERE p.id = NEW.intake_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM claim_tokens p WHERE p.id = NEW.token_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM claim_sessions p WHERE p.id_hash = NEW.session_id_hash AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: recovery_cases'); END;

CREATE TRIGGER IF NOT EXISTS tg_recovery_codes_xtenant_ins BEFORE INSERT ON recovery_codes
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: recovery_codes'); END;

CREATE TRIGGER IF NOT EXISTS tg_recovery_codes_xtenant_upd BEFORE UPDATE OF tenant_id, identity_id ON recovery_codes
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: recovery_codes'); END;
