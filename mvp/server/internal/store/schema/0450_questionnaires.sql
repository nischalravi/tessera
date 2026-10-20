-- Questionnaires (issue #298): forms attached to access requests, privileged items and access
-- review campaigns ("why do you need this?", risk questions).
--
-- questionnaires is the definition's identity and its current version. questionnaire_versions
-- holds every version's title, description and questions (a JSON list; see internal/questionnaires),
-- append-only: editing inserts the next version, so an answer always points at the exact form it was
-- given against. status 'retired' stops new use (its attachments are removed); old answers stay.
--
-- questionnaire_attachments say where a questionnaire is asked. target_kind is catalog_item or
-- business_role (target_id is the item's or role's id), review_campaign (the campaign id, answered
-- per decision) or privileged (target_id '*': every catalog item whose group is privileged and
-- every high-risk role). One questionnaire per target.
--
-- questionnaire_answers are what people answered: one row per subject (a request line, a role
-- request or a review item) and questionnaire, with the version answered, the answers (JSON object
-- keyed by question id) and their SHA-256 (the audit event carries the hash). answered_by is the
-- display name; the audit ledger holds the same hash chained.
--
-- Tenant-owned: guard triggers at the end refuse references to another tenant's rows.
CREATE TABLE IF NOT EXISTS questionnaires (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  title TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','retired')),
  version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
  created_at TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, title)
);

CREATE TABLE IF NOT EXISTS questionnaire_versions (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  questionnaire_id TEXT NOT NULL REFERENCES questionnaires (id),
  version INTEGER NOT NULL CHECK (version >= 1),
  title TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  questions TEXT NOT NULL CHECK (json_valid(questions)),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (tenant_id, questionnaire_id, version)
);

CREATE TRIGGER IF NOT EXISTS tg_questionnaire_versions_no_update BEFORE UPDATE ON questionnaire_versions
BEGIN SELECT RAISE(ABORT, 'questionnaire_versions is append-only'); END;
CREATE TRIGGER IF NOT EXISTS tg_questionnaire_versions_no_delete BEFORE DELETE ON questionnaire_versions
BEGIN SELECT RAISE(ABORT, 'questionnaire_versions is append-only'); END;

CREATE TABLE IF NOT EXISTS questionnaire_attachments (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  questionnaire_id TEXT NOT NULL REFERENCES questionnaires (id),
  target_kind TEXT NOT NULL CHECK (target_kind IN ('catalog_item','business_role','review_campaign','privileged')),
  target_id TEXT NOT NULL,
  UNIQUE (tenant_id, target_kind, target_id)
);
CREATE INDEX IF NOT EXISTS ix_questionnaire_attachments_tenant_q ON questionnaire_attachments (tenant_id, questionnaire_id);

CREATE TABLE IF NOT EXISTS questionnaire_answers (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  questionnaire_id TEXT NOT NULL REFERENCES questionnaires (id),
  version INTEGER NOT NULL,
  subject_kind TEXT NOT NULL CHECK (subject_kind IN ('request_line','role_request','review_item')),
  subject_id TEXT NOT NULL,
  answers TEXT NOT NULL CHECK (json_valid(answers)),
  answers_hash TEXT NOT NULL,
  answered_by TEXT NOT NULL,
  answered_at TEXT NOT NULL,
  UNIQUE (tenant_id, subject_kind, subject_id, questionnaire_id),
  FOREIGN KEY (tenant_id, questionnaire_id, version) REFERENCES questionnaire_versions (tenant_id, questionnaire_id, version)
);

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_questionnaire_versions_xtenant_ins BEFORE INSERT ON questionnaire_versions
WHEN EXISTS (SELECT 1 FROM questionnaires p WHERE p.id = NEW.questionnaire_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: questionnaire_versions'); END;

CREATE TRIGGER IF NOT EXISTS tg_questionnaire_versions_xtenant_upd BEFORE UPDATE OF tenant_id, questionnaire_id ON questionnaire_versions
WHEN EXISTS (SELECT 1 FROM questionnaires p WHERE p.id = NEW.questionnaire_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: questionnaire_versions'); END;

CREATE TRIGGER IF NOT EXISTS tg_questionnaire_attachments_xtenant_ins BEFORE INSERT ON questionnaire_attachments
WHEN EXISTS (SELECT 1 FROM questionnaires p WHERE p.id = NEW.questionnaire_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: questionnaire_attachments'); END;

CREATE TRIGGER IF NOT EXISTS tg_questionnaire_attachments_xtenant_upd BEFORE UPDATE OF tenant_id, questionnaire_id ON questionnaire_attachments
WHEN EXISTS (SELECT 1 FROM questionnaires p WHERE p.id = NEW.questionnaire_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: questionnaire_attachments'); END;

CREATE TRIGGER IF NOT EXISTS tg_questionnaire_answers_xtenant_ins BEFORE INSERT ON questionnaire_answers
WHEN EXISTS (SELECT 1 FROM questionnaires p WHERE p.id = NEW.questionnaire_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM questionnaire_versions p WHERE p.questionnaire_id = NEW.questionnaire_id AND p.version = NEW.version AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: questionnaire_answers'); END;

CREATE TRIGGER IF NOT EXISTS tg_questionnaire_answers_xtenant_upd BEFORE UPDATE OF tenant_id, questionnaire_id, version ON questionnaire_answers
WHEN EXISTS (SELECT 1 FROM questionnaires p WHERE p.id = NEW.questionnaire_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM questionnaire_versions p WHERE p.questionnaire_id = NEW.questionnaire_id AND p.version = NEW.version AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: questionnaire_answers'); END;
