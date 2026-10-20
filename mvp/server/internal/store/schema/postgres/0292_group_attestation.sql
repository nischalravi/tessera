-- Postgres dialect of schema/0292_group_attestation.sql (kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres). The cross-tenant triggers become composite foreign keys
-- (tenant_id, x_id) -> (tenant_id, id); owner/object columns that name a folder or a group by a type
-- column, and platform user ids, are checked by plpgsql guards (tessera_guard_grp_object of 0285,
-- tessera_guard_grp_owner below, tessera_guard_soft_ref of 0001). json_valid is IS JSON.

-- +goose Up

CREATE TABLE grp_inbox_tasks (
  id                   TEXT PRIMARY KEY,
  tenant_id            TEXT NOT NULL REFERENCES tenants (id),
  kind                 TEXT NOT NULL CHECK (kind IN ('deprovisioning','rule','micro_certification','attestation','attestation_overdue')),
  title                TEXT NOT NULL,
  detail               TEXT NOT NULL DEFAULT '{}' CHECK (detail IS JSON),
  object_type          TEXT NOT NULL CHECK (object_type IN ('folder','group')),
  object_id            TEXT NOT NULL,
  subject_identity_id  BIGINT,
  assignee_identity_id BIGINT,
  status               TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','done','dismissed')),
  dedupe_key           TEXT,
  due_at               TEXT,
  created_at           TEXT NOT NULL,
  closed_at            TEXT,
  closed_by            TEXT,
  UNIQUE (tenant_id, id),
  CHECK ((status = 'open') = (closed_at IS NULL)),
  FOREIGN KEY (tenant_id, subject_identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, assignee_identity_id) REFERENCES identities (tenant_id, id)
);
CREATE INDEX grp_inbox_status ON grp_inbox_tasks (tenant_id, status, created_at);
CREATE INDEX grp_inbox_object ON grp_inbox_tasks (tenant_id, object_type, object_id);
CREATE UNIQUE INDEX grp_inbox_open_key ON grp_inbox_tasks (tenant_id, dedupe_key)
  WHERE status = 'open' AND dedupe_key IS NOT NULL;

CREATE TABLE grp_attest_settings (
  tenant_id         TEXT NOT NULL REFERENCES tenants (id),
  owner_type        TEXT NOT NULL CHECK (owner_type IN ('folder','group')),
  owner_id          TEXT NOT NULL,
  interval_days     INTEGER NOT NULL CHECK (interval_days BETWEEN 1 AND 3650),
  window_days       INTEGER NOT NULL CHECK (window_days BETWEEN 1 AND 365),
  reviewer_type     TEXT NOT NULL DEFAULT 'admins' CHECK (reviewer_type IN ('admins','group')),
  reviewer_group_id TEXT,
  reminder_days     TEXT NOT NULL DEFAULT '[]' CHECK (reminder_days IS JSON),
  overdue_action    TEXT NOT NULL DEFAULT 'none' CHECK (overdue_action IN ('none','disable_group','remove_unattested')),
  enabled           INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
  updated_by        TEXT NOT NULL,
  updated_at        TEXT NOT NULL,
  PRIMARY KEY (tenant_id, owner_type, owner_id),
  CHECK ((reviewer_type = 'group') = (reviewer_group_id IS NOT NULL)),
  FOREIGN KEY (tenant_id, reviewer_group_id) REFERENCES grp_groups (tenant_id, id)
);

CREATE TABLE grp_attest_campaigns (
  id                 TEXT PRIMARY KEY,
  tenant_id          TEXT NOT NULL REFERENCES tenants (id),
  group_id           TEXT NOT NULL,
  kind               TEXT NOT NULL CHECK (kind IN ('periodic','micro')),
  review_campaign_id BIGINT,
  status             TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','completed','overdue_applied','cancelled')),
  started_at         TEXT NOT NULL,
  due_at             TEXT NOT NULL,
  closed_at          TEXT,
  overdue_action     TEXT NOT NULL DEFAULT 'none' CHECK (overdue_action IN ('none','disable_group','remove_unattested')),
  reviewer_type      TEXT NOT NULL DEFAULT 'admins' CHECK (reviewer_type IN ('admins','group')),
  reviewer_group_id  TEXT,
  reminder_days      TEXT NOT NULL DEFAULT '[]' CHECK (reminder_days IS JSON),
  acts_as            TEXT NOT NULL,
  population_count   INTEGER NOT NULL,
  population_hash    TEXT NOT NULL,
  reminders_sent     INTEGER NOT NULL DEFAULT 0,
  last_reminder_at   TEXT,
  started_by         TEXT,
  rule_id            TEXT,
  UNIQUE (tenant_id, id),
  CHECK ((status = 'open') = (closed_at IS NULL)),
  FOREIGN KEY (tenant_id, group_id) REFERENCES grp_groups (tenant_id, id),
  FOREIGN KEY (tenant_id, review_campaign_id) REFERENCES review_campaigns (tenant_id, id),
  FOREIGN KEY (tenant_id, reviewer_group_id) REFERENCES grp_groups (tenant_id, id)
);
CREATE INDEX grp_attest_camp_group ON grp_attest_campaigns (tenant_id, group_id, started_at);
CREATE INDEX grp_attest_camp_status ON grp_attest_campaigns (tenant_id, status);
CREATE UNIQUE INDEX grp_attest_one_open ON grp_attest_campaigns (tenant_id, group_id)
  WHERE status = 'open' AND kind = 'periodic';

CREATE TABLE grp_attest_items (
  id             TEXT PRIMARY KEY,
  tenant_id      TEXT NOT NULL REFERENCES tenants (id),
  campaign_id    TEXT NOT NULL,
  group_id       TEXT NOT NULL,
  identity_id    BIGINT NOT NULL,
  how            TEXT NOT NULL CHECK (how IN ('direct','nested')),
  review_item_id BIGINT,
  apply_state    TEXT NOT NULL DEFAULT 'pending' CHECK (apply_state IN ('pending','applied','denied','skipped','failed')),
  apply_detail   TEXT NOT NULL DEFAULT '',
  applied_at     TEXT,
  UNIQUE (tenant_id, campaign_id, identity_id),
  FOREIGN KEY (tenant_id, campaign_id) REFERENCES grp_attest_campaigns (tenant_id, id),
  FOREIGN KEY (tenant_id, group_id) REFERENCES grp_groups (tenant_id, id),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (review_item_id) REFERENCES review_items (id)
);
CREATE INDEX grp_attest_items_review ON grp_attest_items (tenant_id, review_item_id);

CREATE TABLE grp_deprov_settings (
  tenant_id    TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  affiliations TEXT NOT NULL DEFAULT '[]' CHECK (affiliations IS JSON),
  veto_enabled INTEGER NOT NULL DEFAULT 1 CHECK (veto_enabled IN (0,1)),
  updated_at   TEXT NOT NULL,
  updated_by   TEXT
);

CREATE TABLE grp_deprov_folders (
  tenant_id  TEXT NOT NULL REFERENCES tenants (id),
  folder_id  TEXT NOT NULL,
  mode       TEXT NOT NULL CHECK (mode IN ('notify','auto_after','auto_now')),
  days       INTEGER NOT NULL DEFAULT 0 CHECK (days BETWEEN 0 AND 3650),
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, folder_id),
  CHECK ((mode = 'auto_after') = (days > 0)),
  FOREIGN KEY (tenant_id, folder_id) REFERENCES grp_folders (tenant_id, id)
);

CREATE TABLE grp_deprovisioned (
  tenant_id   TEXT NOT NULL REFERENCES tenants (id),
  identity_id BIGINT NOT NULL,
  since       TEXT NOT NULL,
  reason      TEXT NOT NULL CHECK (reason IN ('affiliation_lost','leaver')),
  PRIMARY KEY (tenant_id, identity_id),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id)
);

CREATE TABLE grp_deprov_items (
  id          TEXT PRIMARY KEY,
  tenant_id   TEXT NOT NULL REFERENCES tenants (id),
  identity_id BIGINT NOT NULL,
  folder_id   TEXT NOT NULL,
  task_id     TEXT,
  status      TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','removed','dismissed')),
  mode        TEXT NOT NULL CHECK (mode IN ('notify','auto_after','auto_now')),
  detail      TEXT NOT NULL DEFAULT '{}' CHECK (detail IS JSON),
  opened_at   TEXT NOT NULL,
  due_at      TEXT,
  resolved_at TEXT,
  resolved_by TEXT,
  reason      TEXT NOT NULL DEFAULT '',
  CHECK ((status = 'open') = (resolved_at IS NULL)),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, folder_id) REFERENCES grp_folders (tenant_id, id),
  FOREIGN KEY (tenant_id, task_id) REFERENCES grp_inbox_tasks (tenant_id, id)
);
CREATE INDEX grp_deprov_items_status ON grp_deprov_items (tenant_id, status, opened_at);
CREATE UNIQUE INDEX grp_deprov_one_open ON grp_deprov_items (tenant_id, identity_id, folder_id) WHERE status = 'open';

CREATE TABLE grp_reports (
  id          TEXT PRIMARY KEY,
  tenant_id   TEXT NOT NULL REFERENCES tenants (id),
  name        TEXT NOT NULL,
  kind        TEXT NOT NULL,
  params      TEXT NOT NULL DEFAULT '{}' CHECK (params IS JSON),
  format      TEXT NOT NULL DEFAULT 'csv' CHECK (format IN ('csv','json')),
  schedule    TEXT NOT NULL DEFAULT 'none' CHECK (schedule IN ('none','daily','weekly','monthly')),
  delivery    TEXT NOT NULL DEFAULT 'store' CHECK (delivery IN ('store','email')),
  next_run_at TEXT,
  last_run_at TEXT,
  created_by  TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL,
  UNIQUE (tenant_id, id),
  CHECK ((schedule = 'none') = (next_run_at IS NULL))
);
CREATE INDEX grp_reports_due ON grp_reports (tenant_id, next_run_at) WHERE next_run_at IS NOT NULL;

CREATE TABLE grp_report_runs (
  id           TEXT PRIMARY KEY,
  tenant_id    TEXT NOT NULL REFERENCES tenants (id),
  report_id    TEXT NOT NULL,
  ran_at       TEXT NOT NULL,
  ran_by       TEXT NOT NULL,
  trigger_type TEXT NOT NULL CHECK (trigger_type IN ('manual','schedule')),
  status       TEXT NOT NULL CHECK (status IN ('ok','failed')),
  format       TEXT NOT NULL CHECK (format IN ('csv','json')),
  row_count    INTEGER NOT NULL DEFAULT 0,
  truncated    INTEGER NOT NULL DEFAULT 0 CHECK (truncated IN (0,1)),
  sha256       TEXT NOT NULL DEFAULT '',
  content      TEXT NOT NULL DEFAULT '',
  error        TEXT NOT NULL DEFAULT '',
  FOREIGN KEY (tenant_id, report_id) REFERENCES grp_reports (tenant_id, id)
);
CREATE INDEX grp_report_runs_report ON grp_report_runs (tenant_id, report_id, ran_at);

-- ---------------------------------------------------------------- cross-tenant guards

-- owner_id names a folder or a group by owner_type (no foreign key)
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION tessera_guard_grp_owner() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
	crosses boolean := false;
BEGIN
	IF NEW.owner_type = 'folder' THEN
		SELECT EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.owner_id AND p.tenant_id <> NEW.tenant_id) INTO crosses;
	ELSIF NEW.owner_type = 'group' THEN
		SELECT EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.owner_id AND p.tenant_id <> NEW.tenant_id) INTO crosses;
	END IF;
	IF crosses THEN
		RAISE EXCEPTION 'cross-tenant reference: %', TG_TABLE_NAME USING ERRCODE = 'integrity_constraint_violation';
	END IF;
	RETURN NEW;
END
$fn$;
-- +goose StatementEnd

CREATE TRIGGER tg_grp_inbox_tasks_object_xtenant BEFORE INSERT OR UPDATE OF tenant_id, object_type, object_id ON grp_inbox_tasks
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_grp_object();
CREATE TRIGGER tg_grp_attest_settings_owner_xtenant BEFORE INSERT OR UPDATE OF tenant_id, owner_type, owner_id ON grp_attest_settings
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_grp_owner();

-- review_items has no (tenant_id, id) key here, so its tenant is guarded by a trigger
CREATE TRIGGER tg_grp_attest_items_review_xtenant BEFORE INSERT OR UPDATE OF tenant_id, review_item_id ON grp_attest_items
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('review_items', 'review_item_id', 'bigint');

-- platform user ids (text) in the audit columns
CREATE TRIGGER tg_grp_attest_settings_user_xtenant BEFORE INSERT OR UPDATE OF tenant_id, updated_by ON grp_attest_settings
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('platform_users', 'updated_by', 'text');
CREATE TRIGGER tg_grp_attest_campaigns_actor_xtenant BEFORE INSERT OR UPDATE OF tenant_id, acts_as ON grp_attest_campaigns
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('platform_users', 'acts_as', 'text');
CREATE TRIGGER tg_grp_attest_campaigns_starter_xtenant BEFORE INSERT OR UPDATE OF tenant_id, started_by ON grp_attest_campaigns
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('platform_users', 'started_by', 'text');
CREATE TRIGGER tg_grp_deprov_folders_user_xtenant BEFORE INSERT OR UPDATE OF tenant_id, updated_by ON grp_deprov_folders
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('platform_users', 'updated_by', 'text');
CREATE TRIGGER tg_grp_reports_user_xtenant BEFORE INSERT OR UPDATE OF tenant_id, created_by ON grp_reports
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('platform_users', 'created_by', 'text');
CREATE TRIGGER tg_grp_report_runs_user_xtenant BEFORE INSERT OR UPDATE OF tenant_id, ran_by ON grp_report_runs
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('platform_users', 'ran_by', 'text');
