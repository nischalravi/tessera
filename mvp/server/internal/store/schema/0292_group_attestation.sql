-- Group attestation, deprovisioning, the groups Inbox and saved reports (issue
-- #57, GR-14; design docs/design/groups-grouper-parity.md §10.4, §10.5, §10.7).
-- The design puts this in 0107_group_gov.sql; 0280..0289 are taken or reserved
-- and 0290/0291 belong to another PR, so it is 0292.
--
-- Attestation is a group-membership campaign of the certification engine
-- (review_campaigns / review_items): grp_attest_campaigns links one to a group
-- and freezes its population (count and hash) when it starts.
--
-- owner_id / folder_id columns name a folder or a group with no foreign key
-- (a group is soft-deleted and a folder's settings go with it), so the guard
-- triggers check the tenant. Every table carries tenant_id and its guards.

-- ---------------------------------------------------------------- Inbox

-- A task for the people who administer an object (or one named identity). It
-- is shown to whoever holds admin (stem_admin on a folder) on the object, or
-- is the assignee: the check is made when it is listed, never copied here.
CREATE TABLE IF NOT EXISTS grp_inbox_tasks (
  id                   TEXT PRIMARY KEY,
  tenant_id            TEXT NOT NULL REFERENCES tenants (id),
  kind                 TEXT NOT NULL CHECK (kind IN ('deprovisioning','rule','micro_certification','attestation','attestation_overdue')),
  title                TEXT NOT NULL,
  detail               TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(detail)),
  object_type          TEXT NOT NULL CHECK (object_type IN ('folder','group')),
  object_id            TEXT NOT NULL,
  subject_identity_id  INTEGER REFERENCES identities (id),
  assignee_identity_id INTEGER REFERENCES identities (id),
  status               TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','done','dismissed')),
  -- one open task per key: a rule that fires twice, or a sweep that runs twice, opens one
  dedupe_key           TEXT,
  due_at               TEXT,
  created_at           TEXT NOT NULL,
  closed_at            TEXT,
  closed_by            TEXT,
  CHECK ((status = 'open') = (closed_at IS NULL))
);
CREATE INDEX IF NOT EXISTS grp_inbox_status ON grp_inbox_tasks (tenant_id, status, created_at);
CREATE INDEX IF NOT EXISTS grp_inbox_object ON grp_inbox_tasks (tenant_id, object_type, object_id);
CREATE UNIQUE INDEX IF NOT EXISTS grp_inbox_open_key ON grp_inbox_tasks (tenant_id, dedupe_key)
  WHERE status = 'open' AND dedupe_key IS NOT NULL;

-- ---------------------------------------------------------------- attestation

-- Settings of a group or folder; a group takes the nearest ancestor folder's
-- when it has none of its own. updated_by is the platform user the overdue
-- action acts as (checked again when it fires).
CREATE TABLE IF NOT EXISTS grp_attest_settings (
  tenant_id         TEXT NOT NULL REFERENCES tenants (id),
  owner_type        TEXT NOT NULL CHECK (owner_type IN ('folder','group')),
  owner_id          TEXT NOT NULL,
  interval_days     INTEGER NOT NULL CHECK (interval_days BETWEEN 1 AND 3650),
  window_days       INTEGER NOT NULL CHECK (window_days BETWEEN 1 AND 365),
  reviewer_type     TEXT NOT NULL DEFAULT 'admins' CHECK (reviewer_type IN ('admins','group')),
  reviewer_group_id TEXT REFERENCES grp_groups (id),
  reminder_days     TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(reminder_days)),
  overdue_action    TEXT NOT NULL DEFAULT 'none' CHECK (overdue_action IN ('none','disable_group','remove_unattested')),
  enabled           INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
  updated_by        TEXT NOT NULL,
  updated_at        TEXT NOT NULL,
  PRIMARY KEY (tenant_id, owner_type, owner_id),
  CHECK ((reviewer_type = 'group') = (reviewer_group_id IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS grp_attest_campaigns (
  id                TEXT PRIMARY KEY,
  tenant_id         TEXT NOT NULL REFERENCES tenants (id),
  group_id          TEXT NOT NULL REFERENCES grp_groups (id),
  kind              TEXT NOT NULL CHECK (kind IN ('periodic','micro')),
  review_campaign_id INTEGER REFERENCES review_campaigns (id),
  status            TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','completed','overdue_applied','cancelled')),
  started_at        TEXT NOT NULL,
  due_at            TEXT NOT NULL,
  closed_at         TEXT,
  -- what the campaign was started with, frozen: a later settings change does not move it
  overdue_action    TEXT NOT NULL DEFAULT 'none' CHECK (overdue_action IN ('none','disable_group','remove_unattested')),
  reviewer_type     TEXT NOT NULL DEFAULT 'admins' CHECK (reviewer_type IN ('admins','group')),
  reviewer_group_id TEXT REFERENCES grp_groups (id),
  reminder_days     TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(reminder_days)),
  acts_as           TEXT NOT NULL,
  -- the frozen population: how many identities, and the SHA-256 of their sorted list
  population_count  INTEGER NOT NULL,
  population_hash   TEXT NOT NULL,
  reminders_sent    INTEGER NOT NULL DEFAULT 0,
  last_reminder_at  TEXT,
  started_by        TEXT,
  rule_id           TEXT,
  CHECK ((status = 'open') = (closed_at IS NULL))
);
CREATE INDEX IF NOT EXISTS grp_attest_camp_group ON grp_attest_campaigns (tenant_id, group_id, started_at);
CREATE INDEX IF NOT EXISTS grp_attest_camp_status ON grp_attest_campaigns (tenant_id, status);
CREATE UNIQUE INDEX IF NOT EXISTS grp_attest_one_open ON grp_attest_campaigns (tenant_id, group_id)
  WHERE status = 'open' AND kind = 'periodic';

CREATE TABLE IF NOT EXISTS grp_attest_items (
  id             TEXT PRIMARY KEY,
  tenant_id      TEXT NOT NULL REFERENCES tenants (id),
  campaign_id    TEXT NOT NULL REFERENCES grp_attest_campaigns (id),
  group_id       TEXT NOT NULL REFERENCES grp_groups (id),
  identity_id    INTEGER NOT NULL REFERENCES identities (id),
  how            TEXT NOT NULL CHECK (how IN ('direct','nested')),
  review_item_id INTEGER REFERENCES review_items (id),
  -- what became of a revoke decision: applied through the engine, refused (the
  -- decider lacked the privilege), skipped (nested, or already gone) or failed
  apply_state    TEXT NOT NULL DEFAULT 'pending' CHECK (apply_state IN ('pending','applied','denied','skipped','failed')),
  apply_detail   TEXT NOT NULL DEFAULT '',
  applied_at     TEXT,
  UNIQUE (tenant_id, campaign_id, identity_id)
);
CREATE INDEX IF NOT EXISTS grp_attest_items_review ON grp_attest_items (tenant_id, review_item_id);

-- ---------------------------------------------------------------- deprovisioning

-- One row per tenant: the affiliation groups (a JSON list of group ids) and
-- whether new direct memberships of deprovisioned identities are vetoed.
CREATE TABLE IF NOT EXISTS grp_deprov_settings (
  tenant_id    TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  affiliations TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(affiliations)),
  veto_enabled INTEGER NOT NULL DEFAULT 1 CHECK (veto_enabled IN (0,1)),
  updated_at   TEXT NOT NULL,
  updated_by   TEXT
);

-- A folder's choice (inherited by the folders below it): notify the owners
-- only, remove after N days, or remove at once. updated_by is the platform
-- user an automatic removal acts as.
CREATE TABLE IF NOT EXISTS grp_deprov_folders (
  tenant_id  TEXT NOT NULL REFERENCES tenants (id),
  folder_id  TEXT NOT NULL,
  mode       TEXT NOT NULL CHECK (mode IN ('notify','auto_after','auto_now')),
  days       INTEGER NOT NULL DEFAULT 0 CHECK (days BETWEEN 0 AND 3650),
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, folder_id),
  CHECK ((mode = 'auto_after') = (days > 0))
);

-- An identity that left every affiliation (or a leaver): new direct
-- memberships are vetoed until it regains one or an administrator overrides
-- with a reason.
CREATE TABLE IF NOT EXISTS grp_deprovisioned (
  tenant_id   TEXT NOT NULL REFERENCES tenants (id),
  identity_id INTEGER NOT NULL REFERENCES identities (id),
  since       TEXT NOT NULL,
  reason      TEXT NOT NULL CHECK (reason IN ('affiliation_lost','leaver')),
  PRIMARY KEY (tenant_id, identity_id)
);

CREATE TABLE IF NOT EXISTS grp_deprov_items (
  id          TEXT PRIMARY KEY,
  tenant_id   TEXT NOT NULL REFERENCES tenants (id),
  identity_id INTEGER NOT NULL REFERENCES identities (id),
  folder_id   TEXT NOT NULL,
  task_id     TEXT REFERENCES grp_inbox_tasks (id),
  status      TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','removed','dismissed')),
  mode        TEXT NOT NULL CHECK (mode IN ('notify','auto_after','auto_now')),
  detail      TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(detail)),
  opened_at   TEXT NOT NULL,
  due_at      TEXT,
  resolved_at TEXT,
  resolved_by TEXT,
  reason      TEXT NOT NULL DEFAULT '',
  CHECK ((status = 'open') = (resolved_at IS NULL))
);
CREATE INDEX IF NOT EXISTS grp_deprov_items_status ON grp_deprov_items (tenant_id, status, opened_at);
CREATE UNIQUE INDEX IF NOT EXISTS grp_deprov_one_open ON grp_deprov_items (tenant_id, identity_id, folder_id) WHERE status = 'open';

-- ---------------------------------------------------------------- reports

-- A saved, parameterized report of the fixed catalogue (no free SQL). A
-- scheduled run acts with the privileges created_by holds when it runs.
CREATE TABLE IF NOT EXISTS grp_reports (
  id          TEXT PRIMARY KEY,
  tenant_id   TEXT NOT NULL REFERENCES tenants (id),
  name        TEXT NOT NULL,
  kind        TEXT NOT NULL,
  params      TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(params)),
  format      TEXT NOT NULL DEFAULT 'csv' CHECK (format IN ('csv','json')),
  schedule    TEXT NOT NULL DEFAULT 'none' CHECK (schedule IN ('none','daily','weekly','monthly')),
  delivery    TEXT NOT NULL DEFAULT 'store' CHECK (delivery IN ('store','email')),
  next_run_at TEXT,
  last_run_at TEXT,
  created_by  TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL,
  CHECK ((schedule = 'none') = (next_run_at IS NULL))
);
CREATE INDEX IF NOT EXISTS grp_reports_due ON grp_reports (tenant_id, next_run_at) WHERE next_run_at IS NOT NULL;

-- The output of a run, kept so a scheduled report can be fetched. Only the
-- user who owns the report (or a tenant admin) may read it back.
CREATE TABLE IF NOT EXISTS grp_report_runs (
  id        TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  report_id TEXT NOT NULL REFERENCES grp_reports (id),
  ran_at    TEXT NOT NULL,
  ran_by    TEXT NOT NULL,
  trigger_type TEXT NOT NULL CHECK (trigger_type IN ('manual','schedule')),
  status    TEXT NOT NULL CHECK (status IN ('ok','failed')),
  format    TEXT NOT NULL CHECK (format IN ('csv','json')),
  row_count INTEGER NOT NULL DEFAULT 0,
  truncated INTEGER NOT NULL DEFAULT 0 CHECK (truncated IN (0,1)),
  sha256    TEXT NOT NULL DEFAULT '',
  content   TEXT NOT NULL DEFAULT '',
  error     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS grp_report_runs_report ON grp_report_runs (tenant_id, report_id, ran_at);

-- ---------------------------------------------------------------- cross-tenant guards

CREATE TRIGGER IF NOT EXISTS tg_grp_inbox_tasks_xtenant_ins BEFORE INSERT ON grp_inbox_tasks
WHEN (NEW.object_type = 'folder' AND EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.object_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.object_type = 'group' AND EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.object_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.subject_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.subject_identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.assignee_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.assignee_identity_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_inbox_tasks'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_inbox_tasks_xtenant_upd BEFORE UPDATE OF tenant_id, object_type, object_id, subject_identity_id, assignee_identity_id ON grp_inbox_tasks
WHEN (NEW.object_type = 'folder' AND EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.object_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.object_type = 'group' AND EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.object_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.subject_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.subject_identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.assignee_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.assignee_identity_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_inbox_tasks'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_attest_settings_xtenant_ins BEFORE INSERT ON grp_attest_settings
WHEN (NEW.owner_type = 'folder' AND EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.owner_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.owner_type = 'group' AND EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.owner_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.reviewer_group_id IS NOT NULL AND EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.reviewer_group_id AND p.tenant_id <> NEW.tenant_id))
	OR EXISTS (SELECT 1 FROM platform_users u WHERE u.id = NEW.updated_by AND u.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_attest_settings'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_attest_settings_xtenant_upd BEFORE UPDATE OF tenant_id, owner_type, owner_id, reviewer_group_id, updated_by ON grp_attest_settings
WHEN (NEW.owner_type = 'folder' AND EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.owner_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.owner_type = 'group' AND EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.owner_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.reviewer_group_id IS NOT NULL AND EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.reviewer_group_id AND p.tenant_id <> NEW.tenant_id))
	OR EXISTS (SELECT 1 FROM platform_users u WHERE u.id = NEW.updated_by AND u.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_attest_settings'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_attest_campaigns_xtenant_ins BEFORE INSERT ON grp_attest_campaigns
WHEN EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.review_campaign_id IS NOT NULL AND EXISTS (SELECT 1 FROM review_campaigns p WHERE p.id = NEW.review_campaign_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.reviewer_group_id IS NOT NULL AND EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.reviewer_group_id AND p.tenant_id <> NEW.tenant_id))
	OR EXISTS (SELECT 1 FROM platform_users u WHERE u.id IN (NEW.acts_as, COALESCE(NEW.started_by, NEW.acts_as)) AND u.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_attest_campaigns'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_attest_campaigns_xtenant_upd BEFORE UPDATE OF tenant_id, group_id, review_campaign_id, reviewer_group_id, acts_as, started_by ON grp_attest_campaigns
WHEN EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.review_campaign_id IS NOT NULL AND EXISTS (SELECT 1 FROM review_campaigns p WHERE p.id = NEW.review_campaign_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.reviewer_group_id IS NOT NULL AND EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.reviewer_group_id AND p.tenant_id <> NEW.tenant_id))
	OR EXISTS (SELECT 1 FROM platform_users u WHERE u.id IN (NEW.acts_as, COALESCE(NEW.started_by, NEW.acts_as)) AND u.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_attest_campaigns'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_attest_items_xtenant_ins BEFORE INSERT ON grp_attest_items
WHEN EXISTS (SELECT 1 FROM grp_attest_campaigns p WHERE p.id = NEW.campaign_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.review_item_id IS NOT NULL AND EXISTS (SELECT 1 FROM review_items p WHERE p.id = NEW.review_item_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_attest_items'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_attest_items_xtenant_upd BEFORE UPDATE OF tenant_id, campaign_id, group_id, identity_id, review_item_id ON grp_attest_items
WHEN EXISTS (SELECT 1 FROM grp_attest_campaigns p WHERE p.id = NEW.campaign_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.review_item_id IS NOT NULL AND EXISTS (SELECT 1 FROM review_items p WHERE p.id = NEW.review_item_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_attest_items'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_deprov_folders_xtenant_ins BEFORE INSERT ON grp_deprov_folders
WHEN EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.folder_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM platform_users u WHERE u.id = NEW.updated_by AND u.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_deprov_folders'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_deprov_folders_xtenant_upd BEFORE UPDATE OF tenant_id, folder_id, updated_by ON grp_deprov_folders
WHEN EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.folder_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM platform_users u WHERE u.id = NEW.updated_by AND u.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_deprov_folders'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_deprovisioned_xtenant_ins BEFORE INSERT ON grp_deprovisioned
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_deprovisioned'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_deprovisioned_xtenant_upd BEFORE UPDATE OF tenant_id, identity_id ON grp_deprovisioned
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_deprovisioned'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_report_runs_xtenant_upd BEFORE UPDATE OF tenant_id, report_id, ran_by ON grp_report_runs
WHEN EXISTS (SELECT 1 FROM grp_reports p WHERE p.id = NEW.report_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM platform_users u WHERE u.id = NEW.ran_by AND u.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_report_runs'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_deprov_items_xtenant_ins BEFORE INSERT ON grp_deprov_items
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.folder_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.task_id IS NOT NULL AND EXISTS (SELECT 1 FROM grp_inbox_tasks p WHERE p.id = NEW.task_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_deprov_items'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_deprov_items_xtenant_upd BEFORE UPDATE OF tenant_id, identity_id, folder_id, task_id ON grp_deprov_items
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.folder_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.task_id IS NOT NULL AND EXISTS (SELECT 1 FROM grp_inbox_tasks p WHERE p.id = NEW.task_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_deprov_items'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_reports_xtenant_ins BEFORE INSERT ON grp_reports
WHEN EXISTS (SELECT 1 FROM platform_users u WHERE u.id = NEW.created_by AND u.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_reports'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_reports_xtenant_upd BEFORE UPDATE OF tenant_id, created_by ON grp_reports
WHEN EXISTS (SELECT 1 FROM platform_users u WHERE u.id = NEW.created_by AND u.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_reports'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_report_runs_xtenant_ins BEFORE INSERT ON grp_report_runs
WHEN EXISTS (SELECT 1 FROM grp_reports p WHERE p.id = NEW.report_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM platform_users u WHERE u.id = NEW.ran_by AND u.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_report_runs'); END;
