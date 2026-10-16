-- Group rules and membership constraints (issue #56, GR-13; design
-- docs/design/groups-grouper-parity.md §10.3). The design puts this in
-- 0107_group_gov.sql; 0280..0287 are taken here, so it is 0288.
--
-- A rule is owned by a folder or a group and has a closed vocabulary (K6): a
-- trigger (column trigger_type, as TRIGGER is an SQL keyword: an event type of the groups outbox), conditions (a JSON list of
-- typed objects), one action and its params. No rule holds code. A rule acts
-- with the authority of the platform user who last saved it (updated_by): the
-- privilege check is made when it is saved and again whenever it fires.
--
-- owner_id names a folder or a group by owner_type, with no foreign key (a
-- group is soft-deleted and a folder's rules are deleted with it), so the guard
-- triggers check the tenant. secret_enc is the webhook signing secret, sealed
-- under the KEK (AAD: tenant, grp_rules, secret_enc, rule id).

CREATE TABLE IF NOT EXISTS grp_rules (
  id           TEXT PRIMARY KEY,
  tenant_id    TEXT NOT NULL REFERENCES tenants (id),
  owner_type   TEXT NOT NULL CHECK (owner_type IN ('folder','group')),
  owner_id     TEXT NOT NULL,
  scope        TEXT NOT NULL DEFAULT 'self' CHECK (scope IN ('self','one','sub')),
  name         TEXT NOT NULL DEFAULT '',
  trigger_type TEXT NOT NULL,
  conditions   TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(conditions)),
  action       TEXT NOT NULL,
  params       TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(params)),
  enabled      INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
  secret_enc   BLOB,
  created_by   TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  updated_by   TEXT NOT NULL,
  updated_at   TEXT NOT NULL,
  -- the rule reacts only to events after this seq of the group event outbox: the
  -- last one when it was saved, so a new or changed rule never acts on history
  active_seq   INTEGER NOT NULL DEFAULT 0,
  CHECK ((owner_type = 'group') = (scope = 'self'))
);
CREATE INDEX IF NOT EXISTS grp_rules_owner ON grp_rules (tenant_id, owner_type, owner_id);
CREATE INDEX IF NOT EXISTS grp_rules_trigger ON grp_rules (tenant_id, trigger_type) WHERE enabled = 1;
CREATE INDEX IF NOT EXISTS grp_rules_action ON grp_rules (tenant_id, action) WHERE enabled = 1;

-- Groups rule settings, one row per tenant (Admin > Groups settings, §10.3):
-- rule actions that send email are off until a tenant admin turns them on
-- (Grouper GRP-7381 made this "default closed").
CREATE TABLE IF NOT EXISTS grp_rule_settings (
  tenant_id     TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  email_enabled INTEGER NOT NULL DEFAULT 0 CHECK (email_enabled IN (0,1)),
  updated_at    TEXT NOT NULL,
  updated_by    TEXT
);

-- ---------------------------------------------------------------- cross-tenant guards

CREATE TRIGGER IF NOT EXISTS tg_grp_rules_xtenant_ins BEFORE INSERT ON grp_rules
WHEN (NEW.owner_type = 'folder' AND EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.owner_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.owner_type = 'group' AND EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.owner_id AND p.tenant_id <> NEW.tenant_id))
	OR EXISTS (SELECT 1 FROM platform_users u WHERE u.id IN (NEW.created_by, NEW.updated_by) AND u.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_rules'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_rules_xtenant_upd BEFORE UPDATE OF tenant_id, owner_type, owner_id, created_by, updated_by ON grp_rules
WHEN (NEW.owner_type = 'folder' AND EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.owner_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.owner_type = 'group' AND EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.owner_id AND p.tenant_id <> NEW.tenant_id))
	OR EXISTS (SELECT 1 FROM platform_users u WHERE u.id IN (NEW.created_by, NEW.updated_by) AND u.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_rules'); END;
