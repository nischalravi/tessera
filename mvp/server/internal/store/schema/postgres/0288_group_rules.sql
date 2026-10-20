-- Postgres dialect of schema/0288_group_rules.sql (kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres). owner_id names a folder or a group by owner_type with no
-- foreign key, so a plpgsql guard checks its tenant (and the tenant of created_by and updated_by,
-- platform users, which are text ids). secret_enc is BYTEA; the json_valid CHECKs are IS JSON (the columns are
-- TEXT and internal/groups/rules validates them).

-- +goose Up

CREATE TABLE grp_rules (
  id           TEXT PRIMARY KEY,
  tenant_id    TEXT NOT NULL REFERENCES tenants (id),
  owner_type   TEXT NOT NULL CHECK (owner_type IN ('folder','group')),
  owner_id     TEXT NOT NULL,
  scope        TEXT NOT NULL DEFAULT 'self' CHECK (scope IN ('self','one','sub')),
  name         TEXT NOT NULL DEFAULT '',
  trigger_type TEXT NOT NULL,
  conditions   TEXT NOT NULL DEFAULT '[]' CHECK (conditions IS JSON),
  action       TEXT NOT NULL,
  params       TEXT NOT NULL DEFAULT '{}' CHECK (params IS JSON),
  enabled      INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
  secret_enc   BYTEA,
  created_by   TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  updated_by   TEXT NOT NULL,
  updated_at   TEXT NOT NULL,
  active_seq   BIGINT NOT NULL DEFAULT 0,
  CHECK ((owner_type = 'group') = (scope = 'self'))
);
CREATE INDEX grp_rules_owner ON grp_rules (tenant_id, owner_type, owner_id);
CREATE INDEX grp_rules_trigger ON grp_rules (tenant_id, trigger_type) WHERE enabled = 1;
CREATE INDEX grp_rules_action ON grp_rules (tenant_id, action) WHERE enabled = 1;

CREATE TABLE grp_rule_settings (
  tenant_id     TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  email_enabled INTEGER NOT NULL DEFAULT 0 CHECK (email_enabled IN (0,1)),
  updated_at    TEXT NOT NULL,
  updated_by    TEXT
);

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION tessera_guard_grp_rule() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
	crosses boolean := false;
BEGIN
	IF NEW.owner_type = 'folder' THEN
		SELECT EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.owner_id AND p.tenant_id <> NEW.tenant_id) INTO crosses;
	ELSIF NEW.owner_type = 'group' THEN
		SELECT EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.owner_id AND p.tenant_id <> NEW.tenant_id) INTO crosses;
	END IF;
	IF NOT crosses THEN
		SELECT EXISTS (SELECT 1 FROM platform_users u WHERE u.id IN (NEW.created_by, NEW.updated_by) AND u.tenant_id <> NEW.tenant_id) INTO crosses;
	END IF;
	IF crosses THEN
		RAISE EXCEPTION 'cross-tenant reference: %', TG_TABLE_NAME USING ERRCODE = 'integrity_constraint_violation';
	END IF;
	RETURN NEW;
END
$fn$;
-- +goose StatementEnd

CREATE TRIGGER tg_grp_rules_xtenant BEFORE INSERT OR UPDATE OF tenant_id, owner_type, owner_id, created_by, updated_by ON grp_rules
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_grp_rule();
