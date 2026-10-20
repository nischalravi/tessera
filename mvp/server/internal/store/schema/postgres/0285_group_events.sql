-- Postgres dialect of schema/0285_group_events.sql (kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres). Events and PIT rows outlive what they name, so they carry
-- no foreign keys; the cross-tenant guards are plpgsql triggers (tessera_guard_soft_ref, 0001_tenancy.sql)
-- like the SQLite triggers. json_valid CHECKs are dropped: the columns are TEXT and the store
-- only writes encoded JSON.

-- +goose Up

-- the per-tenant event counter: the UPDATE that bumps it takes the write lock
-- (the row lock in Postgres), so seq stays gap-free and ordered
CREATE TABLE grp_event_heads (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  last_seq BIGINT NOT NULL DEFAULT 0,
  -- events with seq <= pruned_seq were removed by the retention job
  pruned_seq BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE grp_events (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  seq BIGINT NOT NULL CHECK (seq > 0),
  type TEXT NOT NULL CHECK (length(type) BETWEEN 3 AND 80),
  object_type TEXT NOT NULL CHECK (object_type IN ('folder','group','privilege','attribute','loader','provisioning','attestation','rule')),
  object_id TEXT NOT NULL,
  identity_id BIGINT,
  member_group_id TEXT,
  list_id TEXT,
  data TEXT NOT NULL DEFAULT '{}',
  cause_type TEXT NOT NULL CHECK (cause_type IN ('api','loader','rule','engine','timewheel','policy_repo','import','retention')),
  cause_ref TEXT,
  -- audit_events.seq of the ledger event that caused it, when known
  audit_seq BIGINT,
  occurred_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, seq)
);
CREATE INDEX grp_events_object ON grp_events (tenant_id, object_type, object_id, seq);
CREATE INDEX grp_events_time ON grp_events (tenant_id, occurred_at);


CREATE TABLE grp_event_cursors (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  -- pit | graph | provisioner:<id> | webhook:<id> | ...
  consumer TEXT NOT NULL CHECK (length(consumer) BETWEEN 1 AND 120),
  last_seq BIGINT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, consumer)
);

-- names, folders and definitions over time; snapshot is JSON
CREATE TABLE grp_pit_objects (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  object_type TEXT NOT NULL CHECK (object_type IN ('folder','group')),
  object_id TEXT NOT NULL,
  snapshot TEXT NOT NULL,
  start_at TEXT NOT NULL,
  end_at TEXT,
  start_seq BIGINT NOT NULL,
  end_seq BIGINT,
  PRIMARY KEY (tenant_id, object_type, object_id, start_seq)
);
CREATE INDEX grp_pit_objects_time ON grp_pit_objects (tenant_id, object_type, object_id, start_at);

-- a direct membership row over time, with its own enabled and disabled dates
-- (a change of dates closes the interval and opens another)
CREATE TABLE grp_pit_direct (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  group_id TEXT NOT NULL,
  list_id TEXT NOT NULL,
  member_type TEXT NOT NULL CHECK (member_type IN ('identity','group')),
  -- the identity id or the group id, as text: part of the key
  member_key TEXT NOT NULL,
  member_identity_id BIGINT,
  member_group_id TEXT,
  source TEXT NOT NULL,
  enabled_from TEXT,
  disabled_at TEXT,
  start_at TEXT NOT NULL,
  end_at TEXT,
  start_seq BIGINT NOT NULL,
  end_seq BIGINT,
  PRIMARY KEY (tenant_id, group_id, list_id, member_type, member_key, start_seq),
  CHECK ((member_type = 'identity') = (member_identity_id IS NOT NULL)),
  CHECK ((member_type = 'group') = (member_group_id IS NOT NULL))
);
CREATE INDEX grp_pit_direct_g ON grp_pit_direct (tenant_id, group_id, start_at);

CREATE TABLE grp_pit_effective (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  group_id TEXT NOT NULL,
  list_id TEXT NOT NULL,
  identity_id BIGINT NOT NULL,
  start_at TEXT NOT NULL,
  end_at TEXT,
  start_seq BIGINT NOT NULL,
  end_seq BIGINT,
  PRIMARY KEY (tenant_id, group_id, list_id, identity_id, start_seq)
);
CREATE INDEX grp_pit_eff_identity ON grp_pit_effective (tenant_id, identity_id, start_at);

-- privilege grants over time (the privilege model arrives with GR-4)
CREATE TABLE grp_pit_privileges (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  privilege_id TEXT NOT NULL,
  snapshot TEXT NOT NULL,
  start_at TEXT NOT NULL,
  end_at TEXT,
  start_seq BIGINT NOT NULL,
  end_seq BIGINT,
  PRIMARY KEY (tenant_id, privilege_id, start_seq)
);

-- one Merkle root per UTC day over that day's events (K9)
CREATE TABLE grp_pit_digests (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  day TEXT NOT NULL CHECK (day ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'),
  first_seq BIGINT NOT NULL,
  last_seq BIGINT NOT NULL,
  event_count BIGINT NOT NULL,
  merkle_root TEXT NOT NULL,
  -- audit_events.seq of the groups.pit.digest event that anchors the root
  audit_seq BIGINT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, day)
);

CREATE TRIGGER grp_events_no_update BEFORE UPDATE ON grp_events
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('grp_events is append-only');
CREATE TRIGGER grp_pit_digests_no_update BEFORE UPDATE ON grp_pit_digests
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('grp_pit_digests is append-only');

-- ---------------------------------------------------------------- cross-tenant guards

-- object_id names a folder or a group by object_type (no foreign key); other object types
-- are not checked, like SQLite. SECURITY DEFINER for the same reason as tessera_guard_soft_ref.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION tessera_guard_grp_object() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
	crosses boolean := false;
BEGIN
	IF NEW.object_type = 'folder' THEN
		SELECT EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.object_id AND p.tenant_id <> NEW.tenant_id) INTO crosses;
	ELSIF NEW.object_type = 'group' THEN
		SELECT EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.object_id AND p.tenant_id <> NEW.tenant_id) INTO crosses;
	END IF;
	IF crosses THEN
		RAISE EXCEPTION 'cross-tenant reference: %', TG_TABLE_NAME USING ERRCODE = 'integrity_constraint_violation';
	END IF;
	RETURN NEW;
END
$fn$;
-- +goose StatementEnd

CREATE TRIGGER tg_grp_events_object_xtenant BEFORE INSERT ON grp_events
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_grp_object();
CREATE TRIGGER tg_grp_events_identity_xtenant BEFORE INSERT ON grp_events
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('identities', 'identity_id', 'bigint');
CREATE TRIGGER tg_grp_events_member_group_xtenant BEFORE INSERT ON grp_events
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('grp_groups', 'member_group_id', 'text');
CREATE TRIGGER tg_grp_events_list_xtenant BEFORE INSERT ON grp_events
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('grp_lists', 'list_id', 'text');

CREATE TRIGGER tg_grp_pit_objects_xtenant BEFORE INSERT OR UPDATE OF tenant_id, object_type, object_id ON grp_pit_objects
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_grp_object();

CREATE TRIGGER tg_grp_pit_direct_group_xtenant BEFORE INSERT OR UPDATE OF tenant_id, group_id ON grp_pit_direct
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('grp_groups', 'group_id', 'text');
CREATE TRIGGER tg_grp_pit_direct_list_xtenant BEFORE INSERT OR UPDATE OF tenant_id, list_id ON grp_pit_direct
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('grp_lists', 'list_id', 'text');
CREATE TRIGGER tg_grp_pit_direct_identity_xtenant BEFORE INSERT OR UPDATE OF tenant_id, member_identity_id ON grp_pit_direct
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('identities', 'member_identity_id', 'bigint');
CREATE TRIGGER tg_grp_pit_direct_member_group_xtenant BEFORE INSERT OR UPDATE OF tenant_id, member_group_id ON grp_pit_direct
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('grp_groups', 'member_group_id', 'text');

CREATE TRIGGER tg_grp_pit_effective_group_xtenant BEFORE INSERT OR UPDATE OF tenant_id, group_id ON grp_pit_effective
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('grp_groups', 'group_id', 'text');
CREATE TRIGGER tg_grp_pit_effective_list_xtenant BEFORE INSERT OR UPDATE OF tenant_id, list_id ON grp_pit_effective
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('grp_lists', 'list_id', 'text');
CREATE TRIGGER tg_grp_pit_effective_identity_xtenant BEFORE INSERT OR UPDATE OF tenant_id, identity_id ON grp_pit_effective
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('identities', 'identity_id', 'bigint');
