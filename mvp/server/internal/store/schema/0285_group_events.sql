-- Group change events and point-in-time history (issue #46, GR-3; design
-- docs/design/groups-grouper-parity.md §5.3 "0103_group_events", §10.1, §10.2).
-- The design numbers this file 0103; the repo's native-groups files start at
-- 0280, so it is 0285 here.
--
-- grp_events is the outbox: every committed change to a folder, group,
-- membership or privilege writes one row in the same transaction, with a
-- per-tenant gap-free seq taken from grp_event_heads. Rows are append-only
-- (a trigger refuses UPDATE; only the retention job deletes). Consumers keep
-- their position in grp_event_cursors. The grp_pit_* tables are DERIVED from
-- the events (internal/groups/pit rebuilds them), as half-open intervals
-- [start_at, end_at) with the event seq as start_seq / end_seq. grp_pit_digests
-- holds the daily Merkle root over the previous day's events, which is also
-- appended to the audit ledger.
--
-- Events and PIT rows outlive what they name (a deleted folder, a removed
-- identity), so they carry no foreign keys to those rows; the guard triggers at
-- the end still refuse a reference to another tenant's row.

-- the per-tenant event counter: the UPDATE that bumps it takes the write lock
-- (the row lock in Postgres), so seq stays gap-free and ordered
CREATE TABLE IF NOT EXISTS grp_event_heads (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  last_seq INTEGER NOT NULL DEFAULT 0,
  -- events with seq <= pruned_seq were removed by the retention job
  pruned_seq INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS grp_events (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  seq INTEGER NOT NULL CHECK (seq > 0),
  type TEXT NOT NULL CHECK (length(type) BETWEEN 3 AND 80),
  object_type TEXT NOT NULL CHECK (object_type IN ('folder','group','privilege','attribute','loader','provisioning','attestation','rule')),
  object_id TEXT NOT NULL,
  identity_id INTEGER,
  member_group_id TEXT,
  list_id TEXT,
  data TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(data)),
  cause_type TEXT NOT NULL CHECK (cause_type IN ('api','loader','rule','engine','timewheel','policy_repo','import','retention')),
  cause_ref TEXT,
  -- audit_events.seq of the ledger event that caused it, when known
  audit_seq INTEGER,
  occurred_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, seq)
);
CREATE INDEX IF NOT EXISTS grp_events_object ON grp_events (tenant_id, object_type, object_id, seq);
CREATE INDEX IF NOT EXISTS grp_events_time ON grp_events (tenant_id, occurred_at);

CREATE TRIGGER IF NOT EXISTS grp_events_no_update BEFORE UPDATE ON grp_events
BEGIN SELECT RAISE(ABORT, 'grp_events is append-only'); END;

CREATE TABLE IF NOT EXISTS grp_event_cursors (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  -- pit | graph | provisioner:<id> | webhook:<id> | ...
  consumer TEXT NOT NULL CHECK (length(consumer) BETWEEN 1 AND 120),
  last_seq INTEGER NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, consumer)
);

-- names, folders and definitions over time; snapshot is JSON
CREATE TABLE IF NOT EXISTS grp_pit_objects (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  object_type TEXT NOT NULL CHECK (object_type IN ('folder','group')),
  object_id TEXT NOT NULL,
  snapshot TEXT NOT NULL CHECK (json_valid(snapshot)),
  start_at TEXT NOT NULL,
  end_at TEXT,
  start_seq INTEGER NOT NULL,
  end_seq INTEGER,
  PRIMARY KEY (tenant_id, object_type, object_id, start_seq)
);
CREATE INDEX IF NOT EXISTS grp_pit_objects_time ON grp_pit_objects (tenant_id, object_type, object_id, start_at);

-- a direct membership row over time, with its own enabled and disabled dates
-- (a change of dates closes the interval and opens another)
CREATE TABLE IF NOT EXISTS grp_pit_direct (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  group_id TEXT NOT NULL,
  list_id TEXT NOT NULL,
  member_type TEXT NOT NULL CHECK (member_type IN ('identity','group')),
  -- the identity id or the group id, as text: part of the key
  member_key TEXT NOT NULL,
  member_identity_id INTEGER,
  member_group_id TEXT,
  source TEXT NOT NULL,
  enabled_from TEXT,
  disabled_at TEXT,
  start_at TEXT NOT NULL,
  end_at TEXT,
  start_seq INTEGER NOT NULL,
  end_seq INTEGER,
  PRIMARY KEY (tenant_id, group_id, list_id, member_type, member_key, start_seq),
  CHECK ((member_type = 'identity') = (member_identity_id IS NOT NULL)),
  CHECK ((member_type = 'group') = (member_group_id IS NOT NULL))
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS grp_pit_direct_g ON grp_pit_direct (tenant_id, group_id, start_at);

CREATE TABLE IF NOT EXISTS grp_pit_effective (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  group_id TEXT NOT NULL,
  list_id TEXT NOT NULL,
  identity_id INTEGER NOT NULL,
  start_at TEXT NOT NULL,
  end_at TEXT,
  start_seq INTEGER NOT NULL,
  end_seq INTEGER,
  PRIMARY KEY (tenant_id, group_id, list_id, identity_id, start_seq)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS grp_pit_eff_identity ON grp_pit_effective (tenant_id, identity_id, start_at);

-- privilege grants over time (the privilege model arrives with GR-4)
CREATE TABLE IF NOT EXISTS grp_pit_privileges (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  privilege_id TEXT NOT NULL,
  snapshot TEXT NOT NULL CHECK (json_valid(snapshot)),
  start_at TEXT NOT NULL,
  end_at TEXT,
  start_seq INTEGER NOT NULL,
  end_seq INTEGER,
  PRIMARY KEY (tenant_id, privilege_id, start_seq)
);

-- one Merkle root per UTC day over that day's events (K9)
CREATE TABLE IF NOT EXISTS grp_pit_digests (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  day TEXT NOT NULL CHECK (day GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
  first_seq INTEGER NOT NULL,
  last_seq INTEGER NOT NULL,
  event_count INTEGER NOT NULL,
  merkle_root TEXT NOT NULL,
  -- audit_events.seq of the groups.pit.digest event that anchors the root
  audit_seq INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, day)
);

CREATE TRIGGER IF NOT EXISTS grp_pit_digests_no_update BEFORE UPDATE ON grp_pit_digests
BEGIN SELECT RAISE(ABORT, 'grp_pit_digests is append-only'); END;

-- ---------------------------------------------------------------- cross-tenant guards

CREATE TRIGGER IF NOT EXISTS tg_grp_events_xtenant_ins BEFORE INSERT ON grp_events
WHEN (NEW.identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.member_group_id IS NOT NULL AND EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.member_group_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.list_id IS NOT NULL AND EXISTS (SELECT 1 FROM grp_lists p WHERE p.id = NEW.list_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.object_type = 'folder' AND EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.object_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.object_type = 'group' AND EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.object_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_events'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_pit_objects_xtenant_ins BEFORE INSERT ON grp_pit_objects
WHEN (NEW.object_type = 'folder' AND EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.object_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.object_type = 'group' AND EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.object_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_pit_objects'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_pit_objects_xtenant_upd BEFORE UPDATE OF tenant_id, object_type, object_id ON grp_pit_objects
WHEN (NEW.object_type = 'folder' AND EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.object_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.object_type = 'group' AND EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.object_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_pit_objects'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_pit_direct_xtenant_ins BEFORE INSERT ON grp_pit_direct
WHEN EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM grp_lists p WHERE p.id = NEW.list_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.member_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.member_identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.member_group_id IS NOT NULL AND EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.member_group_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_pit_direct'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_pit_direct_xtenant_upd BEFORE UPDATE OF tenant_id, group_id, list_id, member_identity_id, member_group_id ON grp_pit_direct
WHEN EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM grp_lists p WHERE p.id = NEW.list_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.member_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.member_identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.member_group_id IS NOT NULL AND EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.member_group_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_pit_direct'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_pit_effective_xtenant_ins BEFORE INSERT ON grp_pit_effective
WHEN EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM grp_lists p WHERE p.id = NEW.list_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_pit_effective'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_pit_effective_xtenant_upd BEFORE UPDATE OF tenant_id, group_id, list_id, identity_id ON grp_pit_effective
WHEN EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM grp_lists p WHERE p.id = NEW.list_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_pit_effective'); END;
