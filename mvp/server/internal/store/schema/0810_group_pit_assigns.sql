-- Permission and limit history (issue #62, GR-19; design docs/design/groups-grouper-parity.md
-- §10.10). Attribute assignments (0287) change through attribute.assigned,
-- attribute.value_changed and attribute.removed events; this table is their
-- point-in-time history, so "what could this identity do on that day" can be
-- answered for permission (perm) and limit assignments.
--
-- Like grp_pit_privileges it carries no foreign keys: history outlives the
-- assignment, definition and owner it names. It is derived data, rebuilt from
-- grp_events by internal/groups/pit. snapshot is the event's assignment JSON
-- (def, name, action, owner, disallowed, dates, value keys).

CREATE TABLE IF NOT EXISTS grp_pit_assigns (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  assign_id TEXT NOT NULL,
  def_id TEXT NOT NULL,
  owner_type TEXT NOT NULL,
  owner_id TEXT NOT NULL,
  snapshot TEXT NOT NULL CHECK (json_valid(snapshot)),
  start_at TEXT NOT NULL,
  end_at TEXT,
  start_seq INTEGER NOT NULL,
  end_seq INTEGER,
  PRIMARY KEY (tenant_id, assign_id, start_seq)
);
CREATE INDEX IF NOT EXISTS grp_pit_assigns_time ON grp_pit_assigns (tenant_id, start_at);
CREATE INDEX IF NOT EXISTS grp_pit_assigns_owner ON grp_pit_assigns (tenant_id, owner_type, owner_id);
