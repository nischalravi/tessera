-- Membership engine state (issue #45, GR-2; design
-- docs/design/groups-grouper-parity.md §6). 0280 created the engine tables
-- empty; this adds the per-tenant engine state and the indexes the time wheel
-- needs on group-level dates.
--
-- grp_engine_state holds, per tenant: the next engine operation id (op ids are
-- never reused after a queue row is deleted, so "no row" means "done"), the
-- time the wheel last ran (the wheel applies every enabled_from and
-- disabled_at in (wheel_at, now]) and the time of the last full verification.

CREATE TABLE IF NOT EXISTS grp_engine_state (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  next_seq INTEGER NOT NULL DEFAULT 1,
  wheel_at TEXT,
  verified_at TEXT
);

-- 0280's unique indexes on direct memberships are partial (by member_type), so
-- a query by group alone (its lists, its row count, its page) needs this one
CREATE INDEX IF NOT EXISTS grp_dm_by_group ON grp_direct_memberships (tenant_id, group_id, list_id, member_type);

CREATE INDEX IF NOT EXISTS grp_groups_enable ON grp_groups (tenant_id, enabled_from) WHERE enabled_from IS NOT NULL;
CREATE INDEX IF NOT EXISTS grp_groups_disable ON grp_groups (tenant_id, disabled_at) WHERE disabled_at IS NOT NULL;
