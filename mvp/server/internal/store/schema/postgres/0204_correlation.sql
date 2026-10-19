-- Postgres dialect of schema/0204_correlation.sql (Phase 0 PR14). See 0001_tenancy.sql.

-- +goose Up

CREATE TABLE account_links (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  account_id BIGINT NOT NULL,
  decision TEXT NOT NULL CHECK (decision IN ('link','not_person')),
  identity_id BIGINT,
  previous_identity_id BIGINT,
  reason TEXT NOT NULL,
  decided_by TEXT NOT NULL,
  decided_at TEXT NOT NULL,
  CHECK ((decision = 'link') = (identity_id IS NOT NULL)),
  PRIMARY KEY (tenant_id, account_id),
  FOREIGN KEY (tenant_id, account_id) REFERENCES accounts (tenant_id, id),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, previous_identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, decided_by) REFERENCES platform_users (tenant_id, id)
);
CREATE INDEX ix_account_links_tenant_identity ON account_links (tenant_id, identity_id);

CREATE TABLE identity_merges (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  survivor_id BIGINT NOT NULL,
  merged_id BIGINT NOT NULL,
  merged_status TEXT NOT NULL,
  moves TEXT NOT NULL,
  reason TEXT NOT NULL,
  merged_by TEXT NOT NULL,
  merged_at TEXT NOT NULL,
  unmerged_by TEXT,
  unmerged_at TEXT,
  unmerge_reason TEXT,
  CHECK (survivor_id <> merged_id),
  FOREIGN KEY (tenant_id, survivor_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, merged_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, merged_by) REFERENCES platform_users (tenant_id, id),
  FOREIGN KEY (tenant_id, unmerged_by) REFERENCES platform_users (tenant_id, id)
);
CREATE INDEX ix_identity_merges_tenant ON identity_merges (tenant_id, merged_at);
-- one open merge per merged identity
CREATE UNIQUE INDEX ux_identity_merges_open ON identity_merges (tenant_id, merged_id) WHERE unmerged_at IS NULL;

-- A merge record is history: only the unmerge columns may change, once.
CREATE TRIGGER tg_identity_merges_immutable BEFORE UPDATE ON identity_merges
	FOR EACH ROW WHEN (OLD.unmerged_at IS NOT NULL OR NEW.id <> OLD.id OR NEW.survivor_id <> OLD.survivor_id
		OR NEW.merged_id <> OLD.merged_id OR NEW.moves <> OLD.moves OR NEW.merged_status <> OLD.merged_status
		OR NEW.reason <> OLD.reason OR NEW.merged_by <> OLD.merged_by OR NEW.merged_at <> OLD.merged_at)
	EXECUTE FUNCTION tessera_abort('identity_merges is append-only');

CREATE TRIGGER tg_identity_merges_no_delete BEFORE DELETE ON identity_merges
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('identity_merges is append-only');
