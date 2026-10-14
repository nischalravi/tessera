-- Account correlation decisions, merge and unmerge (issue #160; the guest
-- design's §5.4 model applied to live identities and accounts).
--
-- account_links pins a reviewer's decision about one live account: it
-- belongs to identity_id (decision 'link') or to no person ('not_person').
-- Connector sync honours the pin (ingest), so a re-sync never undoes it;
-- releasing the pin hands the account back to the connector's mapping.
--
-- identity_merges records a merge: the merged identity gets status 'merged'
-- (its old status is kept in merged_status) and the rows listed in moves
-- (JSON: [{"table","id","column"}]) now point at the survivor. Unmerge moves
-- back the rows that still point at the survivor and restores the status;
-- rows changed since the merge stay and are reported. History (usage,
-- reviews, requests, HRIS events) is never moved.
--
-- Tenant-owned like 0001_tenancy.sql: guard triggers at the end refuse a
-- reference to another tenant's row.
CREATE TABLE IF NOT EXISTS account_links (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  account_id INTEGER NOT NULL REFERENCES accounts (id),
  decision TEXT NOT NULL CHECK (decision IN ('link','not_person')),
  identity_id INTEGER REFERENCES identities (id),
  previous_identity_id INTEGER REFERENCES identities (id),
  reason TEXT NOT NULL,
  decided_by TEXT NOT NULL REFERENCES platform_users (id),
  decided_at TEXT NOT NULL,
  CHECK ((decision = 'link') = (identity_id IS NOT NULL)),
  PRIMARY KEY (tenant_id, account_id)
);
CREATE INDEX IF NOT EXISTS ix_account_links_tenant_identity ON account_links (tenant_id, identity_id);

CREATE TABLE IF NOT EXISTS identity_merges (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  survivor_id INTEGER NOT NULL REFERENCES identities (id),
  merged_id INTEGER NOT NULL REFERENCES identities (id),
  merged_status TEXT NOT NULL,
  moves TEXT NOT NULL,
  reason TEXT NOT NULL,
  merged_by TEXT NOT NULL REFERENCES platform_users (id),
  merged_at TEXT NOT NULL,
  unmerged_by TEXT REFERENCES platform_users (id),
  unmerged_at TEXT,
  unmerge_reason TEXT,
  CHECK (survivor_id <> merged_id)
);
CREATE INDEX IF NOT EXISTS ix_identity_merges_tenant ON identity_merges (tenant_id, merged_at);
-- one open merge per merged identity
CREATE UNIQUE INDEX IF NOT EXISTS ux_identity_merges_open ON identity_merges (tenant_id, merged_id) WHERE unmerged_at IS NULL;

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_account_links_xtenant_ins BEFORE INSERT ON account_links
WHEN EXISTS (SELECT 1 FROM accounts p WHERE p.id = NEW.account_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.previous_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.previous_identity_id AND p.tenant_id <> NEW.tenant_id))
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.decided_by AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: account_links'); END;

CREATE TRIGGER IF NOT EXISTS tg_account_links_xtenant_upd BEFORE UPDATE OF tenant_id, account_id, identity_id, previous_identity_id, decided_by ON account_links
WHEN EXISTS (SELECT 1 FROM accounts p WHERE p.id = NEW.account_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.previous_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.previous_identity_id AND p.tenant_id <> NEW.tenant_id))
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.decided_by AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: account_links'); END;

CREATE TRIGGER IF NOT EXISTS tg_identity_merges_xtenant_ins BEFORE INSERT ON identity_merges
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.survivor_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.merged_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.merged_by AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.unmerged_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.unmerged_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: identity_merges'); END;

CREATE TRIGGER IF NOT EXISTS tg_identity_merges_xtenant_upd BEFORE UPDATE OF tenant_id, survivor_id, merged_id, merged_by, unmerged_by ON identity_merges
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.survivor_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.merged_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.merged_by AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.unmerged_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.unmerged_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: identity_merges'); END;

-- A merge record is history: only the unmerge columns may change, once.
CREATE TRIGGER IF NOT EXISTS tg_identity_merges_immutable BEFORE UPDATE ON identity_merges
WHEN OLD.unmerged_at IS NOT NULL OR NEW.id <> OLD.id OR NEW.survivor_id <> OLD.survivor_id
	OR NEW.merged_id <> OLD.merged_id OR NEW.moves <> OLD.moves OR NEW.merged_status <> OLD.merged_status
	OR NEW.reason <> OLD.reason OR NEW.merged_by <> OLD.merged_by OR NEW.merged_at <> OLD.merged_at
BEGIN SELECT RAISE(ABORT, 'identity_merges is append-only'); END;

CREATE TRIGGER IF NOT EXISTS tg_identity_merges_no_delete BEFORE DELETE ON identity_merges
BEGIN SELECT RAISE(ABORT, 'identity_merges is append-only'); END;
