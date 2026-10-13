-- Guest access: access bundles and assurance (guest accounts design §8.2,
-- §9.3, issue #75 / GU-12).
--
-- guest_bundle_items is one catalog item of one sponsorship's access bundle
-- and where it stands: pending (waiting for the guest to claim, or for the
-- provisioning operation to be verified), granted (the membership edge
-- exists, source 'guest_sponsorship', expiring with the sponsorship),
-- removing (the sponsorship ended and the removal is not verified yet) or
-- removed. The row is the edge's source_ref: the sponsorship that gave the
-- access, so a reader can see which sponsorship gave which access. The
-- operation ids link the provisioning operations (internal/provision) back to
-- the sponsorship. Rows are kept (history); a removed row is final.
--
-- identity_assurance is the identity assurance level (IAL) a person reached,
-- recorded when the claim completes (and by the identity-verification step
-- when GU-7 lands). It only goes up. Access requests of a guest for a
-- privileged or high-risk item need IAL 2.
--
-- catalog_item_populations lists the guest populations a catalog item is open
-- to. A guest may request an item only if it names their population; an item
-- that names none is for staff.
--
-- Tenant-owned like 0001_tenancy.sql: guard triggers at the end refuse a
-- reference to another tenant's row. Created with IF NOT EXISTS; a reseed
-- drops and recreates (store.tables).

CREATE TABLE IF NOT EXISTS guest_bundle_items (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  sponsorship_id TEXT NOT NULL REFERENCES sponsorships (id),
  guest_identity_id INTEGER NOT NULL REFERENCES identities (id),
  group_id INTEGER NOT NULL REFERENCES groups (id),
  system TEXT NOT NULL CHECK (system <> ''),
  status TEXT NOT NULL CHECK (status IN ('pending','granted','removing','removed')),
  account_op_id TEXT REFERENCES provisioning_ops (id),
  grant_op_id TEXT REFERENCES provisioning_ops (id),
  remove_op_id TEXT REFERENCES provisioning_ops (id),
  edge_id INTEGER,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  granted_at TEXT,
  removed_at TEXT,
  UNIQUE (tenant_id, sponsorship_id, group_id),
  CHECK ((status = 'removed') = (removed_at IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS ix_guest_bundle_items_guest ON guest_bundle_items (tenant_id, guest_identity_id, status);
CREATE INDEX IF NOT EXISTS ix_guest_bundle_items_edge ON guest_bundle_items (tenant_id, edge_id);

CREATE TABLE IF NOT EXISTS identity_assurance (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id INTEGER NOT NULL REFERENCES identities (id),
  ial INTEGER NOT NULL CHECK (ial IN (0,1,2)),
  aal INTEGER NOT NULL CHECK (aal IN (0,1,2,3)),
  source TEXT NOT NULL CHECK (source <> ''),
  recorded_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, identity_id)
);

CREATE TABLE IF NOT EXISTS catalog_item_populations (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  catalog_item_id TEXT NOT NULL REFERENCES catalog_items (id),
  population TEXT NOT NULL CHECK (population IN ('visitor','contractor','volunteer','partner')),
  PRIMARY KEY (tenant_id, catalog_item_id, population)
);

-- A bundle item's sponsorship, person and group never change; a removed row is final.
CREATE TRIGGER IF NOT EXISTS tg_guest_bundle_items_immutable BEFORE UPDATE ON guest_bundle_items
WHEN OLD.status = 'removed' OR NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.sponsorship_id <> OLD.sponsorship_id
	OR NEW.guest_identity_id <> OLD.guest_identity_id OR NEW.group_id <> OLD.group_id OR NEW.created_at <> OLD.created_at
BEGIN SELECT RAISE(ABORT, 'guest_bundle_items: removed rows and identity columns are immutable'); END;

CREATE TRIGGER IF NOT EXISTS tg_guest_bundle_items_no_delete BEFORE DELETE ON guest_bundle_items
BEGIN SELECT RAISE(ABORT, 'guest_bundle_items are append-only'); END;

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_guest_bundle_items_xtenant_ins BEFORE INSERT ON guest_bundle_items
WHEN EXISTS (SELECT 1 FROM sponsorships p WHERE p.id = NEW.sponsorship_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.guest_identity_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM provisioning_ops p WHERE p.id IN (NEW.account_op_id, NEW.grant_op_id, NEW.remove_op_id) AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: guest_bundle_items'); END;

CREATE TRIGGER IF NOT EXISTS tg_guest_bundle_items_xtenant_upd BEFORE UPDATE OF tenant_id, sponsorship_id, guest_identity_id, group_id, account_op_id, grant_op_id, remove_op_id ON guest_bundle_items
WHEN EXISTS (SELECT 1 FROM sponsorships p WHERE p.id = NEW.sponsorship_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.guest_identity_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM provisioning_ops p WHERE p.id IN (NEW.account_op_id, NEW.grant_op_id, NEW.remove_op_id) AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: guest_bundle_items'); END;

CREATE TRIGGER IF NOT EXISTS tg_identity_assurance_xtenant_ins BEFORE INSERT ON identity_assurance
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: identity_assurance'); END;

CREATE TRIGGER IF NOT EXISTS tg_identity_assurance_xtenant_upd BEFORE UPDATE OF tenant_id, identity_id ON identity_assurance
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: identity_assurance'); END;

CREATE TRIGGER IF NOT EXISTS tg_catalog_item_populations_xtenant_ins BEFORE INSERT ON catalog_item_populations
WHEN EXISTS (SELECT 1 FROM catalog_items p WHERE p.id = NEW.catalog_item_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: catalog_item_populations'); END;

CREATE TRIGGER IF NOT EXISTS tg_catalog_item_populations_xtenant_upd BEFORE UPDATE OF tenant_id, catalog_item_id ON catalog_item_populations
WHEN EXISTS (SELECT 1 FROM catalog_items p WHERE p.id = NEW.catalog_item_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: catalog_item_populations'); END;
