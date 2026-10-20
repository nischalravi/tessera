-- Postgres dialect of schema/0369_guest_access.sql (kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE guest_bundle_items (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  sponsorship_id TEXT NOT NULL,
  guest_identity_id BIGINT NOT NULL,
  group_id BIGINT NOT NULL,
  system TEXT NOT NULL CHECK (system <> ''),
  status TEXT NOT NULL CHECK (status IN ('pending','granted','removing','removed')),
  account_op_id TEXT,
  grant_op_id TEXT,
  remove_op_id TEXT,
  edge_id BIGINT,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  granted_at TEXT,
  removed_at TEXT,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, sponsorship_id, group_id),
  CHECK ((status = 'removed') = (removed_at IS NOT NULL)),
  FOREIGN KEY (tenant_id, sponsorship_id) REFERENCES sponsorships (tenant_id, id),
  FOREIGN KEY (tenant_id, guest_identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, group_id) REFERENCES groups (tenant_id, id),
  FOREIGN KEY (tenant_id, account_op_id) REFERENCES provisioning_ops (tenant_id, id),
  FOREIGN KEY (tenant_id, grant_op_id) REFERENCES provisioning_ops (tenant_id, id),
  FOREIGN KEY (tenant_id, remove_op_id) REFERENCES provisioning_ops (tenant_id, id)
);
CREATE INDEX ix_guest_bundle_items_guest ON guest_bundle_items (tenant_id, guest_identity_id, status);
CREATE INDEX ix_guest_bundle_items_edge ON guest_bundle_items (tenant_id, edge_id);

CREATE TABLE identity_assurance (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id BIGINT NOT NULL,
  ial BIGINT NOT NULL CHECK (ial IN (0,1,2)),
  aal BIGINT NOT NULL CHECK (aal IN (0,1,2,3)),
  source TEXT NOT NULL CHECK (source <> ''),
  recorded_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, identity_id),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id)
);

CREATE TABLE catalog_item_populations (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  catalog_item_id TEXT NOT NULL,
  population TEXT NOT NULL CHECK (population IN ('visitor','contractor','volunteer','partner')),
  PRIMARY KEY (tenant_id, catalog_item_id, population),
  FOREIGN KEY (tenant_id, catalog_item_id) REFERENCES catalog_items (tenant_id, id)
);

-- A bundle item's sponsorship, person and group never change; a removed row is final.
CREATE TRIGGER guest_bundle_items_immutable BEFORE UPDATE ON guest_bundle_items
	FOR EACH ROW WHEN (OLD.status = 'removed' OR NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id
		OR NEW.sponsorship_id <> OLD.sponsorship_id OR NEW.guest_identity_id <> OLD.guest_identity_id
		OR NEW.group_id <> OLD.group_id OR NEW.created_at <> OLD.created_at)
	EXECUTE FUNCTION tessera_abort('guest_bundle_items: removed rows and identity columns are immutable');

CREATE TRIGGER guest_bundle_items_no_delete BEFORE DELETE ON guest_bundle_items
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('guest_bundle_items are append-only');
