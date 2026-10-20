-- Postgres dialect of schema/0374_intake.sql (kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

-- identity_conversions points at two affiliations by a composite key.
ALTER TABLE affiliations ADD UNIQUE (tenant_id, id);

CREATE TABLE org_sponsors (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  key TEXT NOT NULL CHECK (key <> ''),
  name TEXT NOT NULL,
  population TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, key)
);

-- One feed event received. event_key makes a replay a no-op: it names the
-- source system, the event and its phase (an HRIS hire is first announced,
-- later effective). status 'review' holds a record whose person could not be
-- decided without matching (GU-5); no identity or affiliation exists for it.
-- detail is a JSON object without personal data (counts, outcomes, ids).
CREATE TABLE intake_events (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  channel TEXT NOT NULL CHECK (channel IN ('sponsor_invite','bulk_invite','self_registration','sis','hris','vms',
    'partner_invite','partner_scim')),
  match_mode TEXT NOT NULL CHECK (match_mode IN ('authoritative','self_asserted','federated')),
  source_record_id TEXT,
  identity_id BIGINT,
  sponsor_org TEXT,
  submitted_by TEXT,
  event_key TEXT NOT NULL CHECK (event_key <> ''),
  event_type TEXT NOT NULL,
  effective_at TEXT,
  status TEXT NOT NULL CHECK (status IN ('received','matching','review','resolved','rejected')),
  detail TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  UNIQUE (tenant_id, event_key),
  FOREIGN KEY (tenant_id, source_record_id) REFERENCES identity_source_records (tenant_id, id),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, sponsor_org) REFERENCES org_sponsors (tenant_id, key),
  UNIQUE (tenant_id, id)
);
CREATE INDEX ix_intake_events_identity ON intake_events (tenant_id, identity_id);
CREATE INDEX ix_intake_events_status ON intake_events (tenant_id, status);

-- A conversion: from_affiliation_id ended and to_affiliation_id began for the
-- same person, caused by intake_id. Append-only history.
CREATE TABLE identity_conversions (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id BIGINT NOT NULL,
  from_affiliation_id TEXT NOT NULL,
  to_affiliation_id TEXT NOT NULL,
  from_type TEXT NOT NULL,
  to_type TEXT NOT NULL,
  trigger TEXT NOT NULL CHECK (trigger IN ('sis_status','hris_hire')),
  intake_id TEXT,
  effective_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, from_affiliation_id) REFERENCES affiliations (tenant_id, id),
  FOREIGN KEY (tenant_id, to_affiliation_id) REFERENCES affiliations (tenant_id, id),
  FOREIGN KEY (tenant_id, intake_id) REFERENCES intake_events (tenant_id, id)
);
CREATE INDEX ix_identity_conversions_identity ON identity_conversions (tenant_id, identity_id);

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER intake_events_immutable BEFORE UPDATE ON intake_events
	FOR EACH ROW WHEN (NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.channel <> OLD.channel OR NEW.event_key <> OLD.event_key
		OR NEW.created_at <> OLD.created_at)
	EXECUTE FUNCTION tessera_abort('intake_events: the event columns are immutable');

CREATE TRIGGER intake_events_no_delete BEFORE DELETE ON intake_events
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('intake events are append-only');

CREATE TRIGGER identity_conversions_immutable BEFORE UPDATE ON identity_conversions
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('identity conversions are append-only');

CREATE TRIGGER identity_conversions_no_delete BEFORE DELETE ON identity_conversions
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('identity conversions are append-only');
