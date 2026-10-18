-- Sponsorships, sponsor invitations and their history (guest accounts design
-- §4.3, §8.2-8.3 and §9.1, issue #65 / GU-2).
--
-- A sponsorship is the record of one sponsor's decision to vouch for one
-- guest: who, why, which population and access bundle, for how long, who
-- approved it and under which version of the sponsor policy. While it is
-- active it drives the guest's affiliation (affiliations, source
-- 'sponsorship') and lifecycle (identity_lifecycle): a person stays active
-- until their last live sponsorship ends.
--
-- intake_records say how a person came to us. A sponsor invitation is
-- self-asserted (match_mode 'self_asserted'): it always creates a NEW
-- identity and never links to an existing person; matching and merging are
-- GU-5. invitation_status is the seam for GU-6: 'ready' means the claim link
-- and the guest's invitation email can be issued; nothing here sends them.
--
-- sponsorship_events is the append-only history of one sponsorship, each
-- decision stamped with the policy version that made it.
--
-- Tenant-owned like 0001_tenancy.sql: guard triggers at the end refuse a
-- reference to another tenant's row. Created with IF NOT EXISTS; a reseed
-- drops and recreates (store.tables).

CREATE TABLE IF NOT EXISTS intake_records (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  channel TEXT NOT NULL CHECK (channel IN ('sponsor_invite','bulk_invite','self_registration','sis','hris','vms',
    'partner_invite','partner_scim')),
  match_mode TEXT NOT NULL CHECK (match_mode IN ('authoritative','self_asserted','federated')),
  source_record_id TEXT REFERENCES identity_source_records (id),
  submitted_by TEXT REFERENCES platform_users (id),
  sponsor_identity_id INTEGER REFERENCES identities (id),
  batch_id TEXT,
  status TEXT NOT NULL CHECK (status IN ('received','matching','review','resolved','rejected')),
  invitation_status TEXT NOT NULL DEFAULT 'ready' CHECK (invitation_status IN ('ready','sent','claimed','revoked')),
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_intake_records_sponsor ON intake_records (tenant_id, sponsor_identity_id, created_at);

CREATE TABLE IF NOT EXISTS sponsorships (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  guest_identity_id INTEGER NOT NULL REFERENCES identities (id),
  intake_id TEXT NOT NULL REFERENCES intake_records (id),
  sponsor_identity_id INTEGER NOT NULL REFERENCES identities (id),
  population TEXT NOT NULL CHECK (population IN ('visitor','contractor','volunteer','partner')),
  purpose TEXT NOT NULL CHECK (purpose <> ''),
  access_bundle TEXT NOT NULL DEFAULT '[]',
  required_ial INTEGER NOT NULL CHECK (required_ial IN (0,1,2)),
  required_aal INTEGER NOT NULL CHECK (required_aal IN (1,2,3)),
  starts_at TEXT NOT NULL,
  ends_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('requested','pending_approval','active','transfer_pending','ended',
    'revoked','rejected')),
  policy_version TEXT NOT NULL CHECK (policy_version <> ''),
  approved_by TEXT REFERENCES platform_users (id),
  approved_at TEXT,
  transfer_to_identity_id INTEGER REFERENCES identities (id),
  transfer_deadline TEXT,
  created_by TEXT REFERENCES platform_users (id),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  ended_at TEXT,
  end_reason TEXT,
  CHECK (ends_at > starts_at),
  CHECK (guest_identity_id <> sponsor_identity_id),
  CHECK ((transfer_to_identity_id IS NULL) = (transfer_deadline IS NULL)),
  CHECK ((status = 'transfer_pending') = (transfer_to_identity_id IS NOT NULL)),
  CHECK ((status IN ('ended','revoked','rejected')) = (ended_at IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS ix_sponsorships_sponsor ON sponsorships (tenant_id, sponsor_identity_id, status);
CREATE INDEX IF NOT EXISTS ix_sponsorships_guest ON sponsorships (tenant_id, guest_identity_id, status);
CREATE INDEX IF NOT EXISTS ix_sponsorships_status_ends ON sponsorships (tenant_id, status, ends_at);

CREATE TABLE IF NOT EXISTS sponsorship_events (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  sponsorship_id TEXT NOT NULL REFERENCES sponsorships (id),
  event TEXT NOT NULL CHECK (event IN ('created','approval_requested','approved','rejected','renewed','ended',
    'revoked','expired','transfer_requested','transfer_accepted','transfer_expired')),
  from_status TEXT,
  to_status TEXT NOT NULL,
  note TEXT,
  policy_version TEXT NOT NULL CHECK (policy_version <> ''),
  actor_user_id TEXT REFERENCES platform_users (id),
  actor TEXT NOT NULL,
  at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_sponsorship_events_sponsorship ON sponsorship_events (tenant_id, sponsorship_id, id);

CREATE TRIGGER IF NOT EXISTS tg_sponsorship_events_no_update BEFORE UPDATE ON sponsorship_events
BEGIN SELECT RAISE(ABORT, 'sponsorship_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS tg_sponsorship_events_no_delete BEFORE DELETE ON sponsorship_events
BEGIN SELECT RAISE(ABORT, 'sponsorship_events is append-only'); END;

-- A sponsorship's person, intake and term never change; its sponsor changes
-- only through a transfer, its status only forward (a final status is final).
CREATE TRIGGER IF NOT EXISTS tg_sponsorships_immutable BEFORE UPDATE ON sponsorships
WHEN OLD.status IN ('ended','revoked','rejected') OR NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id
	OR NEW.guest_identity_id <> OLD.guest_identity_id OR NEW.intake_id <> OLD.intake_id
	OR NEW.population <> OLD.population OR NEW.starts_at <> OLD.starts_at OR NEW.created_at <> OLD.created_at
BEGIN SELECT RAISE(ABORT, 'sponsorships: final rows and identity columns are immutable'); END;

CREATE TRIGGER IF NOT EXISTS tg_sponsorships_no_delete BEFORE DELETE ON sponsorships
BEGIN SELECT RAISE(ABORT, 'sponsorships are append-only'); END;

CREATE TRIGGER IF NOT EXISTS tg_intake_records_immutable BEFORE UPDATE ON intake_records
WHEN NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.channel <> OLD.channel OR NEW.match_mode <> OLD.match_mode
	OR NEW.created_at <> OLD.created_at
BEGIN SELECT RAISE(ABORT, 'intake_records: channel, match mode and identity columns are immutable'); END;

CREATE TRIGGER IF NOT EXISTS tg_intake_records_no_delete BEFORE DELETE ON intake_records
BEGIN SELECT RAISE(ABORT, 'intake_records are append-only'); END;

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_intake_records_xtenant_ins BEFORE INSERT ON intake_records
WHEN (NEW.source_record_id IS NOT NULL AND EXISTS (SELECT 1 FROM identity_source_records p WHERE p.id = NEW.source_record_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.submitted_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.submitted_by AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.sponsor_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.sponsor_identity_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: intake_records'); END;

CREATE TRIGGER IF NOT EXISTS tg_intake_records_xtenant_upd BEFORE UPDATE OF tenant_id, source_record_id, submitted_by, sponsor_identity_id ON intake_records
WHEN (NEW.source_record_id IS NOT NULL AND EXISTS (SELECT 1 FROM identity_source_records p WHERE p.id = NEW.source_record_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.submitted_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.submitted_by AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.sponsor_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.sponsor_identity_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: intake_records'); END;

CREATE TRIGGER IF NOT EXISTS tg_sponsorships_xtenant_ins BEFORE INSERT ON sponsorships
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id IN (NEW.guest_identity_id, NEW.sponsor_identity_id) AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM intake_records p WHERE p.id = NEW.intake_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.transfer_to_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.transfer_to_identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.approved_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.approved_by AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.created_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.created_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: sponsorships'); END;

CREATE TRIGGER IF NOT EXISTS tg_sponsorships_xtenant_upd BEFORE UPDATE OF tenant_id, guest_identity_id, intake_id, sponsor_identity_id, transfer_to_identity_id, approved_by, created_by ON sponsorships
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id IN (NEW.guest_identity_id, NEW.sponsor_identity_id) AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM intake_records p WHERE p.id = NEW.intake_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.transfer_to_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.transfer_to_identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.approved_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.approved_by AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.created_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.created_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: sponsorships'); END;

CREATE TRIGGER IF NOT EXISTS tg_sponsorship_events_xtenant_ins BEFORE INSERT ON sponsorship_events
WHEN EXISTS (SELECT 1 FROM sponsorships p WHERE p.id = NEW.sponsorship_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.actor_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.actor_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: sponsorship_events'); END;

CREATE TRIGGER IF NOT EXISTS tg_sponsorship_events_xtenant_upd BEFORE UPDATE OF tenant_id, sponsorship_id, actor_user_id ON sponsorship_events
WHEN EXISTS (SELECT 1 FROM sponsorships p WHERE p.id = NEW.sponsorship_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.actor_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.actor_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: sponsorship_events'); END;
