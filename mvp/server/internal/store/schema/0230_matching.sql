-- Identity matching, the review queue and four-eyes merges (guest accounts
-- design §5, §9.1, issue #68 / GU-5).
--
-- match_results is what the matcher said about one intake record and one
-- candidate: the tier, the score, the rules that fired and the attributes
-- compared (masked, never a raw value), so "why did this match" is answerable
-- for every link. status says where it stands: 'review' waits in the queue,
-- 'reverification' is a reviewer link that may not be applied until the
-- claimant signs in as the existing person (§5.5.3), 'linked', 'new_person' and
-- 'rejected' are decided, 'superseded' lost to another candidate of the same
-- intake. A tier D result (no candidate) is kept too, as the record that
-- matching ran. subject_id is the provisional person the intake created.
--
-- identity_merge_requests is the second pair of eyes: a merge, or a reviewer
-- link, into a person who holds privileged access, has IAL 2 or more, or is an
-- employee waits here until a different reviewer approves it. The table itself
-- refuses a self-approval. risk is the JSON list of reasons a second reviewer
-- is needed.
--
-- matching_settings are the tenant's matching settings: whether a Tier B match
-- may auto-link, whether exact matches are reviewed, how long a merge can be
-- undone, and whether the TAP ID Match-compatible endpoint is on.
--
-- claim_links records a claim's "yes, I already have an account" sign-in (the
-- login transaction that carries it) and what came of it. The login
-- transaction's purpose stays 'claim'; this row is what tells the callback it
-- is a link by sign-in and not a credential set-up.
--
-- The guard triggers at the end replace the "identity columns are immutable"
-- triggers of affiliations, sponsorships and guest_bundle_items so that a merge
-- (and its undo) can re-point them between the two identities of an open
-- identity_merges row, and only that.
--
-- Tenant-owned like 0001_tenancy.sql. Created with IF NOT EXISTS; a reseed
-- drops and recreates (store.tables).

CREATE TABLE IF NOT EXISTS match_results (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  intake_id TEXT NOT NULL REFERENCES intake_records (id),
  subject_id INTEGER REFERENCES identities (id),
  candidate_id INTEGER REFERENCES identities (id),
  tier TEXT NOT NULL CHECK (tier IN ('A','B','C','D')),
  score REAL NOT NULL DEFAULT 0 CHECK (score >= 0 AND score <= 1),
  rules TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK (outcome IN ('auto_link','review','suspected','new')),
  status TEXT NOT NULL CHECK (status IN ('review','reverification','linked','new_person','rejected','superseded')),
  decision TEXT CHECK (decision IN ('auto_link','link','new','reject','suspected')),
  decided_by TEXT REFERENCES platform_users (id),
  second_reviewer TEXT REFERENCES platform_users (id),
  reason TEXT,
  decided_at TEXT,
  merge_id TEXT,
  created_at TEXT NOT NULL,
  CHECK ((tier = 'D') = (candidate_id IS NULL)),
  CHECK (status IN ('review','reverification') OR decided_at IS NOT NULL),
  CHECK (second_reviewer IS NULL OR second_reviewer <> decided_by)
);
CREATE INDEX IF NOT EXISTS ix_match_results_intake ON match_results (tenant_id, intake_id);
CREATE INDEX IF NOT EXISTS ix_match_results_status ON match_results (tenant_id, status, created_at);
CREATE INDEX IF NOT EXISTS ix_match_results_candidate ON match_results (tenant_id, candidate_id);

CREATE TABLE IF NOT EXISTS identity_merge_requests (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  kind TEXT NOT NULL CHECK (kind IN ('merge','match_link')),
  survivor_id INTEGER NOT NULL REFERENCES identities (id),
  merged_id INTEGER NOT NULL REFERENCES identities (id),
  match_id TEXT REFERENCES match_results (id),
  reason TEXT NOT NULL CHECK (reason <> ''),
  risk TEXT NOT NULL,
  requested_by TEXT NOT NULL REFERENCES platform_users (id),
  requested_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','approved','rejected','cancelled')),
  decided_by TEXT REFERENCES platform_users (id),
  decided_at TEXT,
  decision_reason TEXT,
  merge_id TEXT,
  CHECK (survivor_id <> merged_id),
  CHECK ((status = 'pending') = (decided_at IS NULL)),
  CHECK (status = 'pending' OR decided_by IS NOT NULL),
  -- a different person approves: a self-approval is refused by the table
  CHECK (status <> 'approved' OR decided_by <> requested_by),
  CHECK (status <> 'cancelled' OR decided_by = requested_by)
);
CREATE INDEX IF NOT EXISTS ix_merge_requests_status ON identity_merge_requests (tenant_id, status, requested_at);
-- one pending request per merged person
CREATE UNIQUE INDEX IF NOT EXISTS ux_merge_requests_pending ON identity_merge_requests (tenant_id, merged_id) WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS matching_settings (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  auto_link_tier_b INTEGER NOT NULL DEFAULT 0 CHECK (auto_link_tier_b IN (0,1)),
  require_review_tier_a INTEGER NOT NULL DEFAULT 0 CHECK (require_review_tier_a IN (0,1)),
  unmerge_window_days INTEGER NOT NULL DEFAULT 180 CHECK (unmerge_window_days BETWEEN 1 AND 3650),
  id_match_enabled INTEGER NOT NULL DEFAULT 0 CHECK (id_match_enabled IN (0,1)),
  updated_by TEXT REFERENCES platform_users (id),
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS claim_links (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  session_id_hash TEXT NOT NULL REFERENCES claim_sessions (id_hash),
  intake_id TEXT NOT NULL REFERENCES intake_records (id),
  login_txn_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('started','linked','continued','failed')),
  created_at TEXT NOT NULL,
  completed_at TEXT,
  CHECK ((status = 'started') = (completed_at IS NULL)),
  UNIQUE (tenant_id, login_txn_id)
);
CREATE INDEX IF NOT EXISTS ix_claim_links_intake ON claim_links (tenant_id, intake_id);

-- A decided match result keeps what it decided; a pending one moves forward once.
CREATE TRIGGER IF NOT EXISTS tg_match_results_immutable BEFORE UPDATE ON match_results
WHEN OLD.status IN ('linked','new_person','rejected','superseded') OR NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id
	OR NEW.intake_id <> OLD.intake_id OR NEW.candidate_id IS NOT OLD.candidate_id OR NEW.subject_id IS NOT OLD.subject_id
	OR NEW.tier <> OLD.tier OR NEW.score <> OLD.score OR NEW.rules <> OLD.rules OR NEW.outcome <> OLD.outcome
	OR NEW.created_at <> OLD.created_at
BEGIN SELECT RAISE(ABORT, 'match_results: what was matched is immutable and a decision is final'); END;

CREATE TRIGGER IF NOT EXISTS tg_match_results_no_delete BEFORE DELETE ON match_results
BEGIN SELECT RAISE(ABORT, 'match_results are append-only'); END;

CREATE TRIGGER IF NOT EXISTS tg_identity_merge_requests_immutable BEFORE UPDATE ON identity_merge_requests
WHEN OLD.status <> 'pending' OR NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.kind <> OLD.kind
	OR NEW.survivor_id <> OLD.survivor_id OR NEW.merged_id <> OLD.merged_id OR NEW.match_id IS NOT OLD.match_id
	OR NEW.reason <> OLD.reason OR NEW.risk <> OLD.risk OR NEW.requested_by <> OLD.requested_by
	OR NEW.requested_at <> OLD.requested_at
BEGIN SELECT RAISE(ABORT, 'identity_merge_requests: the request is immutable and a decision is final'); END;

CREATE TRIGGER IF NOT EXISTS tg_identity_merge_requests_no_delete BEFORE DELETE ON identity_merge_requests
BEGIN SELECT RAISE(ABORT, 'identity_merge_requests are append-only'); END;

CREATE TRIGGER IF NOT EXISTS tg_claim_links_immutable BEFORE UPDATE ON claim_links
WHEN OLD.status <> 'started' OR NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.session_id_hash <> OLD.session_id_hash
	OR NEW.intake_id <> OLD.intake_id OR NEW.login_txn_id <> OLD.login_txn_id OR NEW.created_at <> OLD.created_at
BEGIN SELECT RAISE(ABORT, 'claim_links: binding columns are immutable and a result is final'); END;

CREATE TRIGGER IF NOT EXISTS tg_claim_links_no_delete BEFORE DELETE ON claim_links
BEGIN SELECT RAISE(ABORT, 'claim_links are append-only'); END;

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_match_results_xtenant_ins BEFORE INSERT ON match_results
WHEN EXISTS (SELECT 1 FROM intake_records p WHERE p.id = NEW.intake_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.subject_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.subject_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.candidate_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.candidate_id AND p.tenant_id <> NEW.tenant_id))
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id IN (NEW.decided_by, NEW.second_reviewer) AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: match_results'); END;

CREATE TRIGGER IF NOT EXISTS tg_match_results_xtenant_upd BEFORE UPDATE OF tenant_id, intake_id, subject_id, candidate_id, decided_by, second_reviewer ON match_results
WHEN EXISTS (SELECT 1 FROM intake_records p WHERE p.id = NEW.intake_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.subject_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.subject_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.candidate_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.candidate_id AND p.tenant_id <> NEW.tenant_id))
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id IN (NEW.decided_by, NEW.second_reviewer) AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: match_results'); END;

CREATE TRIGGER IF NOT EXISTS tg_identity_merge_requests_xtenant_ins BEFORE INSERT ON identity_merge_requests
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id IN (NEW.survivor_id, NEW.merged_id) AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.match_id IS NOT NULL AND EXISTS (SELECT 1 FROM match_results p WHERE p.id = NEW.match_id AND p.tenant_id <> NEW.tenant_id))
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id IN (NEW.requested_by, NEW.decided_by) AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: identity_merge_requests'); END;

CREATE TRIGGER IF NOT EXISTS tg_identity_merge_requests_xtenant_upd BEFORE UPDATE OF tenant_id, survivor_id, merged_id, match_id, requested_by, decided_by ON identity_merge_requests
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id IN (NEW.survivor_id, NEW.merged_id) AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.match_id IS NOT NULL AND EXISTS (SELECT 1 FROM match_results p WHERE p.id = NEW.match_id AND p.tenant_id <> NEW.tenant_id))
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id IN (NEW.requested_by, NEW.decided_by) AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: identity_merge_requests'); END;

CREATE TRIGGER IF NOT EXISTS tg_matching_settings_xtenant_ins BEFORE INSERT ON matching_settings
WHEN NEW.updated_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.updated_by AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: matching_settings'); END;

CREATE TRIGGER IF NOT EXISTS tg_matching_settings_xtenant_upd BEFORE UPDATE OF tenant_id, updated_by ON matching_settings
WHEN NEW.updated_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.updated_by AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: matching_settings'); END;

CREATE TRIGGER IF NOT EXISTS tg_claim_links_xtenant_ins BEFORE INSERT ON claim_links
WHEN EXISTS (SELECT 1 FROM claim_sessions p WHERE p.id_hash = NEW.session_id_hash AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM intake_records p WHERE p.id = NEW.intake_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: claim_links'); END;

CREATE TRIGGER IF NOT EXISTS tg_claim_links_xtenant_upd BEFORE UPDATE OF tenant_id, session_id_hash, intake_id ON claim_links
WHEN EXISTS (SELECT 1 FROM claim_sessions p WHERE p.id_hash = NEW.session_id_hash AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM intake_records p WHERE p.id = NEW.intake_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: claim_links'); END;

-- Merge moves. A merge re-points a person's affiliations, sponsorships and
-- bundle items to the survivor, and an unmerge back; the earlier triggers made
-- those columns immutable. These replace them: the identity column may change
-- only between the two identities of an open identity_merges row of the same
-- tenant, and then nothing else may change in the same statement (a final row
-- stays final). Every other rule of the old triggers is kept.

DROP TRIGGER IF EXISTS tg_affiliations_immutable;
CREATE TRIGGER tg_affiliations_immutable BEFORE UPDATE ON affiliations
WHEN NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.type <> OLD.type OR NEW.source <> OLD.source
	OR NEW.starts_at <> OLD.starts_at OR NEW.created_at <> OLD.created_at
	OR (NEW.identity_id <> OLD.identity_id AND NOT EXISTS (SELECT 1 FROM identity_merges m
		WHERE m.tenant_id = NEW.tenant_id AND m.unmerged_at IS NULL
		AND ((m.merged_id = OLD.identity_id AND m.survivor_id = NEW.identity_id) OR (m.survivor_id = OLD.identity_id AND m.merged_id = NEW.identity_id))))
	OR (OLD.status IN ('ended','revoked') AND (NEW.status <> OLD.status OR NEW.source_ref IS NOT OLD.source_ref
		OR NEW.org_unit IS NOT OLD.org_unit OR NEW.partner_org_id IS NOT OLD.partner_org_id OR NEW.population IS NOT OLD.population
		OR NEW.ends_at IS NOT OLD.ends_at OR NEW.created_by IS NOT OLD.created_by OR NEW.ended_by IS NOT OLD.ended_by
		OR NEW.end_reason IS NOT OLD.end_reason))
BEGIN SELECT RAISE(ABORT, 'affiliations: ended rows and identity columns are immutable'); END;

DROP TRIGGER IF EXISTS tg_sponsorships_immutable;
CREATE TRIGGER tg_sponsorships_immutable BEFORE UPDATE ON sponsorships
WHEN NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.intake_id <> OLD.intake_id
	OR NEW.population <> OLD.population OR NEW.starts_at <> OLD.starts_at OR NEW.created_at <> OLD.created_at
	OR (NEW.guest_identity_id <> OLD.guest_identity_id AND NOT EXISTS (SELECT 1 FROM identity_merges m
		WHERE m.tenant_id = NEW.tenant_id AND m.unmerged_at IS NULL
		AND ((m.merged_id = OLD.guest_identity_id AND m.survivor_id = NEW.guest_identity_id) OR (m.survivor_id = OLD.guest_identity_id AND m.merged_id = NEW.guest_identity_id))))
	OR (OLD.status IN ('ended','revoked','rejected') AND (NEW.status <> OLD.status OR NEW.sponsor_identity_id <> OLD.sponsor_identity_id
		OR NEW.purpose <> OLD.purpose OR NEW.access_bundle <> OLD.access_bundle OR NEW.required_ial <> OLD.required_ial
		OR NEW.required_aal <> OLD.required_aal OR NEW.ends_at <> OLD.ends_at OR NEW.policy_version <> OLD.policy_version
		OR NEW.approved_by IS NOT OLD.approved_by OR NEW.approved_at IS NOT OLD.approved_at
		OR NEW.transfer_to_identity_id IS NOT OLD.transfer_to_identity_id OR NEW.transfer_deadline IS NOT OLD.transfer_deadline
		OR NEW.created_by IS NOT OLD.created_by OR NEW.updated_at <> OLD.updated_at OR NEW.ended_at IS NOT OLD.ended_at
		OR NEW.end_reason IS NOT OLD.end_reason))
BEGIN SELECT RAISE(ABORT, 'sponsorships: final rows and identity columns are immutable'); END;

DROP TRIGGER IF EXISTS tg_guest_bundle_items_immutable;
CREATE TRIGGER tg_guest_bundle_items_immutable BEFORE UPDATE ON guest_bundle_items
WHEN NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.sponsorship_id <> OLD.sponsorship_id
	OR NEW.group_id <> OLD.group_id OR NEW.created_at <> OLD.created_at
	OR (NEW.guest_identity_id <> OLD.guest_identity_id AND NOT EXISTS (SELECT 1 FROM identity_merges m
		WHERE m.tenant_id = NEW.tenant_id AND m.unmerged_at IS NULL
		AND ((m.merged_id = OLD.guest_identity_id AND m.survivor_id = NEW.guest_identity_id) OR (m.survivor_id = OLD.guest_identity_id AND m.merged_id = NEW.guest_identity_id))))
	OR (OLD.status = 'removed' AND (NEW.status <> OLD.status OR NEW.system <> OLD.system OR NEW.account_op_id IS NOT OLD.account_op_id
		OR NEW.grant_op_id IS NOT OLD.grant_op_id OR NEW.remove_op_id IS NOT OLD.remove_op_id OR NEW.edge_id IS NOT OLD.edge_id
		OR NEW.expires_at <> OLD.expires_at OR NEW.updated_at <> OLD.updated_at OR NEW.granted_at IS NOT OLD.granted_at
		OR NEW.removed_at IS NOT OLD.removed_at))
BEGIN SELECT RAISE(ABORT, 'guest_bundle_items: removed rows and identity columns are immutable'); END;
