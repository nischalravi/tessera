-- Postgres dialect of schema/0363_matching.sql (kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE match_results (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  intake_id TEXT NOT NULL,
  subject_id BIGINT,
  candidate_id BIGINT,
  tier TEXT NOT NULL CHECK (tier IN ('A','B','C','D')),
  score DOUBLE PRECISION NOT NULL DEFAULT 0 CHECK (score >= 0 AND score <= 1),
  rules TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK (outcome IN ('auto_link','review','suspected','new')),
  status TEXT NOT NULL CHECK (status IN ('review','reverification','linked','new_person','rejected','superseded')),
  decision TEXT CHECK (decision IN ('auto_link','link','new','reject','suspected')),
  decided_by TEXT,
  second_reviewer TEXT,
  reason TEXT,
  decided_at TEXT,
  merge_id TEXT,
  created_at TEXT NOT NULL,
  UNIQUE (tenant_id, id),
  CHECK ((tier = 'D') = (candidate_id IS NULL)),
  CHECK (status IN ('review','reverification') OR decided_at IS NOT NULL),
  CHECK (second_reviewer IS NULL OR second_reviewer <> decided_by),
  FOREIGN KEY (tenant_id, intake_id) REFERENCES intake_records (tenant_id, id),
  FOREIGN KEY (tenant_id, subject_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, candidate_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, decided_by) REFERENCES platform_users (tenant_id, id),
  FOREIGN KEY (tenant_id, second_reviewer) REFERENCES platform_users (tenant_id, id)
);
CREATE INDEX ix_match_results_intake ON match_results (tenant_id, intake_id);
CREATE INDEX ix_match_results_status ON match_results (tenant_id, status, created_at);
CREATE INDEX ix_match_results_candidate ON match_results (tenant_id, candidate_id);

CREATE TABLE identity_merge_requests (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  kind TEXT NOT NULL CHECK (kind IN ('merge','match_link')),
  survivor_id BIGINT NOT NULL,
  merged_id BIGINT NOT NULL,
  match_id TEXT,
  reason TEXT NOT NULL CHECK (reason <> ''),
  risk TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  requested_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','approved','rejected','cancelled')),
  decided_by TEXT,
  decided_at TEXT,
  decision_reason TEXT,
  merge_id TEXT,
  UNIQUE (tenant_id, id),
  CHECK (survivor_id <> merged_id),
  CHECK ((status = 'pending') = (decided_at IS NULL)),
  CHECK (status = 'pending' OR decided_by IS NOT NULL),
  -- a different person approves: a self-approval is refused by the table
  CHECK (status <> 'approved' OR decided_by <> requested_by),
  CHECK (status <> 'cancelled' OR decided_by = requested_by),
  FOREIGN KEY (tenant_id, survivor_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, merged_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, match_id) REFERENCES match_results (tenant_id, id),
  FOREIGN KEY (tenant_id, requested_by) REFERENCES platform_users (tenant_id, id),
  FOREIGN KEY (tenant_id, decided_by) REFERENCES platform_users (tenant_id, id)
);
CREATE INDEX ix_merge_requests_status ON identity_merge_requests (tenant_id, status, requested_at);
-- one pending request per merged person
CREATE UNIQUE INDEX ux_merge_requests_pending ON identity_merge_requests (tenant_id, merged_id) WHERE status = 'pending';

CREATE TABLE matching_settings (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  auto_link_tier_b BIGINT NOT NULL DEFAULT 0 CHECK (auto_link_tier_b IN (0,1)),
  require_review_tier_a BIGINT NOT NULL DEFAULT 0 CHECK (require_review_tier_a IN (0,1)),
  unmerge_window_days BIGINT NOT NULL DEFAULT 180 CHECK (unmerge_window_days BETWEEN 1 AND 3650),
  updated_by TEXT,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (tenant_id, updated_by) REFERENCES platform_users (tenant_id, id)
);

CREATE TABLE claim_links (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  session_id_hash TEXT NOT NULL,
  intake_id TEXT NOT NULL,
  login_txn_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('started','linked','continued','failed')),
  created_at TEXT NOT NULL,
  completed_at TEXT,
  CHECK ((status = 'started') = (completed_at IS NULL)),
  UNIQUE (tenant_id, login_txn_id),
  FOREIGN KEY (tenant_id, session_id_hash) REFERENCES claim_sessions (tenant_id, id_hash),
  FOREIGN KEY (tenant_id, intake_id) REFERENCES intake_records (tenant_id, id)
);
CREATE INDEX ix_claim_links_intake ON claim_links (tenant_id, intake_id);

-- A decided match result keeps what it decided; a pending one moves forward once.
CREATE TRIGGER match_results_immutable BEFORE UPDATE ON match_results
	FOR EACH ROW WHEN (OLD.status IN ('linked','new_person','rejected','superseded') OR NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id
		OR NEW.intake_id <> OLD.intake_id OR NEW.candidate_id IS DISTINCT FROM OLD.candidate_id OR NEW.subject_id IS DISTINCT FROM OLD.subject_id
		OR NEW.tier <> OLD.tier OR NEW.score <> OLD.score OR NEW.rules <> OLD.rules OR NEW.outcome <> OLD.outcome
		OR NEW.created_at <> OLD.created_at)
	EXECUTE FUNCTION tessera_abort('match_results: what was matched is immutable and a decision is final');

CREATE TRIGGER match_results_no_delete BEFORE DELETE ON match_results
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('match_results are append-only');

CREATE TRIGGER identity_merge_requests_immutable BEFORE UPDATE ON identity_merge_requests
	FOR EACH ROW WHEN (OLD.status <> 'pending' OR NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.kind <> OLD.kind
		OR NEW.survivor_id <> OLD.survivor_id OR NEW.merged_id <> OLD.merged_id OR NEW.match_id IS DISTINCT FROM OLD.match_id
		OR NEW.reason <> OLD.reason OR NEW.risk <> OLD.risk OR NEW.requested_by <> OLD.requested_by
		OR NEW.requested_at <> OLD.requested_at)
	EXECUTE FUNCTION tessera_abort('identity_merge_requests: the request is immutable and a decision is final');

CREATE TRIGGER identity_merge_requests_no_delete BEFORE DELETE ON identity_merge_requests
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('identity_merge_requests are append-only');

CREATE TRIGGER claim_links_immutable BEFORE UPDATE ON claim_links
	FOR EACH ROW WHEN (OLD.status <> 'started' OR NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.session_id_hash <> OLD.session_id_hash
		OR NEW.intake_id <> OLD.intake_id OR NEW.login_txn_id <> OLD.login_txn_id OR NEW.created_at <> OLD.created_at)
	EXECUTE FUNCTION tessera_abort('claim_links: binding columns are immutable and a result is final');

CREATE TRIGGER claim_links_no_delete BEFORE DELETE ON claim_links
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('claim_links are append-only');

-- Merge moves. A merge re-points a person's affiliations, sponsorships and
-- bundle items to the survivor, and an unmerge back; the earlier triggers made
-- those columns immutable. These replace them: the identity column may change
-- only between the two identities of an open identity_merges row of the same
-- tenant, and then nothing else may change in the same statement (a final row
-- stays final). Every other rule of the old triggers is kept.

DROP TRIGGER affiliations_immutable ON affiliations;
CREATE TRIGGER affiliations_immutable BEFORE UPDATE ON affiliations
	FOR EACH ROW WHEN (NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.type <> OLD.type OR NEW.source <> OLD.source
		OR NEW.starts_at <> OLD.starts_at OR NEW.created_at <> OLD.created_at
		OR (NEW.identity_id <> OLD.identity_id AND NOT EXISTS (SELECT 1 FROM identity_merges m
			WHERE m.tenant_id = NEW.tenant_id AND m.unmerged_at IS NULL
			AND ((m.merged_id = OLD.identity_id AND m.survivor_id = NEW.identity_id) OR (m.survivor_id = OLD.identity_id AND m.merged_id = NEW.identity_id))))
		OR (OLD.status IN ('ended','revoked') AND (NEW.status <> OLD.status OR NEW.source_ref IS DISTINCT FROM OLD.source_ref
			OR NEW.org_unit IS DISTINCT FROM OLD.org_unit OR NEW.partner_org_id IS DISTINCT FROM OLD.partner_org_id OR NEW.population IS DISTINCT FROM OLD.population
			OR NEW.ends_at IS DISTINCT FROM OLD.ends_at OR NEW.created_by IS DISTINCT FROM OLD.created_by OR NEW.ended_by IS DISTINCT FROM OLD.ended_by
			OR NEW.end_reason IS DISTINCT FROM OLD.end_reason)))
	EXECUTE FUNCTION tessera_abort('affiliations: ended rows and identity columns are immutable');

DROP TRIGGER sponsorships_immutable ON sponsorships;
CREATE TRIGGER sponsorships_immutable BEFORE UPDATE ON sponsorships
	FOR EACH ROW WHEN (NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.intake_id <> OLD.intake_id
		OR NEW.population <> OLD.population OR NEW.starts_at <> OLD.starts_at OR NEW.created_at <> OLD.created_at
		OR (NEW.guest_identity_id <> OLD.guest_identity_id AND NOT EXISTS (SELECT 1 FROM identity_merges m
			WHERE m.tenant_id = NEW.tenant_id AND m.unmerged_at IS NULL
			AND ((m.merged_id = OLD.guest_identity_id AND m.survivor_id = NEW.guest_identity_id) OR (m.survivor_id = OLD.guest_identity_id AND m.merged_id = NEW.guest_identity_id))))
		OR (OLD.status IN ('ended','revoked','rejected') AND (NEW.status <> OLD.status OR NEW.sponsor_identity_id <> OLD.sponsor_identity_id
			OR NEW.purpose <> OLD.purpose OR NEW.access_bundle <> OLD.access_bundle OR NEW.required_ial <> OLD.required_ial
			OR NEW.required_aal <> OLD.required_aal OR NEW.ends_at <> OLD.ends_at OR NEW.policy_version <> OLD.policy_version
			OR NEW.approved_by IS DISTINCT FROM OLD.approved_by OR NEW.approved_at IS DISTINCT FROM OLD.approved_at
			OR NEW.transfer_to_identity_id IS DISTINCT FROM OLD.transfer_to_identity_id OR NEW.transfer_deadline IS DISTINCT FROM OLD.transfer_deadline
			OR NEW.created_by IS DISTINCT FROM OLD.created_by OR NEW.updated_at <> OLD.updated_at OR NEW.ended_at IS DISTINCT FROM OLD.ended_at
			OR NEW.end_reason IS DISTINCT FROM OLD.end_reason)))
	EXECUTE FUNCTION tessera_abort('sponsorships: final rows and identity columns are immutable');

DROP TRIGGER guest_bundle_items_immutable ON guest_bundle_items;
CREATE TRIGGER guest_bundle_items_immutable BEFORE UPDATE ON guest_bundle_items
	FOR EACH ROW WHEN (NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.sponsorship_id <> OLD.sponsorship_id
		OR NEW.group_id <> OLD.group_id OR NEW.created_at <> OLD.created_at
		OR (NEW.guest_identity_id <> OLD.guest_identity_id AND NOT EXISTS (SELECT 1 FROM identity_merges m
			WHERE m.tenant_id = NEW.tenant_id AND m.unmerged_at IS NULL
			AND ((m.merged_id = OLD.guest_identity_id AND m.survivor_id = NEW.guest_identity_id) OR (m.survivor_id = OLD.guest_identity_id AND m.merged_id = NEW.guest_identity_id))))
		OR (OLD.status = 'removed' AND (NEW.status <> OLD.status OR NEW.system <> OLD.system OR NEW.account_op_id IS DISTINCT FROM OLD.account_op_id
			OR NEW.grant_op_id IS DISTINCT FROM OLD.grant_op_id OR NEW.remove_op_id IS DISTINCT FROM OLD.remove_op_id OR NEW.edge_id IS DISTINCT FROM OLD.edge_id
			OR NEW.expires_at <> OLD.expires_at OR NEW.updated_at <> OLD.updated_at OR NEW.granted_at IS DISTINCT FROM OLD.granted_at
			OR NEW.removed_at IS DISTINCT FROM OLD.removed_at)))
	EXECUTE FUNCTION tessera_abort('guest_bundle_items: removed rows and identity columns are immutable');
