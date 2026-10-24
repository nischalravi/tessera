-- Certification actions on a review item (issue #588): a reviewer asks another person for advice
-- (consult), the person answers, and an item is reassigned to another reviewer. Append-only: the
-- current reviewer of an item stays in review_items.reviewer_id; this is the trail of how it got
-- there and what was asked.
--
-- kind 'consult': target_identity_id is the person asked, note the question. kind 'answer': the
-- target person's reply, ref_id the consult event it answers. kind 'reassign': target_identity_id is
-- the new reviewer, note the reason. A consult is open until an answer event names it.
--
-- review_campaign_locks: when and by whom a campaign was locked, and when the lock ends by itself. A lock
-- is never indefinite: after expires_at the next decision or schedule pass unlocks the campaign and the
-- deadline logic resumes. One row per locked campaign; unlocking removes it.
--
-- Tenant-owned like 0001_tenancy.sql.
CREATE TABLE IF NOT EXISTS review_item_events (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  item_id INTEGER NOT NULL REFERENCES review_items (id),
  kind TEXT NOT NULL CHECK (kind IN ('consult','answer','reassign')),
  ref_id INTEGER,
  actor_user_id TEXT NOT NULL REFERENCES platform_users (id),
  actor TEXT NOT NULL,
  target_identity_id INTEGER REFERENCES identities (id),
  note TEXT NOT NULL CHECK (length(note) BETWEEN 1 AND 1000),
  at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_review_item_events_tenant_item ON review_item_events (tenant_id, item_id, id);
CREATE INDEX IF NOT EXISTS ix_review_item_events_tenant_target ON review_item_events (tenant_id, target_identity_id, kind);

CREATE TRIGGER IF NOT EXISTS tg_review_item_events_no_update BEFORE UPDATE ON review_item_events
BEGIN SELECT RAISE(ABORT, 'review_item_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS tg_review_item_events_no_delete BEFORE DELETE ON review_item_events
BEGIN SELECT RAISE(ABORT, 'review_item_events is append-only'); END;

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_review_item_events_xtenant_ins BEFORE INSERT ON review_item_events
WHEN EXISTS (SELECT 1 FROM review_items p WHERE p.id = NEW.item_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.actor_user_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.target_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.target_identity_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: review_item_events'); END;

CREATE TRIGGER IF NOT EXISTS tg_review_item_events_xtenant_upd BEFORE UPDATE OF tenant_id, item_id, actor_user_id, target_identity_id ON review_item_events
WHEN EXISTS (SELECT 1 FROM review_items p WHERE p.id = NEW.item_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.actor_user_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.target_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.target_identity_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: review_item_events'); END;

CREATE TABLE IF NOT EXISTS review_campaign_locks (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  campaign_id INTEGER NOT NULL REFERENCES review_campaigns (id),
  locked_by TEXT NOT NULL,
  reason TEXT NOT NULL,
  locked_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, campaign_id)
);

CREATE TRIGGER IF NOT EXISTS tg_review_campaign_locks_xtenant_ins BEFORE INSERT ON review_campaign_locks
WHEN EXISTS (SELECT 1 FROM review_campaigns p WHERE p.id = NEW.campaign_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: review_campaign_locks'); END;

CREATE TRIGGER IF NOT EXISTS tg_review_campaign_locks_xtenant_upd BEFORE UPDATE OF tenant_id, campaign_id ON review_campaign_locks
WHEN EXISTS (SELECT 1 FROM review_campaigns p WHERE p.id = NEW.campaign_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: review_campaign_locks'); END;
