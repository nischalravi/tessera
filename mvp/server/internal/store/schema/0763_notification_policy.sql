-- Admin > Notifications: reminder cadence and escalation SLAs. One row per tenant;
-- no row means the built-in timings (reminders after 7 days and every 7 days, access
-- ending warned 24 hours and just-in-time access 60 minutes ahead, approvals
-- escalated after 48 hours).
--
-- review_remind_after_days is how old an open review campaign is before its
-- reviewers are reminded and review_remind_every_days how often after that.
-- request_warn_hours and jit_warn_minutes are how far ahead the end of requested
-- and just-in-time access is announced. escalate_after_hours is how long an
-- approval stage waits before deciders may act, for a catalog item that has no
-- approval policy of its own (an item's own policy, an organization's default and a
-- workflow keep theirs).
--
-- Tenant-owned like 0001_tenancy.sql.
CREATE TABLE IF NOT EXISTS notification_policy (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  review_remind_after_days INTEGER NOT NULL CHECK (review_remind_after_days BETWEEN 1 AND 90),
  review_remind_every_days INTEGER NOT NULL CHECK (review_remind_every_days BETWEEN 1 AND 90),
  request_warn_hours INTEGER NOT NULL CHECK (request_warn_hours BETWEEN 1 AND 720),
  jit_warn_minutes INTEGER NOT NULL CHECK (jit_warn_minutes BETWEEN 5 AND 1440),
  escalate_after_hours INTEGER NOT NULL CHECK (escalate_after_hours BETWEEN 1 AND 720),
  version INTEGER NOT NULL DEFAULT 1,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
