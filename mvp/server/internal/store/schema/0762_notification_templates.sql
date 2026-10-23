-- Admin > Notifications: a tenant's own wording for the email of a notification
-- kind (approval needed, escalated, review reminder, and the other kinds users
-- can choose a channel for). One row per tenant and kind; no row means the
-- wording the producer wrote.
--
-- subject_tpl and body_tpl hold text with {{name}} placeholders (subject, body,
-- link, product, recipient_name); nothing else is interpreted, so a template can
-- neither run code nor read data the notification does not carry. The API checks
-- the placeholders and the lengths.
--
-- Tenant-owned like 0001_tenancy.sql.
CREATE TABLE IF NOT EXISTS notification_templates (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  kind TEXT NOT NULL CHECK (length(kind) BETWEEN 1 AND 100),
  subject_tpl TEXT NOT NULL CHECK (length(subject_tpl) <= 300),
  body_tpl TEXT NOT NULL CHECK (length(body_tpl) <= 4000),
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, kind)
);
