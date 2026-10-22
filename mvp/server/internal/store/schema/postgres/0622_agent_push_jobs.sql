-- Postgres dialect of the change to schema/0461_agent_jobs.sql (issue #302): the
-- 'provision_push' job kind and the operation it carries out. SQLite gets the
-- same from the new 0461 and upgradeAgentJobs.

-- +goose Up

ALTER TABLE agent_jobs DROP CONSTRAINT agent_jobs_kind_check;
ALTER TABLE agent_jobs ADD CONSTRAINT agent_jobs_kind_check CHECK (kind IN ('sync','provision_push'));
ALTER TABLE agent_jobs ADD COLUMN op_id TEXT;
ALTER TABLE agent_jobs ADD FOREIGN KEY (tenant_id, op_id) REFERENCES provisioning_ops (tenant_id, id);
CREATE INDEX ix_agent_jobs_op ON agent_jobs (tenant_id, op_id, status);
