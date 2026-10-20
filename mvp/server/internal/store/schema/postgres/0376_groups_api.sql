-- Postgres dialect of schema/0376_groups_api.sql (kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres). The immutability trigger uses tessera_abort.

-- +goose Up

CREATE TABLE grp_idempotency (
  tenant_id    TEXT NOT NULL REFERENCES tenants (id),
  principal    TEXT NOT NULL,
  idem_key     TEXT NOT NULL CHECK (length(idem_key) BETWEEN 1 AND 255),
  request_hash TEXT NOT NULL,
  status       INTEGER NOT NULL,
  body         TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  expires_at   TEXT NOT NULL,
  PRIMARY KEY (tenant_id, principal, idem_key)
);
CREATE INDEX grp_idem_expiry ON grp_idempotency (tenant_id, expires_at);

CREATE TRIGGER tg_grp_idempotency_immutable BEFORE UPDATE ON grp_idempotency
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('grp_idempotency rows are immutable');
