-- Postgres dialect of schema/0007_replay.sql (Phase 0 PR14). GLOBAL table.

-- +goose Up

CREATE TABLE replay_cache (
  kind TEXT NOT NULL CHECK (kind IN ('saml_assertion','cas_ticket','dpop_jti')),
  key_hash TEXT NOT NULL CHECK (length(key_hash) = 64),
  expires_at TEXT NOT NULL,
  PRIMARY KEY (kind, key_hash)
);
CREATE INDEX replay_cache_expires ON replay_cache(expires_at);
