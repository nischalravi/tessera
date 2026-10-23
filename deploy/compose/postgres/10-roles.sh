#!/bin/sh
# Runs once, on first start of an empty data directory. Creates the two logins Tessera needs
# (mvp/README.md, "Postgres"): the owner (migrations) and the application (row-level security applies).
set -eu
psql -v ON_ERROR_STOP=1 --username postgres --dbname postgres \
  -v owner_pw="$TESSERA_OWNER_PASSWORD" -v app_pw="$TESSERA_APP_PASSWORD" <<'SQL'
CREATE ROLE tessera_owner LOGIN PASSWORD :'owner_pw' BYPASSRLS;
CREATE ROLE tessera_app LOGIN PASSWORD :'app_pw' NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
ALTER DATABASE tessera OWNER TO tessera_owner;
REVOKE TEMPORARY ON DATABASE tessera FROM PUBLIC, tessera_app;
SQL
