package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"regexp"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Postgres support (Phase 0 PR14, design §14.3).
//
// DSN: postgres://user:pass@host:5432/db?sslmode=require[&app_role=tessera_app]
//
// The DSN's role runs the goose migrations and rls.sql (it must own the
// tables; in production that is tessera_owner, and it must be a superuser or
// have BYPASSRLS so the node-key guard in 0001_tenancy.sql can see other
// tenants' rows). When app_role is given, every connection used for requests
// then runs SET ROLE to it: NOSUPERUSER, NOBYPASSRLS and not the table owner,
// so row-level security binds it. Without app_role one role does both jobs
// (development); FORCE ROW LEVEL SECURITY still applies to a non-superuser
// owner.

// pgSetTenant and pgSetLookup are the only statements that set the session
// variables row-level security reads. They are constants, take one parameter
// and contain no dollar-quoted string (TestPostgresStatementsNoDollarQuotes).
const (
	pgSetTenant = `SELECT set_config('app.tenant_id', $1, true)`
	pgSetLookup = `SELECT set_config('app.lookup', $1, true)`
	// pgLockTenant serializes one tenant's write transactions until commit.
	pgLockTenant = `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`
)

// roleName is what an app_role may look like.
var roleName = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// pgGooseTable is goose's bookkeeping table (listed in GlobalTables).
const pgGooseTable = "schema_migrations"

// parsePGDSN splits the app_role option off a DSN (pgx would send an unknown
// parameter to the server as a setting) and parses the rest.
func parsePGDSN(dsn string) (*pgx.ConnConfig, string, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, "", errors.New("store: invalid postgres DSN")
	}
	// ParseQuery, not u.Query(): the latter silently drops a malformed pair,
	// which for app_role would mean running without it.
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, "", errors.New("store: invalid postgres DSN query")
	}
	role := q.Get("app_role")
	q.Del("app_role")
	u.RawQuery = q.Encode()
	if role != "" && !roleName.MatchString(role) {
		return nil, "", fmt.Errorf("store: invalid app_role %q", role)
	}
	cfg, err := pgx.ParseConfig(u.String())
	if err != nil {
		// pgx errors can echo the DSN; do not leak a password.
		return nil, "", errors.New("store: invalid postgres DSN")
	}
	return cfg, role, nil
}

func openPostgres(ctx context.Context, dsn string, fresh bool) (*DB, error) {
	cfg, role, err := parsePGDSN(dsn)
	if err != nil {
		return nil, err
	}
	owner := stdlib.OpenDB(*cfg)
	owner.SetMaxOpenConns(8)
	d := &DB{sql: owner, owner: owner, d: dialectPostgres}
	if err := d.Migrate(ctx, fresh); err != nil {
		_ = owner.Close()
		return nil, err
	}
	if role != "" {
		app := cfg.Copy()
		app.AfterConnect = func(ctx context.Context, c *pgconn.PgConn) error {
			_, err := c.Exec(ctx, "SET ROLE "+pgx.Identifier{role}.Sanitize()).ReadAll()
			return err
		}
		pool := stdlib.OpenDB(*app)
		pool.SetMaxOpenConns(16)
		if err := pool.PingContext(ctx); err != nil {
			_ = pool.Close()
			_ = owner.Close()
			return nil, fmt.Errorf("store: connect as app_role %s: %w", role, err)
		}
		d.sql = pool
	}
	return d, nil
}

// migratePG applies the goose migrations and rls.sql as the owner role, then
// ensures the _platform tenant. drop=true drops every table first (reseed);
// like SQLite's reseed it only touches the tables this schema owns.
func (d *DB) migratePG(ctx context.Context, drop bool) error {
	if drop {
		rev := slices.Clone(tables)
		slices.Reverse(rev)
		for _, t := range slices.Concat(legacyTables, rev, []string{pgGooseTable}) {
			// t comes from the fixed lists above, never from input.
			if _, err := d.owner.ExecContext(ctx, "DROP TABLE IF EXISTS "+t+" CASCADE"); err != nil { // #nosec G202 -- fixed table names
				return fmt.Errorf("store: drop %s: %w", t, err)
			}
		}
	}
	fsys, err := fs.Sub(pgSchemaFS, "schema/postgres")
	if err != nil {
		return err
	}
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return err
	}
	p, err := goose.NewProvider(goose.DialectPostgres, d.owner, fsys,
		goose.WithTableName(pgGooseTable),
		goose.WithExcludeNames([]string{pgRLSFile}),
		goose.WithSessionLocker(locker))
	if err != nil {
		return fmt.Errorf("store: migrations: %w", err)
	}
	if _, err := p.Up(ctx); err != nil {
		return fmt.Errorf("store: migrations: %w", err)
	}
	rls, err := fs.ReadFile(fsys, pgRLSFile)
	if err != nil {
		return fmt.Errorf("store: %s: %w", pgRLSFile, err)
	}
	if _, err := d.owner.ExecContext(ctx, string(rls)); err != nil {
		return fmt.Errorf("store: %s: %w", pgRLSFile, err)
	}
	// A tamper test may have disabled the audit triggers; Open brings them back.
	if _, err := d.owner.ExecContext(ctx, pgEnableAuditTriggers); err != nil {
		return fmt.Errorf("store: enable audit triggers: %w", err)
	}
	return d.inSystemLocked(ctx, "migrate: ensure _platform tenant", func(s *SystemTx) error {
		_, err := s.exec(tenantsEnsurePlatform, sql.Named("id", tenancy.Platform.String()),
			sql.Named("created_at", T(nowUTC())))
		return err
	})
}

const pgEnableAuditTriggers = `
	ALTER TABLE audit_events ENABLE TRIGGER USER;
	ALTER TABLE audit_checkpoints ENABLE TRIGGER USER;
	ALTER TABLE audit_chain_heads ENABLE TRIGGER USER;`
