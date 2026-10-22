package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Postgres support (Phase 0 PR14, design §14.3; #430).
//
// Two logins, two DSNs. The owner DSN (TESSERA_DB) runs the goose migrations
// and rls.sql; its role owns the tables and must be a superuser or have
// BYPASSRLS so the node-key guard in 0001_tenancy.sql can see other tenants'
// rows. The request pool connects directly as the application login
// (TESSERA_DB_APP, usually tessera_app: LOGIN NOSUPERUSER NOBYPASSRLS, owns
// nothing, not a member of the owner), so row-level security binds it. There
// is no SET ROLE: a role change is reversible, so SQL running as the app
// could have returned to the owner. CheckAppRole refuses a request pool whose
// session_user could do that.

// pgSetTenant and pgSetLookup are the only statements that set the session
// variables row-level security reads. They are constants, take one parameter
// and contain no dollar-quoted string (TestPostgresStatementsNoDollarQuotes).
const (
	pgSetTenant = `SELECT set_config('app.tenant_id', $1, true)`
	pgSetLookup = `SELECT set_config('app.lookup', $1, true)`
	// pgLockTenant serializes one tenant's write transactions until commit.
	pgLockTenant = `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`
)

// pgGooseTable is goose's bookkeeping table (listed in GlobalTables).
const pgGooseTable = "schema_migrations"

// parsePGDSN parses a Postgres DSN. The retired app_role option is refused: it
// made request connections owner logins that ran SET ROLE (#430).
func parsePGDSN(dsn string) (*pgx.ConnConfig, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, errors.New("store: invalid postgres DSN")
	}
	// ParseQuery, not u.Query(): the latter silently drops a malformed pair.
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, errors.New("store: invalid postgres DSN query")
	}
	if q.Has("app_role") {
		return nil, errors.New("store: the app_role DSN option is no longer supported (SET ROLE can be reversed); give the application its own login through TESSERA_DB_APP")
	}
	cfg, err := pgx.ParseConfig(u.String())
	if err != nil {
		// pgx errors can echo the DSN; do not leak a password.
		return nil, errors.New("store: invalid postgres DSN")
	}
	return cfg, nil
}

// AppOptions asks Open for a request pool of its own and checks it. Without
// it (Open, OpenFresh) a Postgres store serves from the owner pool unchecked:
// that is for operator commands, never for serving requests.
type AppOptions struct {
	// DSN is the application login's DSN (TESSERA_DB_APP). Empty makes the
	// owner pool the request pool, which CheckAppRole then refuses.
	DSN string
	// AllowPrivileged skips the CheckAppRole refusal (TESSERA_DEV_DB_ALLOW_PRIVILEGED_APP,
	// dev only; config refuses it in prod).
	AllowPrivileged bool
}

func openPostgres(ctx context.Context, dsn string, fresh bool, app *AppOptions) (*DB, error) {
	cfg, err := parsePGDSN(dsn)
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
	if app == nil {
		return d, nil
	}
	if app.DSN != "" {
		acfg, err := parsePGDSN(app.DSN)
		if err != nil {
			_ = owner.Close()
			return nil, fmt.Errorf("TESSERA_DB_APP: %w", err)
		}
		pool := stdlib.OpenDB(*acfg)
		pool.SetMaxOpenConns(16)
		if err := pool.PingContext(ctx); err != nil {
			_ = pool.Close()
			_ = owner.Close()
			return nil, errors.New("store: connect with TESSERA_DB_APP failed")
		}
		d.sql = pool
	}
	if err := d.CheckAppRole(ctx, app.AllowPrivileged); err != nil {
		_ = d.Close()
		return nil, err
	}
	return d, nil
}

// pgAppRoleFlags reads what the request pool's session_user is: a superuser
// (or a member of one), BYPASSRLS (or a member of such a role), an owner of a
// table in the schema, or a member of the role that owns the tenants table
// (which includes being that role).
const pgAppRoleFlags = `SELECT
	session_user::text,
	EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolsuper AND pg_has_role(session_user, r.oid, 'MEMBER')),
	EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolbypassrls AND pg_has_role(session_user, r.oid, 'MEMBER')),
	EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'p') AND pg_get_userbyid(c.relowner) = session_user),
	EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = current_schema() AND c.relname = 'tenants' AND pg_has_role(session_user, c.relowner, 'MEMBER'))`

// ErrAppRolePrivileged is returned when the request pool's login could undo
// row-level security.
var ErrAppRolePrivileged = errors.New("store: the request pool's database login is privileged")

// CheckAppRole refuses (unless allowPrivileged) a request pool whose
// session_user is a superuser, has BYPASSRLS, owns the schema's tables or is a
// member of the owner role: from any of those, SQL running as the application
// could step around row-level security and the audit guards (#430). SQLite has
// one login and passes.
func (d *DB) CheckAppRole(ctx context.Context, allowPrivileged bool) error {
	if d.d != dialectPostgres {
		return nil
	}
	var user string
	var super, bypass, owns, member bool
	if err := d.sql.QueryRowContext(ctx, pgAppRoleFlags).Scan(&user, &super, &bypass, &owns, &member); err != nil {
		return fmt.Errorf("store: check the request pool's role: %w", err)
	}
	var bad []string
	for _, c := range []struct {
		on   bool
		what string
	}{{super, "is a superuser"}, {bypass, "has BYPASSRLS"}, {owns, "owns tables in the schema"}, {member, "is a member of the schema owner role"}} {
		if c.on {
			bad = append(bad, c.what)
		}
	}
	if len(bad) == 0 || allowPrivileged {
		return nil
	}
	return fmt.Errorf("%w: %q %s; connect requests as a LOGIN NOSUPERUSER NOBYPASSRLS role that owns nothing (TESSERA_DB_APP)",
		ErrAppRolePrivileged, user, strings.Join(bad, ", "))
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
