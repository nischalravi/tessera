// Package store is Tessera's persistence layer and THE ONLY package that may
// import database/sql or a database driver (enforced by internal/archtest).
//
// Graph shape (node kinds):
//
//	Identity --has--> Account --member_of--> Group/Role --maps_to--> Group/Role
//	                          \--direct_grant--> Permission --on--> Resource
//	Group/Role --grants--> Permission
//
// Identity->Account and Permission->Resource are foreign keys; every other
// relationship is a row in grant_edges, which is what revocation, JIT and
// simulation operate on.
//
// Tenant isolation (docs/design/phase-0-platform-security.md §14):
//
//   - Every table except the GlobalTables allowlist has tenant_id.
//   - Tenant-owned tables are reachable only through a *TenantTx, which only
//     DB.InTenant / DB.ReadTenant / DB.ForEachActiveTenant can create, never
//     with the zero tenancy.ID. Repository methods take no tenant argument.
//   - Every statement is a registered constant (tq for tenant statements, sq
//     for system statements). The executor binds @tenant itself and refuses a
//     caller-supplied "tenant" argument. isolation_test.go lints every
//     registered statement.
//
// Timestamps are naive UTC stored as sortable text ("YYYY-MM-DD HH:MM:SS.ffffff").
// Existing primary keys are plain INTEGER PRIMARY KEY (rowid), global across
// tenants; another tenant's id is indistinguishable from a missing one.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"slices"
	"sync"

	_ "modernc.org/sqlite" // pure-Go SQLite driver

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

var (
	// ErrNoTenant is returned when a tenant transaction is requested without a
	// tenant (the zero tenancy.ID) or for a tenant that does not exist. It
	// fails closed.
	ErrNoTenant = errors.New("store: tenant context missing")
	// ErrCrossTenant is returned when a caller tries to supply the tenant
	// itself or passes a row that belongs to another tenant.
	ErrCrossTenant = errors.New("store: cross-tenant access")
	// ErrNotFound is returned by single-row getters when the row does not
	// exist, including when it belongs to another tenant.
	ErrNotFound = errors.New("store: not found")
	// ErrReadOnly is returned by a write through a ReadTenant transaction.
	ErrReadOnly = errors.New("store: write in a read-only transaction")
	// ErrLegacySchema is returned by Open for a database created before
	// tenancy; reseed it (./run.sh --reseed or tessera seed).
	ErrLegacySchema = errors.New("store: database predates this server's schema (tenancy or sign-in); recreate it with `./run.sh --reseed` or `tessera seed` (both start from an empty schema)")
)

// GlobalTables are the only tables without tenant_id. The schema meta-test
// (TestIsolation_EveryTableScopedOrAllowlisted) enforces this list against
// the live schema. Tables listed here that do not exist yet arrive in later
// Phase 0 PRs.
var GlobalTables = []string{"tenants", "platform_keys", "replay_cache", "schema_migrations"}

//go:embed schema/*.sql
var schemaFS embed.FS

// tables in dependency order (parents first); Migrate(drop) drops them in reverse.
var tables = []string{
	"tenants", "platform_keys", "tenant_signing_keys", "identities", "accounts", "groups", "resources", "permissions", "grant_edges", "secrets",
	"agent_delegations", "usage_events", "access_requests", "review_campaigns", "review_items",
	"hris_events",
	// auth core (schema/0005_auth.sql)
	"idp_connections", "platform_users", "external_logins", "role_assignments", "authn_contexts", "sessions",
	"login_transactions",
	// audit ledger (schema/0004_audit.sql)
	"audit_events", "audit_chain_heads", "audit_checkpoints",
	// deployment readiness (schema/0201-0203)
	"connections", "connection_revisions", "readiness_check_runs", "readiness_item_states", "readiness_attestations",
	"readiness_skips", "readiness_overlays", "readiness_check_results", "recon_runs", "recon_findings", "readiness_scores",
	"stg_identities", "stg_accounts", "stg_groups", "stg_memberships", "stg_attr_stats",
	// job run history (schema/0212_job_runs.sql)
	"job_runs",
	// closed-loop provisioning (schema/0224-0225)
	"provisioning_targets", "provisioning_ops", "provisioning_findings",
}

// legacyTables are tables of older schemas that a reseed drops: audit_log was
// the mutable audit table before the hash-chained ledger (PR3).
var legacyTables = []string{"audit_log"}

// DB owns the database handle. The *sql.DB is unexported and there is no
// accessor: no other package can obtain a *sql.DB, *sql.Tx or *sql.Conn.
//
// Writes are serialized through one mutex so SQLite never sees two concurrent
// writers; read-only tenant transactions (ReadTenant) run concurrently (WAL).
type DB struct {
	sql *sql.DB
	mu  sync.Mutex
}

// Open opens (creating if needed) the database at path and applies the schema.
// A database created before tenancy is refused with ErrLegacySchema.
func Open(ctx context.Context, path string) (*DB, error) { return open(ctx, path, false) }

// OpenFresh opens the database at path and drops every table before applying
// the schema, so seeding always starts empty. It works on a database left from
// an older schema (including one that predates tenancy) without deleting any
// file, so a mistyped path can never destroy something that is not ours.
func OpenFresh(ctx context.Context, path string) (*DB, error) { return open(ctx, path, true) }

func open(ctx context.Context, path string, fresh bool) (*DB, error) {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(NORMAL)")
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	db.SetMaxOpenConns(8)
	d := &DB{sql: db}
	if err := d.Migrate(ctx, fresh); err != nil {
		_ = db.Close()
		return nil, err
	}
	return d, nil
}

// Close closes the database.
func (d *DB) Close() error { return d.sql.Close() }

// Checkpoint truncates the write-ahead log into the main database file, so the
// file can be copied on its own (test fixtures).
func (d *DB) Checkpoint(ctx context.Context) error {
	_, err := d.sql.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	return err
}

// Migrate creates the schema and the reserved _platform tenant; drop=true
// drops every table first (reseed). A database created before tenancy is
// refused with ErrLegacySchema unless drop is set.
func (d *DB) Migrate(ctx context.Context, drop bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if drop {
		rev := slices.Clone(tables)
		slices.Reverse(rev)
		for _, t := range slices.Concat(legacyTables, rev) {
			// t comes from the fixed list above, never from input.
			if _, err := d.sql.ExecContext(ctx, "DROP TABLE IF EXISTS "+t); err != nil { // #nosec G202 -- fixed table names
				return fmt.Errorf("store: drop %s: %w", t, err)
			}
		}
	} else if legacy, err := d.legacySchema(ctx); err != nil {
		return err
	} else if legacy {
		return ErrLegacySchema
	}
	files, err := fs.Glob(schemaFS, "schema/*.sql")
	if err != nil {
		return err
	}
	slices.Sort(files)
	for _, f := range files {
		ddl, err := schemaFS.ReadFile(f)
		if err != nil {
			return err
		}
		if _, err := d.sql.ExecContext(ctx, string(ddl)); err != nil {
			return fmt.Errorf("store: schema %s: %w", f, err)
		}
	}
	return d.inSystemLocked(ctx, "migrate: ensure _platform tenant", func(s *SystemTx) error {
		_, err := s.exec(tenantsEnsurePlatform, sql.Named("id", tenancy.Platform.String()),
			sql.Named("created_at", T(nowUTC())))
		return err
	})
}

// legacySchema reports whether the database was created by an older server:
// identities without tenant_id (before tenancy), or access_requests without
// requested_by_user_id (before sign-in, PR5). CREATE TABLE IF NOT EXISTS
// cannot add those columns, and the old rows have no platform users.
func (d *DB) legacySchema(ctx context.Context) (bool, error) {
	for _, c := range []struct{ table, column string }{
		{"identities", "tenant_id"}, {"access_requests", "requested_by_user_id"},
	} {
		var exists, n int
		if err := d.sql.QueryRowContext(ctx,
			`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, c.table).Scan(&exists); err != nil {
			return false, err
		}
		if err := d.sql.QueryRowContext(ctx,
			`SELECT count(*) FROM pragma_table_info(?) WHERE name = ?`, c.table, c.column).Scan(&n); err != nil {
			return false, err
		}
		if exists == 1 && n == 0 {
			return true, nil
		}
	}
	return false, nil
}

// InTenant runs fn in one write transaction scoped to t. A zero tenancy.ID or
// an unknown tenant returns ErrNoTenant (and a zero id also records a
// tenancy.context_missing event in the _platform tenant). fn's error, or a
// panic, rolls the transaction back.
func (d *DB) InTenant(ctx context.Context, t tenancy.ID, fn func(*TenantTx) error) error {
	if t.IsZero() {
		d.RecordContextMissing(ctx, "store.InTenant called with the zero tenant id")
		return ErrNoTenant
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.inTenant(ctx, t, false, fn)
}

// ReadTenant runs fn in one read-only transaction scoped to t: a consistent
// snapshot that runs concurrently with other readers. Writes through it fail
// with ErrReadOnly. Do not start another transaction inside fn.
func (d *DB) ReadTenant(ctx context.Context, t tenancy.ID, fn func(*TenantTx) error) error {
	if t.IsZero() {
		d.RecordContextMissing(ctx, "store.ReadTenant called with the zero tenant id")
		return ErrNoTenant
	}
	return d.inTenant(ctx, t, true, fn)
}

func (d *DB) inTenant(ctx context.Context, t tenancy.ID, readOnly bool, fn func(*TenantTx) error) (err error) {
	sqltx, err := d.sql.BeginTx(ctx, &sql.TxOptions{ReadOnly: readOnly})
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	ttx := &TenantTx{ctx: ctx, tx: sqltx, tenant: t, readOnly: readOnly}
	defer func() {
		if p := recover(); p != nil {
			_ = sqltx.Rollback()
			panic(p)
		}
		if err != nil {
			_ = sqltx.Rollback()
			return
		}
		if err = sqltx.Commit(); err == nil && ttx.appended > 0 {
			if ac, ok := AuditContextFrom(ctx); ok && ac.Committed != nil {
				ac.Committed.Add(ttx.appended)
			}
		}
	}()
	// The tenant must exist: every tenant_id this transaction writes then
	// references a tenants row (SQLite foreign keys are not enforced yet).
	var n int
	if err := sqltx.QueryRowContext(ctx, tenantsExists.sql, sql.Named("id", t.String())).Scan(&n); err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("%w: unknown tenant %s", ErrNoTenant, t)
	}
	return fn(ttx)
}

// InSystem runs fn in one write transaction that can touch only the
// GlobalTables. reason says why (it is for logs and audit later; it must not
// be empty).
func (d *DB) InSystem(ctx context.Context, reason string, fn func(*SystemTx) error) error {
	if reason == "" {
		return errors.New("store: InSystem needs a reason")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.inSystemLocked(ctx, reason, fn)
}

func (d *DB) inSystemLocked(ctx context.Context, reason string, fn func(*SystemTx) error) (err error) {
	sqltx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = sqltx.Rollback()
			panic(p)
		}
		if err != nil {
			_ = sqltx.Rollback()
			return
		}
		err = sqltx.Commit()
	}()
	return fn(&SystemTx{ctx: ctx, tx: sqltx, reason: reason})
}

// ReadSystem runs fn in one read-only system transaction. It does not take
// the write lock, so the per-request session lookup (§14.2) runs concurrently
// with other readers. Writes through it fail.
func (d *DB) ReadSystem(ctx context.Context, reason string, fn func(*SystemTx) error) (err error) {
	if reason == "" {
		return errors.New("store: ReadSystem needs a reason")
	}
	sqltx, err := d.sql.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = sqltx.Rollback()
			panic(p)
		}
		if err != nil {
			_ = sqltx.Rollback()
			return
		}
		err = sqltx.Commit()
	}()
	return fn(&SystemTx{ctx: ctx, tx: sqltx, reason: reason})
}

// ForEachActiveTenant lists the active tenants (not _platform) in a SystemTx,
// then calls fn for each one inside its own InTenant transaction. An error in
// one tenant does not stop the others; all errors are returned joined.
// Background jobs use only this.
func (d *DB) ForEachActiveTenant(ctx context.Context, fn func(context.Context, *TenantTx) error) error {
	var active []Tenant
	if err := d.InSystem(ctx, "for each active tenant", func(s *SystemTx) error {
		var err error
		active, err = s.ActiveTenants()
		return err
	}); err != nil {
		return err
	}
	var errs []error
	for _, t := range active {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(errs, err)...)
		}
		if err := d.InTenant(ctx, t.ID, func(tx *TenantTx) error { return fn(ctx, tx) }); err != nil {
			errs = append(errs, fmt.Errorf("tenant %s: %w", t.Slug, err))
		}
	}
	return errors.Join(errs...)
}

// ActiveTenants lists the active tenants (not _platform), ordered by slug.
func (d *DB) ActiveTenants(ctx context.Context) ([]Tenant, error) {
	var out []Tenant
	err := d.InSystem(ctx, "list active tenants", func(s *SystemTx) error {
		var err error
		out, err = s.ActiveTenants()
		return err
	})
	return out, err
}

// RecordContextMissing writes a tenancy.context_missing event to the
// _platform tenant. It is best effort: it never fails the caller, who is
// already failing closed.
func (d *DB) RecordContextMissing(ctx context.Context, where string) {
	_ = d.InTenant(context.WithoutCancel(ctx), tenancy.Platform, func(tx *TenantTx) error {
		return tx.Audit(nowUTC(), "system", "tenancy.context_missing", detailWhere(where))
	})
}
