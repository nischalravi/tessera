// Package store is Tessera's SQLite persistence: schema, row types and
// parameterized queries (database/sql, no ORM).
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
// Timestamps are naive UTC stored as sortable text ("YYYY-MM-DD HH:MM:SS.ffffff").
// Primary keys are plain INTEGER PRIMARY KEY (rowid), so ids are max(id)+1.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"sync"

	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

// Querier is satisfied by *sql.DB and *sql.Tx.
type Querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Conn binds a Querier to a context. Every domain function takes a *Conn.
type Conn struct {
	Ctx context.Context
	Q   Querier
}

// Exec runs a statement.
func (c *Conn) Exec(query string, args ...any) (sql.Result, error) {
	return c.Q.ExecContext(c.Ctx, query, args...)
}

// Query runs a query.
func (c *Conn) Query(query string, args ...any) (*sql.Rows, error) {
	return c.Q.QueryContext(c.Ctx, query, args...)
}

// QueryRow runs a single-row query.
func (c *Conn) QueryRow(query string, args ...any) *sql.Row {
	return c.Q.QueryRowContext(c.Ctx, query, args...)
}

// Insert runs an INSERT and returns the new row id.
func (c *Conn) Insert(query string, args ...any) (int64, error) {
	res, err := c.Exec(query, args...)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Count runs a COUNT-style query returning one integer.
func (c *Conn) Count(query string, args ...any) (int, error) {
	var n sql.NullInt64
	err := c.QueryRow(query, args...).Scan(&n)
	return int(n.Int64), err
}

// Store owns the database handle. Writes are serialized through one mutex so
// SQLite never sees two concurrent writers; reads run concurrently (WAL).
type Store struct {
	DB *sql.DB
	mu sync.Mutex
}

// Open opens (creating if needed) the database at path and applies the schema.
func Open(ctx context.Context, path string) (*Store, error) {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(NORMAL)")
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	db.SetMaxOpenConns(8)
	s := &Store{DB: db}
	if err := s.Migrate(ctx, false); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.DB.Close() }

// Read gives fn a connection for reads.
func (s *Store) Read(ctx context.Context) *Conn { return &Conn{ctx, s.DB} }

// Write runs fn in a transaction while holding the write lock; fn's error
// rolls the transaction back.
func (s *Store) Write(ctx context.Context, fn func(*Conn) error) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
		if err != nil {
			_ = tx.Rollback()
			return
		}
		err = tx.Commit()
	}()
	return fn(&Conn{ctx, tx})
}

// Migrate creates the schema; drop=true drops every table first (reseed).
func (s *Store) Migrate(ctx context.Context, drop bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if drop {
		for i := len(tables) - 1; i >= 0; i-- {
			if _, err := s.DB.ExecContext(ctx, "DROP TABLE IF EXISTS "+tables[i]); err != nil {
				return fmt.Errorf("store: drop %s: %w", tables[i], err)
			}
		}
	}
	for _, stmt := range schema {
		if _, err := s.DB.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("store: schema: %w", err)
		}
	}
	return nil
}

// ErrNotFound is returned by single-row getters when the row does not exist.
var ErrNotFound = errors.New("store: not found")

var tables = []string{
	"identities", "accounts", "groups", "resources", "permissions", "grant_edges", "secrets",
	"agent_delegations", "usage_events", "access_requests", "review_campaigns", "review_items",
	"hris_events", "audit_log",
}

var schema = []string{
	`CREATE TABLE IF NOT EXISTS identities (
		id INTEGER PRIMARY KEY, external_id TEXT NOT NULL, name TEXT NOT NULL, email TEXT,
		type TEXT NOT NULL, department TEXT, title TEXT, status TEXT NOT NULL, manager_id INTEGER,
		owner_id INTEGER, source TEXT, description TEXT, hired_at TEXT, terminated_at TEXT,
		created_at TEXT NOT NULL,
		FOREIGN KEY(manager_id) REFERENCES identities (id), FOREIGN KEY(owner_id) REFERENCES identities (id))`,
	`CREATE UNIQUE INDEX IF NOT EXISTS ix_identities_external_id ON identities (external_id)`,
	`CREATE INDEX IF NOT EXISTS ix_identities_email ON identities (email)`,
	`CREATE INDEX IF NOT EXISTS ix_identities_type ON identities (type)`,
	`CREATE TABLE IF NOT EXISTS accounts (
		id INTEGER PRIMARY KEY, system TEXT NOT NULL, external_id TEXT NOT NULL, identity_id INTEGER,
		username TEXT NOT NULL, kind TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT, last_login_at TEXT,
		UNIQUE (system, external_id), FOREIGN KEY(identity_id) REFERENCES identities (id))`,
	`CREATE INDEX IF NOT EXISTS ix_accounts_system ON accounts (system)`,
	`CREATE TABLE IF NOT EXISTS groups (
		id INTEGER PRIMARY KEY, system TEXT NOT NULL, external_id TEXT NOT NULL, name TEXT NOT NULL,
		kind TEXT NOT NULL, privileged INTEGER NOT NULL, requestable INTEGER NOT NULL, description TEXT,
		UNIQUE (system, external_id))`,
	`CREATE INDEX IF NOT EXISTS ix_groups_system ON groups (system)`,
	`CREATE TABLE IF NOT EXISTS resources (
		id INTEGER PRIMARY KEY, system TEXT NOT NULL, external_id TEXT NOT NULL, name TEXT NOT NULL,
		kind TEXT NOT NULL, environment TEXT, tags TEXT NOT NULL, UNIQUE (system, external_id))`,
	`CREATE INDEX IF NOT EXISTS ix_resources_system ON resources (system)`,
	`CREATE TABLE IF NOT EXISTS permissions (
		id INTEGER PRIMARY KEY, system TEXT NOT NULL, external_id TEXT NOT NULL, action TEXT NOT NULL,
		resource_id INTEGER NOT NULL, privileged INTEGER NOT NULL, UNIQUE (system, external_id),
		FOREIGN KEY(resource_id) REFERENCES resources (id))`,
	`CREATE INDEX IF NOT EXISTS ix_permissions_system ON permissions (system)`,
	`CREATE INDEX IF NOT EXISTS ix_permissions_action ON permissions (action)`,
	`CREATE TABLE IF NOT EXISTS grant_edges (
		id INTEGER PRIMARY KEY, src TEXT NOT NULL, dst TEXT NOT NULL, relation TEXT NOT NULL,
		source TEXT NOT NULL, expires_at TEXT, created_at TEXT NOT NULL, UNIQUE (src, dst))`,
	`CREATE INDEX IF NOT EXISTS ix_grant_edges_src ON grant_edges (src)`,
	`CREATE INDEX IF NOT EXISTS ix_grant_edges_dst ON grant_edges (dst)`,
	`CREATE TABLE IF NOT EXISTS secrets (
		id INTEGER PRIMARY KEY, system TEXT NOT NULL, external_id TEXT NOT NULL, account_id INTEGER NOT NULL,
		kind TEXT NOT NULL, name TEXT NOT NULL, created_at TEXT NOT NULL, last_rotated_at TEXT,
		last_used_at TEXT, status TEXT NOT NULL, UNIQUE (system, external_id),
		FOREIGN KEY(account_id) REFERENCES accounts (id))`,
	`CREATE TABLE IF NOT EXISTS agent_delegations (
		id INTEGER PRIMARY KEY, agent_id INTEGER NOT NULL, principal_id INTEGER NOT NULL, scopes TEXT NOT NULL,
		created_at TEXT NOT NULL, expires_at TEXT,
		FOREIGN KEY(agent_id) REFERENCES identities (id), FOREIGN KEY(principal_id) REFERENCES identities (id))`,
	`CREATE TABLE IF NOT EXISTS usage_events (
		id INTEGER PRIMARY KEY, identity_id INTEGER NOT NULL, account_id INTEGER, permission_id INTEGER NOT NULL,
		day TEXT NOT NULL, count INTEGER NOT NULL,
		FOREIGN KEY(identity_id) REFERENCES identities (id), FOREIGN KEY(account_id) REFERENCES accounts (id),
		FOREIGN KEY(permission_id) REFERENCES permissions (id))`,
	`CREATE INDEX IF NOT EXISTS ix_usage_events_identity_id ON usage_events (identity_id)`,
	`CREATE INDEX IF NOT EXISTS ix_usage_events_permission_id ON usage_events (permission_id)`,
	`CREATE INDEX IF NOT EXISTS ix_usage_events_day ON usage_events (day)`,
	`CREATE TABLE IF NOT EXISTS access_requests (
		id INTEGER PRIMARY KEY, identity_id INTEGER NOT NULL, account_id INTEGER NOT NULL, group_id INTEGER NOT NULL,
		justification TEXT NOT NULL, duration_hours REAL NOT NULL, status TEXT NOT NULL, requested_at TEXT NOT NULL,
		decided_at TEXT, decided_by TEXT, expires_at TEXT, edge_id INTEGER,
		FOREIGN KEY(identity_id) REFERENCES identities (id), FOREIGN KEY(account_id) REFERENCES accounts (id),
		FOREIGN KEY(group_id) REFERENCES groups (id))`,
	`CREATE TABLE IF NOT EXISTS review_campaigns (
		id INTEGER PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL, status TEXT NOT NULL,
		unused_days INTEGER NOT NULL, total_grants INTEGER NOT NULL, auto_certified INTEGER NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS review_items (
		id INTEGER PRIMARY KEY, campaign_id INTEGER NOT NULL, identity_id INTEGER NOT NULL, edge_id INTEGER,
		edge_src TEXT NOT NULL, edge_dst TEXT NOT NULL, grant_label TEXT NOT NULL, reasons TEXT NOT NULL,
		context TEXT NOT NULL, reviewer_id INTEGER, decision TEXT, comment TEXT, decided_at TEXT,
		FOREIGN KEY(campaign_id) REFERENCES review_campaigns (id), FOREIGN KEY(identity_id) REFERENCES identities (id),
		FOREIGN KEY(reviewer_id) REFERENCES identities (id))`,
	`CREATE TABLE IF NOT EXISTS hris_events (
		id INTEGER PRIMARY KEY, external_id TEXT NOT NULL, type TEXT NOT NULL, identity_id INTEGER,
		payload TEXT NOT NULL, effective_at TEXT NOT NULL, status TEXT NOT NULL, executed_at TEXT,
		UNIQUE (external_id), FOREIGN KEY(identity_id) REFERENCES identities (id))`,
	`CREATE TABLE IF NOT EXISTS audit_log (
		id INTEGER PRIMARY KEY, at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL)`,
}
