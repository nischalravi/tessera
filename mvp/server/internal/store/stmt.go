package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// tstmt is a statement on tenant-owned tables. Its SQL uses only named
// parameters, and every tenant table it names is filtered (or, for INSERT,
// stamped) with the parameter @tenant, which only TenantTx binds.
type tstmt struct{ name, sql string }

// sstmt is a system statement: it may touch only the GlobalTables.
type sstmt struct{ name, sql string }

// lstmt is one of the two hash lookups of design §14.2, the only reads of a
// tenant table outside a TenantTx: SELECT tenant_id, id FROM <table> WHERE
// <unique hash column> = @hash (GlobalHashLookups). They run on a SystemTx
// and return just enough to open the right tenant transaction.
type lstmt struct{ name, sql string }

type registered struct {
	name, sql string
	system    bool
	lookup    bool
}

// statements is every SQL statement the store runs (besides schema DDL and
// the PRAGMAs in db.go), keyed by name. isolation_test.go lints each one.
var statements = map[string]registered{}

func register(name, sql string, system, lookup bool) {
	if _, dup := statements[name]; dup {
		panic(fmt.Sprintf("store: duplicate statement name %q", name))
	}
	statements[name] = registered{name, strings.TrimSpace(sql), system, lookup}
}

// tq declares a tenant statement. Call it only from package-level var blocks.
func tq(name, sql string) tstmt {
	register(name, sql, false, false)
	return tstmt{name, strings.TrimSpace(sql)}
}

// sq declares a system statement. Call it only from package-level var blocks.
func sq(name, sql string) sstmt {
	register(name, sql, true, false)
	return sstmt{name, strings.TrimSpace(sql)}
}

// maxCachedStmts bounds the prepared-statement cache. Every statement is a
// package-level constant (see register), so the bound is only a backstop
// against a statement built at run time.
// It is a variable only so a test can lower it.
var maxCachedStmts = 1024

// stmtCache holds one *sql.Stmt per distinct SQL text. database/sql prepares
// it lazily on each pooled connection and reuses it there, so SQLite parses a
// statement (and compiles its guard triggers) once per connection instead of
// once per call. A schema change makes SQLite re-prepare on its own.
// Binding is unchanged: arguments, including @tenant, are still supplied per
// call by TenantTx, and a cached statement carries no tenant of its own.
type stmtCache struct {
	mu sync.Mutex
	m  map[string]*sql.Stmt

	inflight map[string]*prepCall // statements being prepared right now

	prepares atomic.Int64 // PrepareContext calls, for tests
}

// prepCall is one prepare in progress; st is nil if it failed.
type prepCall struct {
	done chan struct{}
	st   *sql.Stmt
}

// prepareWait bounds how long the first use of a statement waits for a pooled
// connection to prepare it on. Transactions already hold connections, so with
// the pool exhausted an unbounded wait could deadlock; on timeout the call
// simply runs uncached and the next call tries again.
const prepareWait = 200 * time.Millisecond

// stmtFor returns tx's view of the cached statement for query, preparing it
// on first use. ok is false when the statement cannot be cached; the caller
// then runs query directly (which also surfaces any real SQL error).
func (d *DB) stmtFor(ctx context.Context, tx *sql.Tx, query string) (*sql.Stmt, bool) {
	c := &d.stmts
	c.mu.Lock()
	st, ok := c.m[query]
	if !ok {
		if len(c.m) >= maxCachedStmts {
			c.mu.Unlock()
			return nil, false
		}
		if call, busy := c.inflight[query]; busy {
			// Another caller is preparing this statement: wait for it (bounded
			// like a prepare) instead of preparing a duplicate.
			c.mu.Unlock()
			t := time.NewTimer(prepareWait)
			defer t.Stop()
			select {
			case <-call.done:
			case <-t.C:
				return nil, false
			case <-ctx.Done():
				return nil, false
			}
			if call.st == nil {
				return nil, false
			}
			return tx.StmtContext(ctx, call.st), true
		}
		call := &prepCall{done: make(chan struct{})}
		if c.inflight == nil {
			c.inflight = map[string]*prepCall{}
		}
		c.inflight[query] = call
		c.mu.Unlock()

		pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), prepareWait)
		defer cancel()
		c.prepares.Add(1)
		fresh, err := d.sql.PrepareContext(pctx, query)
		c.mu.Lock()
		delete(c.inflight, query)
		if err == nil {
			if c.m == nil {
				c.m = map[string]*sql.Stmt{}
			}
			c.m[query], call.st = fresh, fresh
		}
		c.mu.Unlock()
		close(call.done)
		if err != nil {
			return nil, false
		}
		st = fresh
	} else {
		c.mu.Unlock()
	}
	return tx.StmtContext(ctx, st), true
}

func (d *DB) execIn(ctx context.Context, tx *sql.Tx, query string, args []any) (sql.Result, error) {
	if st, ok := d.stmtFor(ctx, tx, query); ok {
		return st.ExecContext(ctx, args...)
	}
	return tx.ExecContext(ctx, query, args...)
}

func (d *DB) queryIn(ctx context.Context, tx *sql.Tx, query string, args []any) (*sql.Rows, error) {
	if st, ok := d.stmtFor(ctx, tx, query); ok {
		return st.QueryContext(ctx, args...)
	}
	return tx.QueryContext(ctx, query, args...)
}

func (d *DB) queryRowIn(ctx context.Context, tx *sql.Tx, query string, args []any) *sql.Row {
	if st, ok := d.stmtFor(ctx, tx, query); ok {
		return st.QueryRowContext(ctx, args...)
	}
	return tx.QueryRowContext(ctx, query, args...)
}

func (c *stmtCache) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, st := range c.m {
		_ = st.Close()
	}
	c.m = nil
}

// lq declares a hash lookup (see lstmt). Call it only from package-level var blocks.
func lq(name, sql string) lstmt {
	register(name, sql, true, true)
	return lstmt{name, strings.TrimSpace(sql)}
}

// GlobalHashLookups are the tenant-table columns that are unique across
// tenants and may be looked up before the tenant is known (design §14.2):
// bearer-secret hashes. The schema meta-test allows a unique index on exactly
// these columns not to start with tenant_id.
var GlobalHashLookups = map[string]string{"sessions": "secret_hash", "login_transactions": "cookie_hash"}
