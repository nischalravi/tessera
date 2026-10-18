package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Tests of the prepared-statement cache (stmt.go). Most use ad-hoc SQL on the
// global tenants table through DB.queryIn so they exercise the cache alone;
// the isolation test goes through the real TenantTx path.

// openCold opens a database with an empty statement cache: Open and Migrate
// prepare a few statements of their own, which these tests must not count.
func openCold(t *testing.T) *DB {
	t.Helper()
	d := openTest(t)
	d.stmts.close()
	d.stmts.prepares.Store(0)
	return d
}

func cachedCount(d *DB) int {
	d.stmts.mu.Lock()
	defer d.stmts.mu.Unlock()
	return len(d.stmts.m)
}

// countVia runs query (which returns one integer) in a fresh read transaction.
func countVia(ctx context.Context, d *DB, query string, args ...any) (int, error) {
	tx, err := d.sql.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	return countIn(ctx, d, tx, query, args...)
}

func countIn(ctx context.Context, d *DB, tx *sql.Tx, query string, args ...any) (int, error) {
	var n int
	err := d.queryRowIn(ctx, tx, query, args).Scan(&n)
	return n, err
}

func TestStmtCache_ConcurrentMissPreparesOnce(t *testing.T) {
	d := openCold(t)
	ctx := context.Background()
	const query = `SELECT count(*) FROM tenants WHERE id <> @x -- concurrent`
	const workers = 6 // fewer than the pool, so every miss can prepare

	var ready, start, done sync.WaitGroup
	ready.Add(workers)
	start.Add(1)
	errs := make(chan error, workers)
	for range workers {
		done.Add(1)
		go func() {
			defer done.Done()
			ready.Done()
			start.Wait()
			n, err := countVia(ctx, d, query, sql.Named("x", "none"))
			if err == nil && n < 1 {
				err = fmt.Errorf("count = %d, want at least the platform tenant", n)
			}
			errs <- err
		}()
	}
	ready.Wait()
	start.Done()
	done.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if got := d.stmts.prepares.Load(); got != 1 {
		t.Errorf("statement prepared %d times, want 1", got)
	}
	if got := cachedCount(d); got != 1 {
		t.Errorf("cache holds %d statements, want 1", got)
	}
}

func TestStmtCache_PoolExhaustedFallsBackUncached(t *testing.T) {
	d := openCold(t)
	ctx := context.Background()
	d.sql.SetMaxOpenConns(2)
	const query = `SELECT count(*) FROM tenants WHERE id <> @x -- exhausted`

	var held []*sql.Tx
	for range 2 {
		tx, err := d.sql.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, tx)
	}
	release := func() {
		for _, tx := range held {
			_ = tx.Rollback()
		}
		held = nil
	}
	defer release()

	type result struct {
		n   int
		err error
		dur time.Duration
	}
	res := make(chan result, 1)
	go func() {
		begin := time.Now()
		n, err := countIn(ctx, d, held[0], query, sql.Named("x", "none"))
		res <- result{n, err, time.Since(begin)}
	}()
	select {
	case r := <-res:
		if r.err != nil || r.n < 1 {
			t.Fatalf("uncached fallback: n=%d err=%v", r.n, r.err)
		}
		if r.dur < prepareWait/2 || r.dur > 10*prepareWait {
			t.Errorf("fallback took %v, want about %v", r.dur, prepareWait)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("deadlock: query did not finish with the pool exhausted")
	}
	if got := cachedCount(d); got != 0 {
		t.Errorf("cache holds %d statements after a failed prepare, want 0", got)
	}

	// With connections free again, the next call prepares and caches.
	release()
	if n, err := countVia(ctx, d, query, sql.Named("x", "none")); err != nil || n < 1 {
		t.Fatalf("after release: n=%d err=%v", n, err)
	}
	if got := cachedCount(d); got != 1 {
		t.Errorf("cache holds %d statements after release, want 1", got)
	}
}

func TestStmtCache_Cancellation(t *testing.T) {
	d := openTest(t)
	live := context.Background()
	const query = `SELECT count(*) FROM tenants WHERE id <> @x -- cancelled`

	tests := []struct {
		name string
		run  func(ctx context.Context, tx *sql.Tx) error
	}{
		{"query", func(ctx context.Context, tx *sql.Tx) error {
			rows, err := d.queryIn(ctx, tx, query, []any{sql.Named("x", "none")})
			if err == nil {
				_ = rows.Close()
			}
			return err
		}},
		{"exec", func(ctx context.Context, tx *sql.Tx) error {
			_, err := d.execIn(ctx, tx, `UPDATE tenants SET name = name WHERE id = @x -- cancelled`, []any{sql.Named("x", "none")})
			return err
		}},
		{"queryRow", func(ctx context.Context, tx *sql.Tx) error {
			var n int
			return d.queryRowIn(ctx, tx, query, []any{sql.Named("x", "none")}).Scan(&n)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tx, err := d.sql.BeginTx(live, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback() }()
			ctx, cancel := context.WithCancel(live)
			cancel()
			if err := tc.run(ctx, tx); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled context: err = %v, want context.Canceled", err)
			}
			// Whatever was cached must be usable with a live context.
			if err := tc.run(live, tx); err != nil {
				t.Fatalf("live context after cancellation: %v", err)
			}
		})
	}

	// A cancelled context never leaves a broken statement behind: every
	// cached statement works on a fresh transaction.
	n, err := countVia(live, d, query, sql.Named("x", "none"))
	if err != nil || n < 1 {
		t.Fatalf("fresh transaction: n=%d err=%v", n, err)
	}
}

func TestStmtCache_CancelledDuringPrepareIsNotCached(t *testing.T) {
	d := openCold(t)
	const query = `SELECT count(*) FROM tenants WHERE id <> @x -- prepare-cancel`
	tx, err := d.sql.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// The prepare ignores the caller's cancellation (WithoutCancel), so the
	// cached statement is valid; the execute is what reports the error.
	if _, err := countIn(ctx, d, tx, query, sql.Named("x", "none")); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if n, err := countIn(context.Background(), d, tx, query, sql.Named("x", "none")); err != nil || n < 1 {
		t.Fatalf("live call: n=%d err=%v", n, err)
	}
	if got := d.stmts.prepares.Load(); got != 1 {
		t.Errorf("prepared %d times, want 1 (the second call must hit the cache)", got)
	}
}

func TestStmtCache_InvalidSQLIsNotCached(t *testing.T) {
	d := openCold(t)
	ctx := context.Background()
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := countIn(ctx, d, tx, `SELECT nope FROM no_such_table`); err == nil {
		t.Fatal("want the SQL error from the uncached path")
	}
	if got := cachedCount(d); got != 0 {
		t.Errorf("cache holds %d statements, want 0", got)
	}
}

func TestStmtCache_CapRunsUncachedAndCorrect(t *testing.T) {
	d := openCold(t)
	ctx := context.Background()
	old := maxCachedStmts
	maxCachedStmts = 3
	t.Cleanup(func() { maxCachedStmts = old })

	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	for i := range 10 {
		query := fmt.Sprintf(`SELECT %d + @x -- cap %d`, i, i)
		var got int
		if err := d.queryRowIn(ctx, tx, query, []any{sql.Named("x", 100)}).Scan(&got); err != nil {
			t.Fatalf("statement %d: %v", i, err)
		}
		if want := 100 + i; got != want {
			t.Errorf("statement %d = %d, want %d", i, got, want)
		}
	}
	if got := cachedCount(d); got != 3 {
		t.Errorf("cache holds %d statements, want the cap of 3", got)
	}
	if got := d.stmts.prepares.Load(); got != 3 {
		t.Errorf("prepared %d statements, want 3: beyond the cap nothing is prepared on the pool", got)
	}
}

func TestStmtCache_CloseClosesEverything(t *testing.T) {
	d, err := Open(context.Background(), t.TempDir()+"/close.db")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	d.stmts.close()
	for i := range 4 {
		if _, err := countVia(ctx, d, fmt.Sprintf(`SELECT count(*) FROM tenants WHERE id <> @x -- close %d`, i), sql.Named("x", "none")); err != nil {
			t.Fatal(err)
		}
	}
	d.stmts.mu.Lock()
	var cached []*sql.Stmt
	for _, st := range d.stmts.m {
		cached = append(cached, st)
	}
	d.stmts.mu.Unlock()
	if len(cached) != 4 {
		t.Fatalf("cache holds %d statements, want 4", len(cached))
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if got := cachedCount(d); got != 0 {
		t.Errorf("cache holds %d statements after Close, want 0", got)
	}
	if open := d.sql.Stats().OpenConnections; open != 0 {
		t.Errorf("%d connections open after Close, want 0", open)
	}
	for i, st := range cached {
		if _, err := st.QueryContext(ctx, sql.Named("x", "none")); err == nil {
			t.Errorf("statement %d still usable after Close", i)
		}
	}
}

func TestStmtCache_TenantIsolationThroughCache(t *testing.T) {
	d := openTest(t)
	ctx := context.Background()
	ids := map[string]tenancy.ID{}
	for _, slug := range []string{"tenant-a", "tenant-b"} {
		if err := d.InSystem(ctx, "test", func(s *SystemTx) error {
			tn, err := s.CreateTenant(Tenant{Slug: slug, Name: slug})
			ids[slug] = tn.ID
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	seed := map[string][]string{"tenant-a": {"a1", "a2", "a3"}, "tenant-b": {"b1"}}
	for slug, xids := range seed {
		if err := d.InTenant(ctx, ids[slug], func(tx *TenantTx) error {
			for _, x := range xids {
				if _, err := tx.InsertIdentity(&Identity{ExternalID: x, Name: x, Type: "human", Status: "active"}); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}

	for _, slug := range []string{"tenant-a", "tenant-b", "tenant-a", "tenant-b", "tenant-a"} {
		err := d.ReadTenant(ctx, ids[slug], func(tx *TenantTx) error {
			got, err := tx.Identities()
			if err != nil {
				return err
			}
			if len(got) != len(seed[slug]) {
				return fmt.Errorf("%s: %d identities, want %d", slug, len(got), len(seed[slug]))
			}
			for i, id := range got {
				if id.TenantID != ids[slug] || id.ExternalID != seed[slug][i] {
					return fmt.Errorf("%s: row %q of tenant %s", slug, id.ExternalID, id.TenantID)
				}
			}
			// The same statement text is cached, yet a lookup by id of another
			// tenant's row finds nothing.
			other := "tenant-a"
			if slug == other {
				other = "tenant-b"
			}
			var otherID int64
			if err := d.ReadTenant(ctx, ids[other], func(o *TenantTx) error {
				rows, err := o.Identities()
				if err == nil {
					otherID = rows[0].ID
				}
				return err
			}); err != nil {
				return err
			}
			if x, err := tx.Identity(otherID); err == nil && x != nil && x.TenantID != ids[slug] {
				return fmt.Errorf("%s read %s's identity %d", slug, other, otherID)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if d.stmts.prepares.Load() == 0 || cachedCount(d) == 0 {
		t.Error("expected the statements to have gone through the cache")
	}
}
