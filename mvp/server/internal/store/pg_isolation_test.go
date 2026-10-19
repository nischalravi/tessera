package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Postgres row-level security, composite foreign keys and audit enforcement
// (design §14.3, §14.4, §13.8). These run only with TESSERA_TEST_PG_URL set
// (a failure with TESSERA_REQUIRE_PG_TESTS=1), against a fresh database opened
// the way production opens it: the migrations run as the URL's role, requests
// as tessera_app.

var (
	pgTenantA = tenancy.MustParse("00000000-0000-4000-8000-0000000000a1")
	pgTenantB = tenancy.MustParse("00000000-0000-4000-8000-0000000000b2")
)

// pgFixture is a Postgres store with tenants A and B, each with one identity,
// one account, one grant edge and one session, written through the owner pool
// (which bypasses row-level security), plus the ids.
type pgFixture struct {
	db       *DB
	identity map[tenancy.ID]int64
	edge     map[tenancy.ID]int64
}

func newPGFixture(t *testing.T) *pgFixture {
	t.Helper()
	PostgresForTest(t)
	ctx := context.Background()
	db, err := Open(ctx, TestTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if db.d != dialectPostgres || db.owner == db.sql {
		t.Fatal("expected a Postgres store with a separate application pool")
	}
	f := &pgFixture{db: db, identity: map[tenancy.ID]int64{}, edge: map[tenancy.ID]int64{}}
	const at = "2026-10-08 09:30:00.000000"
	for _, tn := range []struct {
		id   tenancy.ID
		slug string
	}{{pgTenantA, "tenant-a"}, {pgTenantB, "tenant-b"}} {
		if err := db.InSystem(ctx, "pg test", func(s *SystemTx) error {
			_, err := s.CreateTenant(Tenant{ID: tn.id, Slug: tn.slug, Name: tn.slug, CreatedAt: nowUTC()})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		var iid, aid, eid int64
		must := func(err error) {
			t.Helper()
			if err != nil {
				t.Fatal(err)
			}
		}
		must(db.owner.QueryRowContext(ctx, `INSERT INTO identities (tenant_id, external_id, name, type, status, created_at)
			VALUES ($1, 'e-1', $2, 'human', 'active', $3) RETURNING id`, tn.id.String(), "alice of "+tn.slug, at).Scan(&iid))
		must(db.owner.QueryRowContext(ctx, `INSERT INTO accounts (tenant_id, system, external_id, identity_id, username, kind, status)
			VALUES ($1, 'okta', 'a-1', $2, 'alice', 'human', 'active') RETURNING id`, tn.id.String(), iid).Scan(&aid))
		must(db.owner.QueryRowContext(ctx, `INSERT INTO grant_edges (tenant_id, src, dst, relation, source, created_at)
			VALUES ($1, 'identity:'||CAST($2 AS BIGINT)::text, 'account:'||CAST($3 AS BIGINT)::text, 'has', 'sync', $4) RETURNING id`, tn.id.String(), iid, aid, at).Scan(&eid))
		f.identity[tn.id], f.edge[tn.id] = iid, eid
		uid, ctx1 := "user-"+tn.slug, "ctx-"+tn.slug
		_, err := db.owner.ExecContext(ctx, `INSERT INTO platform_users (id, tenant_id, display_name, created_at) VALUES ($1, $2, 'U', $3)`, uid, tn.id.String(), at)
		must(err)
		_, err = db.owner.ExecContext(ctx, `INSERT INTO authn_contexts (id, tenant_id, user_id, protocol, purpose, aal, phishing_resistant,
			phr_basis, tessera_acr, auth_time, mapping_profile, mapping_version, claims_sha256, created_at)
			VALUES ($1, $2, $3, 'oidc', 'login', 1, 0, 'none', 'urn:tessera:acr:aal1', $4, 'p', 1, 'x', $4)`, ctx1, tn.id.String(), uid, at)
		must(err)
		_, err = db.owner.ExecContext(ctx, `INSERT INTO sessions (id, tenant_id, user_id, kind, secret_hash, csrf_secret,
			initial_authn_context_id, current_authn_context_id, created_at, last_activity_at, idle_expires_at, absolute_expires_at)
			VALUES ($1, $2, $3, 'browser', $4, 'csrf', $5, $5, $6, $6, $6, $6)`, map[tenancy.ID]string{pgTenantA: "5e55aaaa-0000-4000-8000-000000000001", pgTenantB: "5e55bbbb-0000-4000-8000-000000000002"}[tn.id], tn.id.String(), uid,
			strings.Repeat(map[tenancy.ID]string{pgTenantA: "a", pgTenantB: "b"}[tn.id], 64), ctx1, at)
		must(err)
	}
	return f
}

// asApp runs fn in a transaction on the application pool (tessera_app), with
// app.tenant_id set to tenant ("" leaves it unset) and always rolls back.
func (f *pgFixture) asApp(t *testing.T, tenant string, fn func(tx *sql.Tx)) {
	t.Helper()
	ctx := context.Background()
	tx, err := f.db.sql.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if tenant != "" {
		if _, err := tx.ExecContext(ctx, pgSetTenant, tenant); err != nil {
			t.Fatal(err)
		}
	}
	fn(tx)
}

func count(t *testing.T, tx *sql.Tx, q string, args ...any) int {
	t.Helper()
	var n int
	if err := tx.QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

// sqlState returns the SQLSTATE of a Postgres error ("" if none).
func sqlState(err error) string {
	var s interface{ SQLState() string }
	if errors.As(err, &s) {
		return s.SQLState()
	}
	return ""
}

// TestIsolation_PostgresRLS: as tessera_app, with no app.tenant_id no tenant
// table returns a row; with tenant A set only A's rows are visible and
// writable; a row of B cannot be inserted or moved under A; and a hand-written
// SELECT * (no repository, no tenant predicate) cannot bypass any of it.
func TestIsolation_PostgresRLS(t *testing.T) {
	f := newPGFixture(t)
	a, b := pgTenantA.String(), pgTenantB.String()

	t.Run("application role is not privileged", func(t *testing.T) {
		f.asApp(t, "", func(tx *sql.Tx) {
			var user string
			var super, bypass bool
			if err := tx.QueryRowContext(context.Background(), `SELECT current_user, r.rolsuper, r.rolbypassrls FROM pg_roles r WHERE r.rolname = current_user`).Scan(&user, &super, &bypass); err != nil {
				t.Fatal(err)
			}
			if user != "tessera_app" || super || bypass {
				t.Errorf("application role %s super=%t bypassrls=%t", user, super, bypass)
			}
			if n := count(t, tx, `SELECT count(*) FROM pg_tables WHERE tablename = 'identities' AND tableowner = current_user`); n != 0 {
				t.Error("tessera_app owns the tables")
			}
		})
	})

	t.Run("no tenant, no rows (fail closed)", func(t *testing.T) {
		tbls, err := PostgresTables()
		if err != nil {
			t.Fatal(err)
		}
		checked := 0
		f.asApp(t, "", func(tx *sql.Tx) {
			for _, tb := range tbls {
				if _, ok := tb.Column("tenant_id"); !ok || isGlobal(tb.Name) {
					continue
				}
				if n := count(t, tx, "SELECT count(*) FROM "+tb.Name); n != 0 { // #nosec G202 -- table names from the embedded schema
					t.Errorf("%s: %d rows visible with no tenant", tb.Name, n)
				}
				checked++
			}
		})
		if checked < 40 {
			t.Errorf("only %d tenant tables checked", checked)
		}
		// an empty setting (what a pooled connection shows after a transaction that set one) matches nothing either
		f.asApp(t, "", func(tx *sql.Tx) {
			if _, err := tx.ExecContext(context.Background(), pgSetTenant, ""); err != nil {
				t.Fatal(err)
			}
			if n := count(t, tx, `SELECT count(*) FROM identities`); n != 0 {
				t.Errorf("empty tenant setting shows %d identities", n)
			}
		})
	})

	t.Run("tenant set, only its rows", func(t *testing.T) {
		for _, tn := range []struct{ id, other string }{{a, b}, {b, a}} {
			f.asApp(t, tn.id, func(tx *sql.Tx) {
				for _, tbl := range []string{"identities", "accounts", "grant_edges", "platform_users", "authn_contexts", "sessions"} {
					if n := count(t, tx, "SELECT count(*) FROM "+tbl); n != 1 { // #nosec G202 -- fixed list
						t.Errorf("tenant %s sees %d rows of %s, want its own 1", tn.id[len(tn.id)-2:], n, tbl)
					}
					if n := count(t, tx, "SELECT count(*) FROM "+tbl+" WHERE tenant_id = $1", tn.other); n != 0 { // #nosec G202 -- fixed list
						t.Errorf("asking for the other tenant's %s returned %d rows", tbl, n)
					}
				}
				// a hand-written SELECT * without any predicate
				rows, err := tx.QueryContext(context.Background(), `SELECT * FROM identities`)
				if err != nil {
					t.Fatal(err)
				}
				defer rows.Close()
				cols, _ := rows.Columns()
				seen := 0
				for rows.Next() {
					vals := make([]any, len(cols))
					ptrs := make([]any, len(cols))
					for i := range vals {
						ptrs[i] = &vals[i]
					}
					if err := rows.Scan(ptrs...); err != nil {
						t.Fatal(err)
					}
					for i, c := range cols {
						if c == "tenant_id" && vals[i] != tn.id {
							t.Errorf("SELECT * returned a row of tenant %v", vals[i])
						}
					}
					seen++
				}
				if seen != 1 {
					t.Errorf("SELECT * returned %d rows", seen)
				}
			})
		}
	})

	t.Run("cannot write another tenant's rows", func(t *testing.T) {
		f.asApp(t, a, func(tx *sql.Tx) {
			_, err := tx.ExecContext(context.Background(), `INSERT INTO identities (tenant_id, external_id, name, type, status, created_at)
				VALUES ($1, 'x', 'intruder', 'human', 'active', 'z')`, b)
			if sqlState(err) != "42501" {
				t.Errorf("insert of a B row under A: %v (want a row-level security violation)", err)
			}
		})
		f.asApp(t, a, func(tx *sql.Tx) {
			_, err := tx.ExecContext(context.Background(), `UPDATE identities SET tenant_id = $1`, b)
			if sqlState(err) != "42501" {
				t.Errorf("moving A's row to B: %v (want a row-level security violation)", err)
			}
		})
		f.asApp(t, a, func(tx *sql.Tx) {
			for _, q := range []string{`UPDATE identities SET name = 'pwned' WHERE tenant_id = $1`, `DELETE FROM identities WHERE tenant_id = $1`} {
				res, err := tx.ExecContext(context.Background(), q, b)
				if err != nil {
					t.Fatal(err)
				}
				if n, _ := res.RowsAffected(); n != 0 {
					t.Errorf("%s under A touched %d of B's rows", q, n)
				}
			}
		})
		var name string
		if err := f.db.owner.QueryRowContext(context.Background(), `SELECT name FROM identities WHERE tenant_id = $1`, b).Scan(&name); err != nil || name != "alice of tenant-b" {
			t.Errorf("B's identity after the attempts: %q %v", name, err)
		}
	})

	t.Run("setting is transaction-local", func(t *testing.T) {
		ctx := context.Background()
		if err := f.db.InTenant(ctx, pgTenantA, func(tx *TenantTx) error {
			var got string
			if err := tx.tx.QueryRowContext(ctx, `SELECT current_setting('app.tenant_id', true)`).Scan(&got); err != nil {
				return err
			}
			if got != a {
				t.Errorf("inside InTenant app.tenant_id = %q", got)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		f.asApp(t, "", func(tx *sql.Tx) {
			var got sql.NullString
			if err := tx.QueryRowContext(ctx, `SELECT current_setting('app.tenant_id', true)`).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got.String != "" {
				t.Errorf("app.tenant_id %q leaked into the next transaction of the pool", got.String)
			}
		})
	})

	t.Run("hash lookup policy", func(t *testing.T) {
		hashA := strings.Repeat("a", 64)
		// without app.lookup the lookup finds nothing
		f.asApp(t, "", func(tx *sql.Tx) {
			if n := count(t, tx, `SELECT count(*) FROM sessions WHERE secret_hash = $1`, hashA); n != 0 {
				t.Errorf("unscoped lookup found %d sessions", n)
			}
			if _, err := tx.ExecContext(context.Background(), pgSetLookup, "session_hash"); err != nil {
				t.Fatal(err)
			}
			if n := count(t, tx, `SELECT count(*) FROM sessions WHERE secret_hash = $1`, hashA); n != 1 {
				t.Errorf("lookup by hash found %d sessions, want 1", n)
			}
			// the lookup setting opens sessions only, and only for SELECT
			if n := count(t, tx, `SELECT count(*) FROM identities`); n != 0 {
				t.Errorf("app.lookup opened %d identities", n)
			}
			if _, err := tx.ExecContext(context.Background(), `UPDATE sessions SET status = 'revoked'`); err != nil {
				t.Fatal(err)
			}
			if n := count(t, tx, `SELECT count(*) FROM sessions WHERE status = 'revoked'`); n != 0 {
				t.Errorf("app.lookup allowed an update of %d sessions", n)
			}
		})
		// the store's own lookup uses it
		if err := f.db.ReadSystem(context.Background(), "pg test", func(s *SystemTx) error {
			tid, _, err := s.lookup(sessionsLookup, "session_hash", hashA)
			if err == nil && tid != pgTenantA {
				t.Errorf("lookup resolved tenant %s", tid)
			}
			return err
		}); err != nil {
			t.Errorf("SystemTx lookup: %v", err)
		}
	})
}

// TestIsolation_PostgresEveryTableScopedOrAllowlisted is
// TestIsolation_EveryTableScopedOrAllowlisted on the live Postgres schema (design
// §14.4): every table is a GlobalTable or has tenant_id NOT NULL with a foreign
// key to tenants, row-level security enabled and forced, and every unique
// index other than a primary key leads with tenant_id (the two bearer-hash
// lookups excepted).
func TestIsolation_PostgresEveryTableScopedOrAllowlisted(t *testing.T) {
	f := newPGFixture(t)
	ctx := context.Background()
	rows, err := f.db.owner.QueryContext(ctx, `SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
			EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND a.attnotnull AND NOT a.attisdropped),
			EXISTS (SELECT 1 FROM pg_constraint k WHERE k.conrelid = c.oid AND k.contype = 'f' AND k.confrelid = 'tenants'::regclass
				AND k.conkey = ARRAY[(SELECT attnum FROM pg_attribute WHERE attrelid = c.oid AND attname = 'tenant_id')])
		FROM pg_class c WHERE c.relkind = 'r' AND c.relnamespace = current_schema()::regnamespace`)
	if err != nil {
		t.Fatal(err)
	}
	type tbl struct{ rls, force, scoped, fk bool }
	found := map[string]tbl{}
	for rows.Next() {
		var name string
		var x tbl
		if err := rows.Scan(&name, &x.rls, &x.force, &x.scoped, &x.fk); err != nil {
			t.Fatal(err)
		}
		found[name] = x
	}
	_ = rows.Close()
	for name, x := range found {
		if name == pgGooseTable {
			continue
		}
		if isGlobal(name) {
			if x.scoped || x.rls {
				t.Errorf("global table %s has tenant_id or row-level security", name)
			}
			continue
		}
		switch {
		case !x.scoped:
			t.Errorf("table %s has no tenant_id NOT NULL and is not in GlobalTables", name)
		case !x.fk:
			t.Errorf("table %s: tenant_id does not reference tenants", name)
		case !x.rls || !x.force:
			t.Errorf("table %s: row-level security enabled=%t forced=%t", name, x.rls, x.force)
		}
	}
	for _, g := range GlobalTables {
		if _, ok := found[g]; !ok {
			t.Errorf("GlobalTables names %s, which does not exist", g)
		}
	}
	// unique indexes lead with tenant_id
	irows, err := f.db.owner.QueryContext(ctx, `SELECT c.relname, i.relname, (SELECT a.attname FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attnum = x.indkey[0])
		FROM pg_index x JOIN pg_class c ON c.oid = x.indrelid JOIN pg_class i ON i.oid = x.indexrelid
		WHERE x.indisunique AND NOT x.indisprimary AND c.relnamespace = current_schema()::regnamespace`)
	if err != nil {
		t.Fatal(err)
	}
	defer irows.Close()
	for irows.Next() {
		var table, index string
		var first sql.NullString
		if err := irows.Scan(&table, &index, &first); err != nil {
			t.Fatal(err)
		}
		if table == pgGooseTable || isGlobal(table) || first.String == "tenant_id" {
			continue
		}
		if col, ok := GlobalHashLookups[table]; ok && first.String == col {
			continue
		}
		t.Errorf("unique index %s on %s starts with %q, not tenant_id", index, table, first.String)
	}
}

func isGlobal(name string) bool {
	for _, g := range GlobalTables {
		if g == name {
			return true
		}
	}
	return false
}

// TestIsolation_PostgresCompositeForeignKeys: the database itself refuses a
// reference into another tenant, whether or not row-level security would hide
// the target row (the key check bypasses it), and the text node keys and soft
// references have guard triggers.
func TestIsolation_PostgresCompositeForeignKeys(t *testing.T) {
	f := newPGFixture(t)
	a := pgTenantA.String()
	bID := f.identity[pgTenantB]
	for _, tc := range []struct {
		name, q string
		args    []any
		state   string
		msg     string
	}{
		{"account of A -> identity of B", `INSERT INTO accounts (tenant_id, system, external_id, identity_id, username, kind, status)
			VALUES ($1, 'okta', 'x', $2, 'x', 'human', 'active')`, []any{a, bID}, "23503", "foreign key"},
		{"identity of A managed by identity of B", `UPDATE identities SET manager_id = $2 WHERE tenant_id = $1`, []any{a, bID}, "23503", "foreign key"},
		{"grant edge of A -> node of B", `INSERT INTO grant_edges (tenant_id, src, dst, relation, source, created_at)
			VALUES ($1, 'identity:'||CAST($2 AS BIGINT)::text, 'group:1', 'member_of', 'sync', 'z')`, []any{a, bID}, "23000", "cross-tenant reference"},
		{"hris event of A -> identity of B", `INSERT INTO hris_events (tenant_id, external_id, type, identity_id, payload, effective_at, status)
			VALUES ($1, 'h', 'leaver', $2, '{}', 'z', 'pending')`, []any{a, bID}, "23000", "cross-tenant reference"},
		{"access request of A -> edge of B", `INSERT INTO access_requests (tenant_id, identity_id, account_id, group_id, justification,
			duration_hours, status, requested_at, edge_id)
			SELECT $1, i.id, ac.id, 0, 'j', 1, 'pending', 'z', $2 FROM identities i JOIN accounts ac ON ac.identity_id = i.id WHERE i.tenant_id = $1`,
			[]any{a, f.edge[pgTenantB]}, "23000", "cross-tenant reference"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.asApp(t, a, func(tx *sql.Tx) {
				_, err := tx.ExecContext(context.Background(), tc.q, tc.args...)
				if err == nil {
					t.Fatal("cross-tenant reference accepted")
				}
				if got := sqlState(err); tc.state != "23000" && got != tc.state {
					t.Errorf("SQLSTATE %s, want %s: %v", got, tc.state, err)
				}
				if !strings.Contains(err.Error(), tc.msg) {
					t.Errorf("error %v does not mention %q", err, tc.msg)
				}
			})
		})
	}
	// a request whose edge is gone is fine (a soft reference); one whose edge is B's is not
	t.Run("soft reference tolerates a missing row, refuses another tenant's", func(t *testing.T) {
		const ins = `INSERT INTO hris_events (tenant_id, external_id, type, identity_id, payload, effective_at, status)
			VALUES ($1, 'h', 'leaver', $2, '{}', 'z', 'pending')`
		f.asApp(t, a, func(tx *sql.Tx) {
			if _, err := tx.ExecContext(context.Background(), ins, a, int64(987654321)); err != nil {
				t.Errorf("event for an identity that does not exist: %v", err)
			}
		})
		f.asApp(t, a, func(tx *sql.Tx) {
			if _, err := tx.ExecContext(context.Background(), ins, a, f.identity[pgTenantA]); err != nil {
				t.Errorf("event for its own identity: %v", err)
			}
		})
	})
	// the store maps the refusal to ErrCrossTenant
	err := f.db.InTenant(context.Background(), pgTenantA, func(tx *TenantTx) error {
		_, err := tx.InsertAccount(&Account{System: "okta", ExternalID: "x", IdentityID: &bID, Username: "x", Kind: "human", Status: "active"})
		return err
	})
	if !errors.Is(err, ErrCrossTenant) {
		t.Errorf("store error %v, want ErrCrossTenant", err)
	}
	// ...and the transaction survives a refused statement, as it does on SQLite
	err = f.db.InTenant(context.Background(), pgTenantA, func(tx *TenantTx) error {
		if _, err := tx.InsertAccount(&Account{System: "okta", ExternalID: "x", IdentityID: &bID, Username: "x", Kind: "human", Status: "active"}); !errors.Is(err, ErrCrossTenant) {
			t.Errorf("refusal: %v", err)
		}
		own := f.identity[pgTenantA]
		_, err := tx.InsertAccount(&Account{System: "okta", ExternalID: "y", IdentityID: &own, Username: "y", Kind: "human", Status: "active"})
		return err
	})
	if err != nil {
		t.Errorf("statement after a refused one: %v", err)
	}
}

// TestIsolation_PostgresAuditAppendOnly: the application role cannot UPDATE,
// DELETE or TRUNCATE the audit tables (REVOKE), except the anchor columns of
// a checkpoint; and the plpgsql triggers refuse the same even to the owner.
func TestIsolation_PostgresAuditAppendOnly(t *testing.T) {
	f := newPGFixture(t)
	ctx := context.Background()
	// one event, written the normal way, and a checkpoint of it
	if err := f.db.InTenant(ctx, pgTenantA, func(tx *TenantTx) error { return tx.Audit(nowUTC(), "system", "pg.test", nil) }); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.owner.ExecContext(ctx, `INSERT INTO audit_checkpoints (id, tenant_id, seq, head_hash, created_at, jws)
		SELECT 'cp-1', tenant_id, seq, hash, 'z', 'jws' FROM audit_events WHERE tenant_id = $1 AND seq = 1`, pgTenantA.String()); err != nil {
		t.Fatal(err)
	}
	// the anchor columns stay writable for the application
	f.asApp(t, pgTenantA.String(), func(tx *sql.Tx) {
		res, err := tx.ExecContext(ctx, `UPDATE audit_checkpoints SET anchor_status = 'anchored', anchor_ref = 'r', anchored_at = 'z', anchor_attempts = anchor_attempts + 1`)
		if n, _ := res.RowsAffected(); err != nil || n != 1 {
			t.Errorf("anchor update: %d rows, %v", n, err)
		}
	})
	for _, tc := range []struct {
		table, priv string
		want        bool
	}{
		{"audit_events", "SELECT", true}, {"audit_events", "INSERT", true},
		{"audit_events", "UPDATE", false}, {"audit_events", "DELETE", false}, {"audit_events", "TRUNCATE", false},
		{"audit_checkpoints", "SELECT", true}, {"audit_checkpoints", "INSERT", true},
		{"audit_checkpoints", "UPDATE", false}, {"audit_checkpoints", "DELETE", false}, {"audit_checkpoints", "TRUNCATE", false},
		{"audit_chain_heads", "UPDATE", true},
	} {
		var has bool
		if err := f.db.owner.QueryRowContext(ctx, `SELECT has_table_privilege('tessera_app', $1, $2)`, tc.table, tc.priv).Scan(&has); err != nil {
			t.Fatal(err)
		}
		// table-level UPDATE is false when only some columns are granted
		if has != tc.want {
			t.Errorf("tessera_app %s on %s = %t, want %t", tc.priv, tc.table, has, tc.want)
		}
	}
	for col, want := range map[string]bool{"anchor_status": true, "anchor_ref": true, "anchored_at": true, "anchor_attempts": true,
		"jws": false, "head_hash": false, "seq": false, "tenant_id": false} {
		var has bool
		if err := f.db.owner.QueryRowContext(ctx, `SELECT has_column_privilege('tessera_app', 'audit_checkpoints', $1, 'UPDATE')`, col).Scan(&has); err != nil {
			t.Fatal(err)
		}
		if has != want {
			t.Errorf("tessera_app UPDATE (%s) on audit_checkpoints = %t, want %t", col, has, want)
		}
	}
	// as the application role the statements fail with "permission denied"
	// (one transaction each: a refusal aborts it)
	for _, q := range []string{`UPDATE audit_events SET detail = '{}'`, `DELETE FROM audit_events`, `TRUNCATE audit_events`,
		`UPDATE audit_checkpoints SET jws = 'x'`, `DELETE FROM audit_checkpoints`, `TRUNCATE audit_checkpoints`} {
		f.asApp(t, pgTenantA.String(), func(tx *sql.Tx) {
			if _, err := tx.ExecContext(ctx, q); sqlState(err) != "42501" {
				t.Errorf("%s as tessera_app: %v (want permission denied)", q, err)
			}
		})
	}
	// chain heads may move forward but are never deleted (trigger)
	f.asApp(t, pgTenantA.String(), func(tx *sql.Tx) {
		if _, err := tx.ExecContext(ctx, `DELETE FROM audit_chain_heads`); err == nil || !strings.Contains(err.Error(), "permanent") {
			t.Errorf("DELETE FROM audit_chain_heads as tessera_app: %v", err)
		}
	})
	// the owner is stopped by the triggers
	for _, q := range []string{`UPDATE audit_events SET detail = '{}'`, `DELETE FROM audit_events`, `TRUNCATE audit_events`,
		`DELETE FROM audit_checkpoints`, `TRUNCATE audit_checkpoints`, `DELETE FROM audit_chain_heads`} {
		if _, err := f.db.owner.ExecContext(ctx, q); err == nil || !(strings.Contains(err.Error(), "append-only") || strings.Contains(err.Error(), "permanent")) {
			t.Errorf("%s as the owner: %v (want the append-only trigger)", q, err)
		}
	}
}

// TestPostgresMigrationsIdempotent: opening an up-to-date database again
// changes nothing, and OpenFresh starts over from an empty schema.
func TestPostgresMigrationsIdempotent(t *testing.T) {
	PostgresForTest(t)
	ctx := context.Background()
	target := TestTarget(t)
	db, err := Open(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.InSystem(ctx, "pg test", func(s *SystemTx) error {
		_, err := s.CreateTenant(Tenant{ID: pgTenantA, Slug: "tenant-a", Name: "A"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var versions int
	if err := db.owner.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE is_applied`).Scan(&versions); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	db, err = Open(ctx, target)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	var again int
	var tenants []Tenant
	if err := db.owner.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE is_applied`).Scan(&again); err != nil || again != versions {
		t.Errorf("migrations applied: %d then %d (%v)", versions, again, err)
	}
	if tenants, err = db.ActiveTenants(ctx); err != nil || len(tenants) != 1 {
		t.Errorf("tenants after reopen: %v %v", tenants, err)
	}
	_ = db.Close()
	db, err = OpenFresh(ctx, target)
	if err != nil {
		t.Fatalf("fresh open: %v", err)
	}
	defer db.Close()
	if tenants, err = db.ActiveTenants(ctx); err != nil || len(tenants) != 0 {
		t.Errorf("tenants after OpenFresh: %v %v", tenants, err)
	}
}

// TestPostgresRLSFileCurrent: the embedded rls.sql is what gen-rls renders
// from the Postgres schema today (regenerate with `tessera admin gen-rls -out
// internal/store/schema/postgres/rls.sql`).
func TestPostgresRLSFileCurrent(t *testing.T) {
	want, err := GenerateRLS()
	if err != nil {
		t.Fatal(err)
	}
	have, err := PostgresRLSFile()
	if err != nil {
		t.Fatal(err)
	}
	if string(have) != string(want) {
		t.Fatal("schema/postgres/rls.sql is out of date; regenerate it with `go run ./cmd/tessera admin gen-rls -out internal/store/schema/postgres/rls.sql`")
	}
	// every tenant table is covered, every global table is not
	tbls, err := PostgresTables()
	if err != nil {
		t.Fatal(err)
	}
	for _, tb := range tbls {
		_, scoped := tb.Column("tenant_id")
		has := strings.Contains(string(have), "ALTER TABLE "+tb.Name+" FORCE ROW LEVEL SECURITY;")
		if scoped && !isGlobal(tb.Name) && !has {
			t.Errorf("tenant table %s has no row-level security", tb.Name)
		}
		if isGlobal(tb.Name) && has {
			t.Errorf("global table %s has row-level security", tb.Name)
		}
	}
}
