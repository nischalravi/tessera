package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

func openTest(t *testing.T) *DB {
	t.Helper()
	db, err := Open(context.Background(), filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestIsolation_EveryTableScopedOrAllowlisted is the schema meta-test: after
// Migrate, every table either has tenant_id TEXT NOT NULL with a foreign key
// to tenants(id) and every unique index starting with tenant_id, or is in
// GlobalTables.
func TestIsolation_EveryTableScopedOrAllowlisted(t *testing.T) {
	db := openTest(t)
	ctx := context.Background()
	rows, err := db.sql.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sortedCopy(names), sortedCopy(tables)) {
		t.Errorf("live tables %v differ from store.tables %v", names, tables)
	}
	for _, table := range names {
		t.Run(table, func(t *testing.T) {
			if slices.Contains(GlobalTables, table) {
				return
			}
			var typ string
			var notNull int
			err := db.sql.QueryRowContext(ctx, `SELECT type, "notnull" FROM pragma_table_info(@t) WHERE name = 'tenant_id'`,
				sql.Named("t", table)).Scan(&typ, &notNull)
			if errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("%s has no tenant_id and is not in GlobalTables", table)
			}
			if err != nil {
				t.Fatal(err)
			}
			if typ != "TEXT" || notNull != 1 {
				t.Errorf("%s.tenant_id is %s notnull=%d, want TEXT NOT NULL", table, typ, notNull)
			}
			var fk int
			if err := db.sql.QueryRowContext(ctx, `SELECT count(*) FROM pragma_foreign_key_list(@t)
				WHERE "from" = 'tenant_id' AND "table" = 'tenants' AND "to" = 'id'`, sql.Named("t", table)).Scan(&fk); err != nil {
				t.Fatal(err)
			}
			if fk != 1 {
				t.Errorf("%s.tenant_id has no foreign key to tenants(id)", table)
			}
			var tenantIndexed int
			idx, err := db.sql.QueryContext(ctx, `SELECT name, "unique", origin FROM pragma_index_list(@t)`, sql.Named("t", table))
			if err != nil {
				t.Fatal(err)
			}
			type ix struct {
				name   string
				unique bool
				origin string
			}
			var ixs []ix
			for idx.Next() {
				var x ix
				if err := idx.Scan(&x.name, &x.unique, &x.origin); err != nil {
					t.Fatal(err)
				}
				ixs = append(ixs, x)
			}
			if err := idx.Close(); err != nil {
				t.Fatal(err)
			}
			for _, x := range ixs {
				var first string
				if err := db.sql.QueryRowContext(ctx, `SELECT name FROM pragma_index_info(@i) WHERE seqno = 0`,
					sql.Named("i", x.name)).Scan(&first); err != nil {
					t.Fatal(err)
				}
				if first == "tenant_id" {
					tenantIndexed++
				}
				if x.unique && x.origin != "pk" && first != "tenant_id" && !globalHashIndex(t, db, x.name, table) {
					t.Errorf("unique index %s on %s does not start with tenant_id", x.name, table)
				}
			}
			if tenantIndexed == 0 {
				t.Errorf("%s has no index starting with tenant_id", table)
			}
		})
	}
}

// globalHashIndex reports whether index is a single-column unique index on
// the table's GlobalHashLookups column (the bearer-secret hashes of §14.2,
// unique across tenants by design).
func globalHashIndex(t *testing.T, db *DB, index, table string) bool {
	t.Helper()
	col, ok := GlobalHashLookups[table]
	if !ok {
		return false
	}
	rows, err := db.sql.QueryContext(context.Background(), `SELECT name FROM pragma_index_info(@i)`, sql.Named("i", index))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			t.Fatal(err)
		}
		cols = append(cols, c)
	}
	return len(cols) == 1 && cols[0] == col
}

func sortedCopy(s []string) []string {
	c := slices.Clone(s)
	sort.Strings(c)
	return c
}

// TestIsolation_EveryStatementBindsTenant lints every registered statement:
// each tenant-table reference has its alias's tenant_id = @tenant conjunct,
// each INSERT stamps tenant_id with @tenant, ON CONFLICT targets start with
// tenant_id, no SET list assigns tenant_id, and system statements touch only
// GlobalTables.
func TestIsolation_EveryStatementBindsTenant(t *testing.T) {
	if len(statements) < 50 {
		t.Fatalf("only %d statements registered", len(statements))
	}
	names := make([]string, 0, len(statements))
	for n := range statements {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		st := statements[n]
		t.Run(n, func(t *testing.T) {
			lint := lintStatement
			if st.lookup {
				lint = func(q string, _ bool, _ []string) error { return lintLookup(q) }
			}
			if err := lint(st.sql, st.system, GlobalTables); err != nil {
				t.Errorf("%v\n%s", err, st.sql)
			}
		})
	}
}

// TestIsolation_TenantIDNeverUpdated: no registered statement assigns
// tenant_id in a SET list (also covered by the lint; kept as its own named
// check from the design's table).
func TestIsolation_TenantIDNeverUpdated(t *testing.T) {
	for n, st := range statements {
		toks, err := tokenize(st.sql)
		if err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		if err := checkSetLists(toks); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
}

// TestStatementLintRejects proves the linter catches each way a statement can
// escape its tenant (so a passing lint means something).
func TestStatementLintRejects(t *testing.T) {
	bad := []struct{ name, sql string }{
		{"no predicate", `SELECT i.id FROM identities i ORDER BY i.id`},
		{"no tenant param", `SELECT i.id FROM identities i WHERE i.tenant_id = @other`},
		{"predicate under OR", `SELECT i.id FROM identities i WHERE i.tenant_id = @tenant OR i.id = @id`},
		{"OR after predicate", `SELECT i.id FROM identities i WHERE i.id = @id OR i.tenant_id = @tenant`},
		{"joined table unscoped", `SELECT s.id FROM secrets s JOIN accounts a ON s.account_id = a.id WHERE s.tenant_id = @tenant`},
		{"predicate on the wrong alias", `SELECT s.id FROM secrets s JOIN accounts a ON s.account_id = a.id
			WHERE s.tenant_id = @tenant AND s.tenant_id = @tenant`},
		{"subquery unscoped", `SELECT (SELECT count(*) FROM grant_edges e WHERE e.source = 'jit') FROM identities i
			WHERE i.tenant_id = @tenant`},
		{"predicate only in subquery", `SELECT i.id FROM identities i WHERE i.id IN (SELECT e.id FROM grant_edges e
			WHERE e.tenant_id = @tenant AND i.tenant_id = @tenant)`},
		{"positional parameter", `SELECT i.id FROM identities i WHERE i.tenant_id = @tenant AND i.id = ?`},
		{"dollar parameter", `SELECT i.id FROM identities i WHERE i.tenant_id = @tenant AND i.id = $1`},
		{"two statements", `DELETE FROM grant_edges WHERE tenant_id = @tenant; DELETE FROM grant_edges`},
		{"comma join", `SELECT i.id FROM identities i, accounts a WHERE i.tenant_id = @tenant AND a.tenant_id = @tenant`},
		{"unscoped delete", `DELETE FROM agent_delegations`},
		{"unscoped update", `UPDATE identities SET name = @name WHERE id = @id`},
		{"update sets tenant", `UPDATE identities SET tenant_id = @to WHERE tenant_id = @tenant AND id = @id`},
		{"insert without tenant", `INSERT INTO audit_events (id, seq, action, detail) VALUES (@id, @a, @b, @c)`},
		{"insert with other tenant", `INSERT INTO audit_events (tenant_id, id, seq, action, detail) VALUES (@t, @id, @a, @b, @c)`},
		{"conflict target without tenant", `INSERT INTO groups (tenant_id, system, external_id, name, kind, privileged,
			requestable) VALUES (@tenant, @s, @x, @n, @k, 0, 0) ON CONFLICT (system, external_id) DO UPDATE SET name = excluded.name`},
		{"upsert moves tenant", `INSERT INTO groups (tenant_id, system, external_id, name, kind, privileged, requestable)
			VALUES (@tenant, @s, @x, @n, @k, 0, 0) ON CONFLICT (tenant_id, system, external_id) DO UPDATE SET
			name = excluded.name, tenant_id = excluded.tenant_id`},
		{"insert select", `INSERT INTO audit_events (tenant_id, id, seq, action, detail) SELECT @tenant, l.id, l.seq, l.action,
			l.detail FROM audit_events l`},
		{"CTE", `WITH x AS (SELECT i.id FROM identities i) SELECT x.id FROM x WHERE x.tenant_id = @tenant`},
		{"union", `SELECT i.id FROM identities i WHERE i.tenant_id = @tenant UNION SELECT a.id FROM accounts a`},
		{"system statement on tenant table", `SELECT count(*) FROM identities i`},
		{"tenant statement on global table only", `SELECT t.id FROM tenants t WHERE t.id = @tenant`},
		{"quoted identifier", `SELECT "i".id FROM identities i WHERE i.tenant_id = @tenant`},
	}
	for _, tc := range bad {
		system := strings.HasPrefix(tc.name, "system")
		if err := lintStatement(tc.sql, system, GlobalTables); err == nil {
			t.Errorf("%s: lint accepted\n%s", tc.name, tc.sql)
		}
	}
	good := []string{
		`SELECT i.id FROM identities i WHERE i.tenant_id = @tenant AND (i.id = @a OR i.id = @b)`,
		`SELECT i.id FROM identities i WHERE @tenant = i.tenant_id`,
		`DELETE FROM grant_edges WHERE tenant_id = @tenant AND id = @id`,
	}
	for _, q := range good {
		if err := lintStatement(q, false, GlobalTables); err != nil {
			t.Errorf("lint rejected a scoped statement: %v\n%s", err, q)
		}
	}
}

// TestIsolation_CallerCannotBindTenant: a "tenant" argument supplied by a
// caller is refused by every executor path, whatever its case.
func TestIsolation_CallerCannotBindTenant(t *testing.T) {
	db := openTest(t)
	ctx := context.Background()
	var a tenancy.ID
	if err := db.InSystem(ctx, "test", func(s *SystemTx) error {
		ta, err := s.CreateTenant(Tenant{Slug: "tenant-a", Name: "A"})
		a = ta.ID
		return err
	}); err != nil {
		t.Fatal(err)
	}
	err := db.InTenant(ctx, a, func(tx *TenantTx) error {
		for _, name := range []string{"tenant", "TENANT", "Tenant"} {
			arg := sql.Named(name, "00000000-0000-4000-8000-000000000999")
			if _, err := tx.exec(identitiesSetOwner, arg, sql.Named("owner_id", nil), sql.Named("id", 1)); !errors.Is(err, ErrCrossTenant) {
				t.Errorf("exec with %s: %v", name, err)
			}
			if _, err := tx.query(identitiesList, arg); !errors.Is(err, ErrCrossTenant) {
				t.Errorf("query with %s: %v", name, err)
			}
			var n int
			if err := tx.queryRow(identitiesGet, arg, sql.Named("id", 1)).Scan(&n); !errors.Is(err, ErrCrossTenant) {
				t.Errorf("queryRow with %s: %v", name, err)
			}
			if _, err := tx.count(accountsCount, arg); !errors.Is(err, ErrCrossTenant) {
				t.Errorf("count with %s: %v", name, err)
			}
			if _, err := tx.insert(auditHeadInsert, arg, sql.Named("hash", ""), sql.Named("at", "")); !errors.Is(err, ErrCrossTenant) {
				t.Errorf("insert with %s: %v", name, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestReadTenantRefusesWrites: a ReadTenant transaction cannot write.
func TestReadTenantRefusesWrites(t *testing.T) {
	db := openTest(t)
	err := db.ReadTenant(context.Background(), tenancy.Platform, func(tx *TenantTx) error {
		return tx.Audit(nowUTC(), "x", "y", nil)
	})
	if !errors.Is(err, ErrReadOnly) {
		t.Errorf("err = %v, want ErrReadOnly", err)
	}
}

// referenceColumns are the tenant-table columns that hold a reference to
// another row but have no declared foreign key: grant_edges ids and graph
// node keys ("account:12").
var referenceColumns = map[string][]string{
	// a chain head and a checkpoint name an event of their tenant by (seq, hash)
	"audit_chain_heads": {"last_seq", "last_hash"},
	"audit_checkpoints": {"seq", "head_hash"},
	"grant_edges":       {"src", "dst"},
	"access_requests":   {"edge_id", "requested_by_user_id", "decided_by_user_id"},
	"review_items":      {"edge_id", "edge_src", "edge_dst", "decided_by_user_id"},
	"hris_events":       {"executed_by_user_id"},
	// platform users and sessions named without a declared foreign key
	"role_assignments":   {"granted_by_user_id"},
	"login_transactions": {"session_id", "expected_external_login_id", "bootstrap_invitation_id"},
}

// immutableTables refuse every UPDATE (a trigger raises unconditionally), so
// they need no UPDATE guard.
var immutableTables = []string{"authn_contexts", "terms_acceptances", "attribute_consents"}

// TestIsolation_EveryReferenceGuarded checks that every foreign key (other
// than tenant_id) and every reference column on a tenant table is covered by
// the cross-tenant guard triggers, on both INSERT and UPDATE.
func TestIsolation_EveryReferenceGuarded(t *testing.T) {
	db := openTest(t)
	ctx := context.Background()
	for _, table := range tables {
		if slices.Contains(GlobalTables, table) {
			continue
		}
		cols := slices.Clone(referenceColumns[table])
		rows, err := db.sql.QueryContext(ctx, `SELECT "from" FROM pragma_foreign_key_list(@t) WHERE "table" <> 'tenants'`,
			sql.Named("t", table))
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var c string
			if err := rows.Scan(&c); err != nil {
				t.Fatal(err)
			}
			cols = append(cols, c)
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
		for _, ev := range []string{"ins", "upd"} {
			if len(cols) == 0 || (ev == "upd" && slices.Contains(immutableTables, table)) {
				continue
			}
			// the guard is tg_<table>_xtenant_<ev>, plus any other
			// tg_<table>_*xtenant* trigger on the same event (a later schema
			// file guarding columns it added)
			name := "tg_" + table + "_xtenant_" + ev
			kind := map[string]string{"ins": "BEFORE INSERT", "upd": "BEFORE UPDATE"}[ev]
			var body string
			grows, err := db.sql.QueryContext(ctx, `SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = @t`,
				sql.Named("t", table))
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for grows.Next() {
				var n, b string
				if err := grows.Scan(&n, &b); err != nil {
					t.Fatal(err)
				}
				if n == name {
					found = true
				}
				if strings.HasPrefix(n, "tg_"+table+"_") && strings.Contains(n, "xtenant") && strings.Contains(b, kind) {
					body += b + "\n"
				}
			}
			if err := grows.Close(); err != nil {
				t.Fatal(err)
			}
			if !found {
				t.Errorf("%s: missing (table %s has references %v)", name, table, cols)
				continue
			}
			for _, c := range cols {
				if !strings.Contains(body, "NEW."+c+" ") && !strings.Contains(body, "NEW."+c+",") &&
					!strings.Contains(body, "NEW."+c+")") {
					t.Errorf("%s does not guard %s.%s", name, table, c)
				}
				if ev == "upd" && !strings.Contains(body, " "+c+",") && !strings.Contains(body, " "+c+" ON") {
					t.Errorf("%s does not fire on UPDATE OF %s", name, c)
				}
			}
		}
	}
}
