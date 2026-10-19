package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// The Postgres dialect of the schema and of the statements (PR14). These
// tests need no database; the live comparison at the end runs with
// TESSERA_TEST_PG_URL.

// pgOnlyColumns are the columns the Postgres DDL has and SQLite does not:
// SQLite orders some tables by its implicit rowid, Postgres by an explicit
// identity column of the same name.
var pgOnlyColumns = map[string]bool{"rowid": true}

func tablesByName(t *testing.T, load func() ([]DDLTable, error)) map[string]DDLTable {
	t.Helper()
	ts, err := load()
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]DDLTable{}
	for _, tb := range ts {
		if _, dup := m[tb.Name]; dup {
			t.Fatalf("table %s defined twice", tb.Name)
		}
		m[tb.Name] = tb
	}
	return m
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestSchemaParity_SQLiteAndPostgres: the Postgres migrations define the same
// tables as the SQLite schema, with the same columns, storage families and
// NOT NULL-ness (plus only the documented rowid columns), and every table the
// store knows (the drop list) exists in both.
func TestSchemaParity_SQLiteAndPostgres(t *testing.T) {
	lite := tablesByName(t, SQLiteTables)
	pg := tablesByName(t, PostgresTables)
	if got, want := sortedKeys(pg), sortedKeys(lite); !slices.Equal(got, want) {
		t.Errorf("tables differ:\n  sqlite   %v\n  postgres %v", want, got)
	}
	for _, name := range tables {
		if _, ok := lite[name]; !ok {
			t.Errorf("table %s is in the drop list but not in the SQLite schema", name)
		}
		if _, ok := pg[name]; !ok {
			t.Errorf("table %s is in the drop list but not in the Postgres schema", name)
		}
	}
	for _, name := range sortedKeys(lite) {
		l, p := lite[name], pg[name]
		for _, lc := range l.Columns {
			pc, ok := p.Column(lc.Name)
			switch {
			case !ok:
				t.Errorf("%s.%s is missing in Postgres", name, lc.Name)
			case pc.Type != lc.Type:
				t.Errorf("%s.%s: sqlite %s, postgres %s", name, lc.Name, lc.Type, pc.Type)
			case pc.NotNull != lc.NotNull:
				t.Errorf("%s.%s: NOT NULL is %t in sqlite, %t in postgres", name, lc.Name, lc.NotNull, pc.NotNull)
			}
		}
		for _, pc := range p.Columns {
			if _, ok := l.Column(pc.Name); !ok && !pgOnlyColumns[pc.Name] {
				t.Errorf("%s.%s exists only in Postgres", name, pc.Name)
			}
		}
	}
}

// TestSchemaParity_TenantScoped: the tables with tenant_id are the same in
// both dialects and exactly the non-global ones, so the generated RLS covers
// what TestIsolation_EveryTableScopedOrAllowlisted enforces on SQLite.
func TestSchemaParity_TenantScoped(t *testing.T) {
	for name, load := range map[string]func() ([]DDLTable, error){"sqlite": SQLiteTables, "postgres": PostgresTables} {
		for _, tb := range tablesByName(t, load) {
			c, scoped := tb.Column("tenant_id")
			if isGlobal(tb.Name) {
				if scoped {
					t.Errorf("%s: global table %s has tenant_id", name, tb.Name)
				}
				continue
			}
			if !scoped || !c.NotNull || c.Type != "text" {
				t.Errorf("%s: table %s has no tenant_id TEXT NOT NULL", name, tb.Name)
			}
		}
	}
}

// TestPostgresRowidColumns: every statement that orders by <alias>.rowid names
// a table whose Postgres DDL has the explicit rowid column.
func TestPostgresRowidColumns(t *testing.T) {
	pg := tablesByName(t, PostgresTables)
	used := 0
	for name, st := range statements {
		toks, err := tokenize(st.sql)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		refs, err := tableRefs(toks)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for i := 0; i+2 < len(toks); i++ {
			if toks[i+1].text != "." || toks[i+2].text != "rowid" {
				continue
			}
			found := false
			for _, r := range refs {
				if r.qual == toks[i].text {
					found = true
					used++
					if _, ok := pg[r.table].Column("rowid"); !ok {
						t.Errorf("%s orders by %s.rowid but Postgres %s has no rowid column", name, r.qual, r.table)
					}
				}
			}
			if !found {
				t.Errorf("%s: cannot resolve the table of %s.rowid", name, toks[i].text)
			}
		}
	}
	if used == 0 {
		t.Error("no statement uses rowid: the check found nothing")
	}
}

var dollarQuote = regexp.MustCompile(`\$[A-Za-z_]*\$`)

// TestPostgresStatementsNoDollarQuotes: pgx before v5.9.2 mistook the
// placeholders of a statement containing a dollar-quoted string (CVE-2026-41889,
// GO-2026-5004). No statement the store runs with arguments has one, before or
// after translation, and no Go source of the package builds one. (The goose
// migrations use $fn$ bodies; they run without arguments.)
func TestPostgresStatementsNoDollarQuotes(t *testing.T) {
	check := func(what, sql string) {
		if m := dollarQuote.FindString(sql); m != "" {
			t.Errorf("%s contains a dollar-quoted string (%s): %.80s", what, m, sql)
		}
	}
	for name, st := range statements {
		check(name, st.sql)
		ps, err := buildPG(st.sql)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		check(name+" (postgres)", ps.sql)
	}
	for name, o := range pgOverrides {
		check("override "+name, o)
	}
	for name, c := range map[string]string{"pgSetTenant": pgSetTenant, "pgSetLookup": pgSetLookup, "pgLockTenant": pgLockTenant,
		"pgEnableAuditTriggers": pgEnableAuditTriggers} {
		check(name, c)
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if m := dollarQuote.FindString(string(b)); m != "" {
			t.Errorf("%s contains %q: Go code must not build dollar-quoted SQL", f, m)
		}
	}
	// the lint itself must see a dollar-quoted string
	for _, bad := range []string{`SELECT $$x$$`, `SELECT $tag$ $1 $tag$`} {
		if !dollarQuote.MatchString(bad) {
			t.Errorf("lint misses %q", bad)
		}
	}
}

// TestPostgresStatementsTranslate: every registered statement translates, each
// @name becomes one $n, nothing of the SQLite spelling is left, and the
// arguments come out in placeholder order.
func TestPostgresStatementsTranslate(t *testing.T) {
	for name, st := range statements {
		toks, err := tokenize(st.sql)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var want []string
		for _, tk := range toks {
			if tk.kind == tParam && !slices.Contains(want, tk.text) {
				want = append(want, tk.text)
			}
		}
		ps, err := buildPG(st.sql)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if _, overridden := pgOverrides[name]; !overridden && !slices.Equal(ps.names, want) {
			t.Errorf("%s: parameters %v, want %v", name, ps.names, want)
		}
		for _, n := range ps.names {
			if !strings.Contains(ps.sql, "$") || strings.Contains(ps.sql, "@"+n) {
				t.Errorf("%s: parameter @%s left in %q", name, n, ps.sql)
			}
		}
		if regexp.MustCompile(`(?i)\b(instr|insert\s+or\s+ignore|json_valid|json_type)\b`).MatchString(ps.sql) {
			t.Errorf("%s: SQLite-only syntax left in %q", name, ps.sql)
		}
	}
}

func TestTranslatePG(t *testing.T) {
	named := func(kv ...any) []any {
		var out []any
		for i := 0; i < len(kv); i += 2 {
			out = append(out, sql.Named(kv[i].(string), kv[i+1]))
		}
		return out
	}
	for _, tc := range []struct {
		name, in string
		args     []any
		want     string
		wantArgs []any
		wantErr  string
	}{
		{name: "plain", in: `SELECT 1`, want: `SELECT 1`},
		{name: "ordered by first use", in: `SELECT x FROM t WHERE a = @b AND c = @a`, args: named("a", 1, "b", "two"),
			want: `SELECT x FROM t WHERE a = $1 AND c = $2`, wantArgs: []any{"two", 1}},
		{name: "repeated name shares a placeholder", in: `WHERE (@k = '' OR a = @k)`, args: named("k", "v"),
			want: `WHERE ($1 = '' OR a = $1)`, wantArgs: []any{"v"}},
		{name: "unused argument is dropped", in: `SELECT @a`, args: named("a", 1, "z", 2), want: `SELECT $1`, wantArgs: []any{1}},
		{name: "not inside strings, identifiers or comments", in: "SELECT '@a', \"@b\", x -- @c\n, y /* @d */ FROM t WHERE e = @e",
			args: named("e", 5), want: "SELECT '@a', \"@b\", x -- @c\n, y /* @d */ FROM t WHERE e = $1", wantArgs: []any{5}},
		{name: "doubled quote in a string", in: `SELECT 'it''s @a', @b`, args: named("b", 1), want: `SELECT 'it''s @a', $1`, wantArgs: []any{1}},
		{name: "instr", in: `SELECT INSTR(a, ':'), instr(b, '/')`, want: `SELECT strpos(a, ':'), strpos(b, '/')`},
		{name: "insert or ignore", in: "INSERT OR IGNORE INTO t (a) VALUES (@a)", args: named("a", 1),
			want: `INSERT INTO t (a) VALUES ($1) ON CONFLICT DO NOTHING`, wantArgs: []any{1}},
		{name: "limit parameter: negative means no limit", in: `SELECT 1 FROM t ORDER BY a LIMIT @n`, args: named("n", -1),
			want: `SELECT 1 FROM t ORDER BY a LIMIT NULLIF(CAST($1 AS BIGINT), -1)`, wantArgs: []any{-1}},
		{name: "limit literal stays", in: `SELECT 1 FROM t LIMIT 1`, want: `SELECT 1 FROM t LIMIT 1`},
		{name: "missing argument", in: `SELECT @a`, wantErr: "@a has no argument"},
		{name: "positional argument refused", in: `SELECT @a`, args: []any{1}, wantErr: "named arguments only"},
		{name: "unterminated string", in: `SELECT 'abc`, wantErr: "unterminated quote"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, args, err := translatePG(tc.in, tc.args)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want || fmt.Sprint(args) != fmt.Sprint(tc.wantArgs) {
				t.Errorf("got %q %v\nwant %q %v", got, args, tc.want, tc.wantArgs)
			}
		})
	}
}

func TestParsePGDSN(t *testing.T) {
	cfg, role, err := parsePGDSN("postgres://owner:pw@db.example.com:6543/tessera?sslmode=require&app_role=tessera_app&application_name=t")
	if err != nil {
		t.Fatal(err)
	}
	if role != "tessera_app" || cfg.Host != "db.example.com" || cfg.Port != 6543 || cfg.Database != "tessera" || cfg.User != "owner" {
		t.Errorf("parsed %q %+v", role, cfg)
	}
	if _, ok := cfg.RuntimeParams["app_role"]; ok {
		t.Error("app_role would be sent to the server as a setting")
	}
	if cfg.RuntimeParams["application_name"] != "t" {
		t.Errorf("other options lost: %v", cfg.RuntimeParams)
	}
	if _, role, err := parsePGDSN("postgres://owner@localhost/db"); err != nil || role != "" {
		t.Errorf("no app_role: %q %v", role, err)
	}
	for _, bad := range []string{"postgres://o@h/db?app_role=Tessera%20App", "postgres://o@h/db?app_role=a;drop", "postgres://o@h/db?app_role=" + strings.Repeat("a", 64)} {
		// refused, never silently run without the role
		if _, _, err := parsePGDSN(bad); err == nil || !strings.Contains(err.Error(), "invalid") {
			t.Errorf("%q: %v", bad, err)
		}
	}
	_, _, err = parsePGDSN("postgres://owner:hunter2@h:notaport/db")
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("a bad DSN must be refused without echoing the password: %v", err)
	}
	for in, want := range map[string]bool{"postgres://h/db": true, "postgresql://h/db": true, "tessera.db": false, "sqlite:///x.db": false, "": false, "xpostgres://h": false} {
		if IsPostgresDSN(in) != want {
			t.Errorf("IsPostgresDSN(%q) = %t", in, !want)
		}
	}
}

func TestParseDDL(t *testing.T) {
	ts, err := ParseDDL(`
		-- a comment, with (parens) and a comma
		CREATE TABLE IF NOT EXISTS a (
			id INTEGER PRIMARY KEY, -- trailing
			name TEXT NOT NULL DEFAULT 'x,y)', /* inline (comment */
			n BIGINT GENERATED BY DEFAULT AS IDENTITY,
			f DOUBLE PRECISION NOT NULL CHECK (f IN (1, 2)),
			b BYTEA, w REAL,
			k1 TEXT, k2 TEXT,
			UNIQUE (name, k1),
			PRIMARY KEY (k1, k2)
		);
		CREATE INDEX i ON a (name);
		create table b (x text not null, y integer);`)
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 2 || ts[0].Name != "a" || ts[1].Name != "b" {
		t.Fatalf("tables %+v", ts)
	}
	want := map[string]DDLColumn{"id": {"id", "int", true}, "name": {"name", "text", true}, "n": {"n", "int", false}, "f": {"f", "real", true},
		"b": {"b", "blob", false}, "w": {"w", "real", false}, "k1": {"k1", "text", true}, "k2": {"k2", "text", true}}
	if len(ts[0].Columns) != len(want) {
		t.Errorf("columns %+v", ts[0].Columns)
	}
	for _, c := range ts[0].Columns {
		if want[c.Name] != c {
			t.Errorf("column %+v, want %+v", c, want[c.Name])
		}
	}
	if y, _ := ts[1].Column("y"); y.NotNull || y.Type != "int" {
		t.Errorf("b.y %+v", y)
	}
	for _, bad := range []string{"CREATE TABLE x", "CREATE TABLE x (a (b)", "CREATE TABLE x (a MONEY)", "CREATE TABLE x (a)"} {
		if _, err := ParseDDL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// TestSchemaParity_LiveDatabases: the columns the two real databases report
// match what the DDL parser read from the files, so the static parity test
// compares what the databases actually have. SQLite always; Postgres when
// TESSERA_TEST_PG_URL is set.
func TestSchemaParity_LiveDatabases(t *testing.T) {
	ctx := context.Background()
	lite, err := Open(ctx, filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer lite.Close()
	type col struct {
		typ     string
		notNull bool
	}
	liveLite := map[string]map[string]col{}
	rows, err := lite.sql.QueryContext(ctx, `SELECT m.name, p.name, p.type, p."notnull", p.pk FROM sqlite_master m, pragma_table_info(m.name) p
		WHERE m.type = 'table' AND m.name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var tbl, name, typ string
		var nn, pk int
		if err := rows.Scan(&tbl, &name, &typ, &nn, &pk); err != nil {
			t.Fatal(err)
		}
		if liveLite[tbl] == nil {
			liveLite[tbl] = map[string]col{}
		}
		family, _ := typeFamily(strings.ToUpper(typ))
		liveLite[tbl][name] = col{family, nn == 1 || pk > 0}
	}
	_ = rows.Close()
	parsed := tablesByName(t, SQLiteTables)
	for name, tb := range parsed {
		for _, c := range tb.Columns {
			if got := liveLite[name][c.Name]; got != (col{c.Type, c.NotNull}) {
				t.Errorf("sqlite %s.%s: database says %+v, DDL parser says %+v", name, c.Name, got, c)
			}
		}
		if len(liveLite[name]) != len(tb.Columns) {
			t.Errorf("sqlite %s: %d columns live, %d parsed", name, len(liveLite[name]), len(tb.Columns))
		}
	}

	PostgresForTest(t)
	pgdb, err := Open(ctx, TestTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	defer pgdb.Close()
	prows, err := pgdb.owner.QueryContext(ctx, `SELECT table_name, column_name, data_type, is_nullable FROM information_schema.columns
		WHERE table_schema = current_schema()`)
	if err != nil {
		t.Fatal(err)
	}
	livePG := map[string]map[string]col{}
	for prows.Next() {
		var tbl, name, typ, nullable string
		if err := prows.Scan(&tbl, &name, &typ, &nullable); err != nil {
			t.Fatal(err)
		}
		if tbl == pgGooseTable { // goose's own bookkeeping
			continue
		}
		family := map[string]string{"bigint": "int", "integer": "int", "text": "text", "double precision": "real", "bytea": "blob"}[typ]
		if family == "" {
			t.Errorf("postgres %s.%s has type %s", tbl, name, typ)
		}
		if livePG[tbl] == nil {
			livePG[tbl] = map[string]col{}
		}
		livePG[tbl][name] = col{family, nullable == "NO"}
	}
	_ = prows.Close()
	for name, cols := range liveLite {
		for cn, c := range cols {
			if got, ok := livePG[name][cn]; !ok || got != c {
				t.Errorf("postgres %s.%s: %+v (present %t), sqlite has %+v", name, cn, got, ok, c)
			}
		}
	}
	for name, cols := range livePG {
		if name == pgGooseTable {
			continue
		}
		for cn := range cols {
			if _, ok := liveLite[name][cn]; !ok && !pgOnlyColumns[cn] {
				t.Errorf("postgres %s.%s has no SQLite counterpart", name, cn)
			}
		}
	}
}
