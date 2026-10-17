package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// TestIsolation_GroupLoaderTablesGuarded: grp_loaders, grp_loader_runs and
// grp_loader_unresolved (schema/0293_group_loaders.sql) refuse a row of tenant
// B that names tenant A's folder, group, connection or loader, accept the same
// row inside tenant A, scope their names by tenant and keep the enumerations.
func TestIsolation_GroupLoaderTablesGuarded(t *testing.T) {
	db := openTest(t)
	ctx := context.Background()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	nows := now.Format(time.RFC3339)
	ta := tenancy.MustParse("00000000-0000-4000-8000-0000000000a1")
	tb := tenancy.MustParse("00000000-0000-4000-8000-0000000000b2")
	for _, id := range []tenancy.ID{ta, tb} {
		err := db.InSystem(ctx, "test", func(s *SystemTx) error {
			_, err := s.CreateTenant(Tenant{ID: id, Slug: id.String()[30:], Name: "t", CreatedAt: now})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	var folder, group string
	err := db.InTenant(ctx, ta, func(c *TenantTx) error {
		root := &Folder{CreatedAt: now}
		if err := c.InsertGrpFolder(root); err != nil {
			return err
		}
		g := &NativeGroup{FolderID: root.ID, Extension: "g", DisplayExtension: "g", Name: "g", DisplayName: "g", CreatedAt: now}
		if err := c.InsertGrpGroup(g); err != nil {
			return err
		}
		folder, group = string(root.ID), string(g.ID)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	loader := func(tenant tenancy.ID, id, name string, extra string) error {
		_, err := db.sql.ExecContext(ctx, `INSERT INTO grp_loaders (id, tenant_id, name, type, config, target_folder_id, schedule, failsafe,
			created_at, updated_at`+extra+`) VALUES (@id, @t, @name, 'csv', '{}', @f, '@daily', '{}', @n, @n`+
			map[bool]string{true: ", @g", false: ""}[extra != ""]+`)`,
			sql.Named("id", id), sql.Named("t", tenant.String()), sql.Named("name", name), sql.Named("f", folder),
			sql.Named("g", group), sql.Named("n", nows))
		return err
	}
	// each reference of a loader to another tenant's row is refused, and accepted inside the tenant
	if err := loader(tb, "lb", "x", ""); err == nil || !strings.Contains(err.Error(), "cross-tenant reference") {
		t.Errorf("B's loader in A's folder: %v, want a cross-tenant refusal", err)
	}
	if err := loader(tb, "lb2", "x", ", and_group_id"); err == nil || !strings.Contains(err.Error(), "cross-tenant reference") {
		t.Errorf("B's loader with A's AND group: %v, want a cross-tenant refusal", err)
	}
	if err := loader(ta, "la", "Staff", ", and_group_id"); err != nil {
		t.Fatalf("A's loader: %v", err)
	}
	if err := loader(ta, "la2", "staff", ""); err == nil {
		t.Error("two loaders whose names differ only in case, in one tenant")
	}
	conn := func(tenant tenancy.ID) error {
		_, err := db.sql.ExecContext(ctx, `INSERT INTO connections (id, tenant_id, name, connector_type, system, created_at, updated_at)
			VALUES ('c-'||@t, @t, 'c', 'okta', 'okta', @n, @n)`, sql.Named("t", tenant.String()), sql.Named("n", nows))
		return err
	}
	if err := conn(ta); err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.ExecContext(ctx, `UPDATE grp_loaders SET connection_id = 'c-'||@t WHERE id = 'la'`, sql.Named("t", ta.String())); err != nil {
		t.Errorf("A's loader names A's connection: %v", err)
	}
	if err := conn(tb); err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.ExecContext(ctx, `UPDATE grp_loaders SET connection_id = 'c-'||@b WHERE id = 'la'`, sql.Named("b", tb.String())); err == nil ||
		!strings.Contains(err.Error(), "cross-tenant reference") {
		t.Errorf("A's loader moved to B's connection: %v, want a cross-tenant refusal", err)
	}
	// B's own loader of the same name is fine, in B's own folder
	var bFolder string
	err = db.InTenant(ctx, tb, func(c *TenantTx) error {
		root := &Folder{CreatedAt: now}
		if err := c.InsertGrpFolder(root); err != nil {
			return err
		}
		bFolder = string(root.ID)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.ExecContext(ctx, `INSERT INTO grp_loaders (id, tenant_id, name, type, config, target_folder_id, schedule, failsafe, created_at, updated_at)
		VALUES ('lb3', @t, 'Staff', 'csv', '{}', @f, '@daily', '{}', @n, @n)`, sql.Named("t", tb.String()), sql.Named("f", bFolder),
		sql.Named("n", nows)); err != nil {
		t.Errorf("B's loader named like A's: %v", err)
	}
	// enumerations and json columns
	bad := map[string]string{
		"on_missing_group": `UPDATE grp_loaders SET on_missing_group = 'explode' WHERE id = 'la'`,
		"status":           `UPDATE grp_loaders SET status = 'paused' WHERE id = 'la'`,
		"incremental_secs": `UPDATE grp_loaders SET incremental_secs = 5 WHERE id = 'la'`,
		"config":           `UPDATE grp_loaders SET config = 'not json' WHERE id = 'la'`,
		"failsafe":         `UPDATE grp_loaders SET failsafe = '{' WHERE id = 'la'`,
	}
	for name, q := range bad {
		if _, err := db.sql.ExecContext(ctx, q); err == nil {
			t.Errorf("loader %s: an invalid value was stored", name)
		}
	}
	// runs and unresolved subjects follow the loader's tenant
	run := func(tenant tenancy.ID, loaderID, kind, status string) error {
		_, err := db.sql.ExecContext(ctx, `INSERT INTO grp_loader_runs (id, tenant_id, loader_id, kind, started_at, status)
			VALUES (lower(hex(randomblob(8))), @t, @l, @k, @n, @s)`, sql.Named("t", tenant.String()), sql.Named("l", loaderID),
			sql.Named("k", kind), sql.Named("n", nows), sql.Named("s", status))
		return err
	}
	if err := run(tb, "la", "full", "applied"); err == nil || !strings.Contains(err.Error(), "cross-tenant reference") {
		t.Errorf("B's run of A's loader: %v, want a cross-tenant refusal", err)
	}
	if err := run(ta, "la", "full", "applied"); err != nil {
		t.Errorf("A's run: %v", err)
	}
	for _, c := range [][2]string{{"nightly", "applied"}, {"full", "paused"}} {
		if err := run(ta, "la", c[0], c[1]); err == nil {
			t.Errorf("a run of kind %s and status %s was stored", c[0], c[1])
		}
	}
	unres := func(tenant tenancy.ID) error {
		_, err := db.sql.ExecContext(ctx, `INSERT INTO grp_loader_unresolved (tenant_id, loader_id, source, identifier, first_seen, last_seen, groups)
			VALUES (@t, 'la', 'hris', '1', @n, @n, '[]')`, sql.Named("t", tenant.String()), sql.Named("n", nows))
		return err
	}
	if err := unres(tb); err == nil || !strings.Contains(err.Error(), "cross-tenant reference") {
		t.Errorf("B's unresolved subject of A's loader: %v, want a cross-tenant refusal", err)
	}
	if err := unres(ta); err != nil {
		t.Errorf("A's unresolved subject: %v", err)
	}
	if err := unres(ta); err == nil {
		t.Error("the same unresolved subject twice in one loader")
	}
	// a loader moved to another tenant is refused too
	if _, err := db.sql.ExecContext(ctx, `UPDATE grp_loader_runs SET loader_id = 'lb3' WHERE loader_id = 'la'`); err == nil ||
		!strings.Contains(err.Error(), "cross-tenant reference") {
		t.Errorf("a run moved to B's loader: %v, want a cross-tenant refusal", err)
	}
}

// TestRunExtQuery: the read-only query of a SQL loader runs on its own
// read-only connection, so a statement that writes anyway fails and changes
// nothing, and a result over the row limit is an error rather than a cut-off.
func TestRunExtQuery(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "src.db")
	src, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	for _, q := range []string{`CREATE TABLE people (id TEXT, grp TEXT, n INTEGER, f REAL)`,
		`INSERT INTO people VALUES ('a','x',1,1.5),('b','x',2,NULL),('c','y',3,2)`} {
		if _, err := src.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	count := func() int {
		var n int
		if err := src.QueryRowContext(ctx, `SELECT count(*) FROM people`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	res, err := RunExtQuery(ctx, ExtQuery{Path: path, SQL: `SELECT id, n, f FROM people WHERE grp = @g ORDER BY id`, Args: map[string]string{"g": "x"}})
	if err != nil || len(res.Rows) != 2 || res.Columns[0] != "id" || res.Rows[0][1] != "1" || res.Rows[0][2] != "1.5" || res.Rows[1][2] != "" {
		t.Fatalf("select = %+v, %v", res, err)
	}
	// the first line of defence: the statement is checked before it is run
	for name, q := range map[string]string{
		"insert":           `INSERT INTO people VALUES ('z','z',9,9)`,
		"with delete":      `WITH x AS (SELECT 1) DELETE FROM people`,
		"drop":             `DROP TABLE people`,
		"update":           `UPDATE people SET grp = 'q'`,
		"attach":           `ATTACH DATABASE '` + filepath.Join(dir, "other.db") + `' AS o`,
		"create":           `CREATE TABLE t2 (a)`,
		"pragma":           `PRAGMA query_only = 0`,
		"second statement": `SELECT 1; DELETE FROM people`,
		"comment":          `SELECT 1 -- DELETE FROM people`,
		"no keyword":       `people`,
	} {
		if _, err := RunExtQuery(ctx, ExtQuery{Path: path, SQL: q}); err == nil {
			t.Errorf("%s: the statement ran", name)
		}
	}
	// the second: a statement that passes the check but writes is refused by the connection
	replace := `WITH x AS (SELECT 'z' AS a) REPLACE INTO people SELECT a, a, 9, 9 FROM x`
	if err := CheckReadOnlySQL(replace); err != nil {
		t.Fatalf("the statement meant to get past the check was refused by it: %v", err)
	}
	if _, err := RunExtQuery(ctx, ExtQuery{Path: path, SQL: replace}); err == nil || !strings.Contains(err.Error(), "readonly") {
		t.Errorf("a WITH ... REPLACE INTO = %v, want the read-only connection to refuse it", err)
	}
	if n := count(); n != 3 {
		t.Errorf("the source table has %d rows after the write attempts, want 3", n)
	}
	if _, err := os.Stat(filepath.Join(dir, "other.db")); err == nil {
		t.Error("ATTACH created a file")
	}
	if _, err := RunExtQuery(ctx, ExtQuery{Path: path, SQL: `SELECT id FROM people`, MaxRows: 2}); !errors.Is(err, ErrExtRowLimit) {
		t.Errorf("a result over the row limit = %v, want ErrExtRowLimit", err)
	}
	if _, err := RunExtQuery(ctx, ExtQuery{Path: path, SQL: `SELECT id FROM people`, MaxRows: 3}); err != nil {
		t.Errorf("a result at the row limit: %v", err)
	}
	// a query that never ends is stopped by the timeout
	_, err = RunExtQuery(ctx, ExtQuery{Path: path, Timeout: 100 * time.Millisecond,
		SQL: `WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT count(*) FROM c`})
	if err == nil {
		t.Error("an endless query returned")
	}
	// paths: relative, a missing file and URI metacharacters are refused
	for _, p := range []string{"src.db", filepath.Join(dir, "missing.db"), path + "?mode=rw", path + "#x", ""} {
		if _, err := RunExtQuery(ctx, ExtQuery{Path: p, SQL: `SELECT 1`}); err == nil {
			t.Errorf("path %q was accepted", p)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "missing.db")); err == nil {
		t.Error("opening a missing source created it")
	}
}
