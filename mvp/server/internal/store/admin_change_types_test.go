package store

import (
	"io/fs"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// TestAdminChangeTypes_PostgresMatchesSQLite checks that the last Postgres
// migration to rebuild admin_change_requests_type_check lists exactly the types
// of the SQLite CHECK in 0008_admin_changes.sql and of upgradeAdminChangeTypes.
// Each Postgres migration replaces the whole list, so one written in parallel
// with another can silently drop the other's type.
func TestAdminChangeTypes_PostgresMatchesSQLite(t *testing.T) {
	quoted := regexp.MustCompile(`'([a-z_][a-z0-9_.]*)'`)
	typesIn := func(s string) []string {
		var out []string
		for _, m := range quoted.FindAllStringSubmatch(s, -1) {
			out = append(out, m[1])
		}
		sort.Strings(out)
		return slices.Compact(out)
	}

	sqlite, err := fs.ReadFile(schemaFS, "schema/0008_admin_changes.sql")
	if err != nil {
		t.Fatal(err)
	}
	src := string(sqlite)
	start := strings.Index(src, "type TEXT NOT NULL CHECK (type IN (")
	if start < 0 {
		t.Fatal("0008_admin_changes.sql: type CHECK not found")
	}
	end := strings.Index(src[start:], "')),")
	if end < 0 {
		t.Fatal("0008_admin_changes.sql: end of type CHECK not found")
	}
	var lines []string
	for _, l := range strings.Split(src[start:start+end+2], "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "--") {
			lines = append(lines, l)
		}
	}
	want := typesIn(strings.Join(lines, "\n"))

	var upgraded []string
	for _, p := range adminChangeNewTypes {
		upgraded = append(upgraded, strings.Trim(p[0], "'"))
	}
	for _, ty := range upgraded {
		if !slices.Contains(want, ty) {
			t.Errorf("upgradeAdminChangeTypes adds %q, which the SQLite CHECK lacks", ty)
		}
	}

	entries, err := fs.ReadDir(pgSchemaFS, "schema/postgres")
	if err != nil {
		t.Fatal(err)
	}
	var last, lastName string
	for _, e := range entries { // ReadDir returns names in order
		b, err := fs.ReadFile(pgSchemaFS, "schema/postgres/"+e.Name())
		if err != nil {
			t.Fatal(err)
		}
		if i := strings.Index(string(b), "ADD CONSTRAINT admin_change_requests_type_check"); i >= 0 {
			last, lastName = string(b)[i:], e.Name()
		}
	}
	if last == "" {
		t.Fatal("no Postgres migration rebuilds admin_change_requests_type_check")
	}
	got := typesIn(last[:strings.Index(last, ";")])
	if !slices.Equal(got, want) {
		for _, ty := range want {
			if !slices.Contains(got, ty) {
				t.Errorf("%s drops change type %q that SQLite allows", lastName, ty)
			}
		}
		for _, ty := range got {
			if !slices.Contains(want, ty) {
				t.Errorf("%s allows change type %q that SQLite does not", lastName, ty)
			}
		}
	}
}
