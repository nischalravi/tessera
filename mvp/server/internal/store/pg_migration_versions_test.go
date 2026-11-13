package store

import (
	"database/sql"
	"io/fs"
	"testing"

	"github.com/pressly/goose/v3"
)

// Two Postgres migrations with one numeric prefix are one goose version, and goose refuses the directory:
// migratePG fails and a Postgres server does not start (issue #970). schema/*.sql is covered by
// scripts/check-schema-prefixes.sh; this covers schema/postgres and needs no database.
func TestPostgresMigrationVersionsUnique(t *testing.T) {
	fsys, err := fs.Sub(pgSchemaFS, "schema/postgres")
	if err != nil {
		t.Fatal(err)
	}
	// the same provider options as migratePG, over a handle that is never used
	if _, err := goose.NewProvider(goose.DialectPostgres, new(sql.DB), fsys,
		goose.WithTableName(pgGooseTable), goose.WithExcludeNames([]string{pgRLSFile})); err != nil {
		t.Fatalf("the Postgres migrations cannot be loaded (renumber a duplicate prefix): %v", err)
	}
}
