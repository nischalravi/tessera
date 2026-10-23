package store

import (
	"context"
	"strings"
	"testing"
)

func TestSchemaCurrent_SQLite(t *testing.T) {
	d := openTest(t)
	ctx := context.Background()
	if err := d.SchemaCurrent(ctx); err != nil {
		t.Fatalf("fresh database: %v", err)
	}
	// a pass is remembered; a fresh handle over a damaged schema fails
	d.schemaOK = false
	dropped := false
	for i := len(tables) - 1; i >= 0 && !dropped; i-- { // a leaf table drops cleanly
		_, err := d.sql.ExecContext(ctx, "DROP TABLE "+tables[i]) // #nosec G202 -- fixed names
		dropped = err == nil
	}
	if !dropped {
		t.Fatal("no table could be dropped")
	}
	err := d.SchemaCurrent(ctx)
	if err == nil || !strings.Contains(err.Error(), "not current") {
		t.Fatalf("a missing table passed: %v", err)
	}
}

func TestPGWantVersion(t *testing.T) {
	v, err := pgWantVersion()
	if err != nil || v < 300 {
		t.Fatalf("want version = %d, %v", v, err)
	}
}
