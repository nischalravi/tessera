package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

// A database created before tenancy (identities without tenant_id) is refused
// by Open, and OpenFresh recreates it in place so seeding works over it (#121).
func TestLegacySchema_OpenRefusesAndOpenFreshRecreates(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.db")

	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, `CREATE TABLE identities (id INTEGER PRIMARY KEY, name TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, `INSERT INTO identities (name) VALUES ('pre-tenancy row')`); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	if d, err := Open(ctx, path); !errors.Is(err, ErrLegacySchema) {
		if d != nil {
			_ = d.Close()
		}
		t.Fatalf("Open on a legacy database: got %v, want ErrLegacySchema", err)
	}

	d, err := OpenFresh(ctx, path)
	if err != nil {
		t.Fatalf("OpenFresh on a legacy database: %v", err)
	}
	legacy, err := d.legacySchema(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if legacy {
		t.Fatal("OpenFresh left the legacy schema in place")
	}
	var rows int
	if err := d.sql.QueryRowContext(ctx, `SELECT count(*) FROM identities`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("OpenFresh kept %d pre-tenancy rows, want 0", rows)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	// The recreated file now opens normally.
	d2, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open after OpenFresh: %v", err)
	}
	_ = d2.Close()
}
