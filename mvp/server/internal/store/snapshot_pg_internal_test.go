package store

import (
	"context"
	"errors"
	"testing"
)

// TestSnapshot_PostgresRefused: backup is SQLite-only; on Postgres Snapshot
// refuses before touching the database.
func TestSnapshot_PostgresRefused(t *testing.T) {
	d := &DB{d: dialectPostgres}
	if !d.IsPostgres() {
		t.Fatal("IsPostgres is false")
	}
	if err := d.Snapshot(context.Background(), t.TempDir()+"/x.db"); !errors.Is(err, ErrSnapshotUnsupported) {
		t.Fatalf("Snapshot on postgres = %v, want ErrSnapshotUnsupported", err)
	}
}
