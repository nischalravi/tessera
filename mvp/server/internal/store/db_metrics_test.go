package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/obs"
)

func TestIsBusy(t *testing.T) {
	for err, want := range map[string]bool{
		"database is locked (5) (SQLITE_BUSY)": true,
		"table is locked (6) (SQLITE_LOCKED)":  true,
		"constraint failed: UNIQUE":            false,
		"context deadline exceeded":            false,
	} {
		if got := isBusy(errors.New(err)); got != want {
			t.Errorf("isBusy(%q) = %v", err, got)
		}
	}
}

// Transactions are timed by kind; SQLITE_BUSY is counted on SQLite only.
func TestTxMetrics(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cs, _ := obs.DBTxDuration.Snapshot("system_read", "ok")
	if err := db.ReadSystem(ctx, "test", func(*SystemTx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if n, _ := obs.DBTxDuration.Snapshot("system_read", "ok"); n != cs+1 {
		t.Errorf("system_read ok count %d, want %d", n, cs+1)
	}
	busy := obs.DBBusy.Value("system_write")
	_ = db.InSystem(ctx, "test", func(*SystemTx) error { return errors.New("database is locked (5) (SQLITE_BUSY)") })
	if obs.DBBusy.Value("system_write") != busy+1 {
		t.Error("SQLITE_BUSY not counted")
	}
	if p := db.PoolStats(); p.Open < 0 {
		t.Errorf("pool: %+v", p)
	}
}
