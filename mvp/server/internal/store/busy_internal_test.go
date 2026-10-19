package store

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Two handles on one database file (a CLI command run while a server or a test
// fixture still holds the file open) have separate write mutexes. A write
// transaction that starts with a read (InTenant checks the tenant first) must
// wait for the other handle's write lock instead of failing with SQLITE_BUSY
// when it cannot upgrade a stale WAL snapshot (#126). This needs BEGIN
// IMMEDIATE for write transactions (the _txlock DSN option).
func TestWriteTx_TwoHandlesOneFileNeverBusy(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "shared.db")
	a, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	tid := tenancy.MustParse("00000000-0000-4000-8000-00000000b057")
	if err := a.InSystem(ctx, "test", func(s *SystemTx) error {
		_, err := s.CreateTenant(Tenant{ID: tid, Slug: "busy", Name: "Busy", CreatedAt: time.Now()})
		return err
	}); err != nil {
		t.Fatal(err)
	}

	const perHandle = 200
	errc := make(chan error, 2*perHandle)
	var wg sync.WaitGroup
	for _, d := range []*DB{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range perHandle {
				errc <- d.InTenant(ctx, tid, func(tx *TenantTx) error {
					return tx.Audit(time.Now(), "system", "test.busy", ojson.Object{{Key: "i", Value: i}})
				})
			}
		}()
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		if err != nil {
			t.Fatalf("write through one of two handles failed: %v", err)
		}
	}
}
