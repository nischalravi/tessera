package backup_test

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/backup"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// TestDrill_EverySchemaTableIsInTheBackup: the backup carries every table that
// any schema file creates (0008_admin_changes, the 02xx files, native groups
// and whatever lands later), with the same row counts as the live database. It
// inventories the decrypted backup file itself, without applying the schema,
// so a table the backup dropped would be missing here rather than recreated.
func TestDrill_EverySchemaTableIsInTheBackup(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	c := f.backup(t)

	plain := filepath.Join(f.dir, "decrypted.db")
	if _, err := backup.Decrypt(c.Path, plain, f.sealer); err != nil {
		t.Fatal(err)
	}
	got, err := store.InventoryFile(ctx, plain)
	if err != nil {
		t.Fatal(err)
	}
	live, err := f.db.Inventory(ctx)
	if err != nil {
		t.Fatal(err)
	}

	perFile, err := store.SchemaFileTables()
	if err != nil {
		t.Fatal(err)
	}
	files := make([]string, 0, len(perFile))
	for name := range perFile {
		files = append(files, name)
	}
	sort.Strings(files)
	if len(files) < 20 {
		t.Fatalf("only %d schema files with tables found: %v", len(files), files)
	}
	for _, want := range []string{"0008_admin_changes.sql", "0206_business_roles.sql", "0221_abac.sql", "0280_groups.sql"} {
		if _, ok := perFile[want]; !ok {
			t.Errorf("schema file %s not found or creates no table", want)
		}
	}
	for _, name := range files {
		for _, table := range perFile[name] {
			if _, ok := got[table]; !ok {
				t.Errorf("%s: table %s is not in the backup", name, table)
			}
			if _, ok := live[table]; !ok {
				t.Errorf("%s: table %s is not in the live database", name, table)
			}
		}
	}
	for table, n := range live {
		if got[table] != n {
			t.Errorf("table %s: backup has %d rows, live database %d", table, got[table], n)
		}
	}
	for table := range got {
		if _, ok := live[table]; !ok {
			t.Errorf("table %s is in the backup but not the live database", table)
		}
	}

	// and the restore itself serves the same inventory
	target := filepath.Join(f.dir, "restored-drill.db")
	if _, err := backup.Restore(ctx, c.Path, f.sealer, backup.RestoreOptions{Target: target, Anchors: f.anchorSet(t), Now: t0}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	copyPath := filepath.Join(f.dir, "restored-copy.db")
	if err := copyFileTo(target, copyPath); err != nil {
		t.Fatal(err)
	}
	restored, err := store.InventoryFile(ctx, copyPath)
	if err != nil {
		t.Fatal(err)
	}
	for table, n := range live {
		if _, ok := restored[table]; !ok {
			t.Errorf("table %s is missing after restore", table)
		}
		// restore only revokes or deletes credentials; the other tables are untouched
		switch table {
		case "login_transactions", "bootstrap_invitations":
		default:
			if restored[table] != n {
				t.Errorf("table %s: restored %d rows, live database %d", table, restored[table], n)
			}
		}
	}
}

func copyFileTo(src, dst string) error {
	b, err := os.ReadFile(src) // #nosec G304 -- test temp path
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o600)
}
