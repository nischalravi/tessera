package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestBackupDRDrill is the restore drill of docs/runbooks/disaster-recovery.md,
// run by CI with the Go suite: back up a live database, lose it, restore it,
// and check the restored chain with tessera audit verify against the anchors.
func TestBackupDRDrill(t *testing.T) {
	db, anchors := auditDB(t)
	ctx := context.Background()
	dir := filepath.Join(filepath.Dir(db), "backups")
	var out bytes.Buffer
	if err := run(ctx, []string{"backup", "create", "-db", db, "-dir", dir, "-keep", "2"}, &out, &out); err != nil {
		t.Fatalf("create: %v\n%s", err, out.String())
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.tbak"))
	if len(files) != 1 {
		t.Fatalf("backups %v", files)
	}
	bak := files[0]
	out.Reset()
	if err := run(ctx, []string{"backup", "list", "-dir", dir}, &out, &out); err != nil || !strings.Contains(out.String(), filepath.Base(bak)) {
		t.Fatalf("list: %v %s", err, out.String())
	}
	out.Reset()
	if err := run(ctx, []string{"backup", "verify", "-in", bak, "-db", db}, &out, &out); err != nil {
		t.Fatalf("verify: %v\n%s", err, out.String())
	}

	// Disaster: the live database is gone. Restore it in place (same
	// directory, so the dev KEK next to it is the one that sealed the backup).
	start := time.Now()
	for _, sfx := range []string{"", "-wal", "-shm"} {
		_ = os.Remove(db + sfx)
	}
	out.Reset()
	if err := run(ctx, []string{"backup", "restore", "-in", bak, "-db", db}, &out, &out); err != nil {
		t.Fatalf("restore: %v\n%s", err, out.String())
	}
	t.Logf("restore drill: %s (RTO target 30 min)", time.Since(start).Round(time.Millisecond))
	out.Reset()
	if err := run(ctx, []string{"audit", "verify", "-all", "-db", db, "-anchors", "file://" + anchors}, &out, &out); err != nil {
		t.Fatalf("restored chain does not verify: %v\n%s", err, out.String())
	}

	// A second restore over the live database needs -force.
	if err := run(ctx, []string{"backup", "restore", "-in", bak, "-db", db}, &out, &out); exitCode(err) != ExitBackupRefused {
		t.Errorf("restore over a live database without -force: %v", err)
	}
	// A tampered backup is refused with exit 7.
	raw, _ := os.ReadFile(bak)
	raw[len(raw)-10] ^= 0xff
	bad := filepath.Join(dir, "tampered.tbak")
	if err := os.WriteFile(bad, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, []string{"backup", "verify", "-in", bad, "-db", db}, &out, &out); exitCode(err) != ExitBackupRefused {
		t.Errorf("tampered backup: %v", err)
	}
}
