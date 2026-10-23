package store

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A database created before issues #510 and #512 gets helpdesk_idp_risks' submitter and dismissal columns and
// queue_schedules.paused_until on open, defaulted to empty, and its rows survive.
func TestUpgradeSecurityControls(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")
	d, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	d.sql.SetMaxOpenConns(1)
	for _, tbl := range []struct{ name, col string }{{"queue_schedules", "paused_until"}, {"helpdesk_idp_risks", "dismiss_reason"}} {
		var def string
		if err := d.sql.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE name = ?`, tbl.name).Scan(&def); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(def, tbl.col) {
			t.Fatalf("%s is not in the %s schema", tbl.col, tbl.name)
		}
	}
	// recreate both tables the way they were
	old := map[string][]string{
		"queue_schedules":    {"paused_until"},
		"helpdesk_idp_risks": {"submitted_by", "submitted_by_user", "dismissed_at", "dismissed_by", "dismissed_by_user", "dismiss_reason"},
	}
	for tbl, cols := range old {
		var def string
		if err := d.sql.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE name = ?`, tbl).Scan(&def); err != nil {
			t.Fatal(err)
		}
		for _, c := range cols {
			lines := strings.Split(def, "\n")
			kept := lines[:0]
			for _, l := range lines {
				if tl := strings.TrimSpace(l); !strings.HasPrefix(tl, c+" ") && !strings.HasPrefix(tl, "--") {
					kept = append(kept, l)
				}
			}
			def = strings.Join(kept, "\n")
		}
		// the last remaining column line may now end with a comma before the closing parenthesis
		def = regexp.MustCompile(`,\s*\)\s*$`).ReplaceAllString(def, "\n)")
		for _, q := range []string{"PRAGMA foreign_keys = OFF", "DROP TABLE " + tbl, def, "PRAGMA foreign_keys = ON"} {
			if _, err := d.sql.ExecContext(ctx, q); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
	}
	_ = d.Close()
	for range 2 {
		d, err = Open(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		for tbl, cols := range old {
			for _, c := range cols {
				var n int
				if err := d.sql.QueryRowContext(ctx, `SELECT count(*) FROM pragma_table_info(?) WHERE name = ?`, tbl, c).Scan(&n); err != nil || n != 1 {
					t.Fatalf("%s.%s after the upgrade: %d %v", tbl, c, n, err)
				}
			}
		}
		_ = d.Close()
	}
}
