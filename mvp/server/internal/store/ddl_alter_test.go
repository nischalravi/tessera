package store

import (
	"io/fs"
	"testing"
	"testing/fstest"
)

// TestParseFSFoldsAddColumn: a forward migration's ADD COLUMN lands in its table.
func TestParseFSFoldsAddColumn(t *testing.T) {
	fsys := fstest.MapFS{
		"d/0001_a.sql": {Data: []byte("CREATE TABLE t (id TEXT PRIMARY KEY, n BIGINT NOT NULL);")},
		"d/0002_b.sql": {Data: []byte("-- add\nALTER TABLE t ADD COLUMN IF NOT EXISTS note TEXT CHECK (note IN ('a','b'));\nALTER TABLE t ADD COLUMN at2 TEXT NOT NULL DEFAULT '';")},
	}
	var _ fs.FS = fsys
	ts, err := parseFS(fsys, "d", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 1 {
		t.Fatalf("tables: %d", len(ts))
	}
	for name, notNull := range map[string]bool{"id": true, "n": true, "note": false, "at2": true} {
		c, ok := ts[0].Column(name)
		if !ok || c.NotNull != notNull {
			t.Errorf("column %s: found %t, %+v", name, ok, c)
		}
	}
}
