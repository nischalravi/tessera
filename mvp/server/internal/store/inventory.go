package store

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Table inventory (issue #171). The backup drill compares the tables and row
// counts of a live database with those inside a decrypted backup, and checks
// that every table any schema file creates is present, so a table added by a
// later schema file cannot be silently left out of a backup.

var (
	identRE       = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	createTableRE = regexp.MustCompile(`(?im)^\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"?([A-Za-z_][A-Za-z0-9_]*)"?`)
)

// SchemaFileTables returns, for every embedded schema file, the tables it
// creates.
func SchemaFileTables() (map[string][]string, error) {
	files, err := schemaFS.ReadDir("schema")
	if err != nil {
		return nil, fmt.Errorf("store: schema files: %w", err)
	}
	out := make(map[string][]string, len(files))
	for _, f := range files {
		b, err := schemaFS.ReadFile("schema/" + f.Name())
		if err != nil {
			return nil, fmt.Errorf("store: schema file %s: %w", f.Name(), err)
		}
		for _, m := range createTableRE.FindAllStringSubmatch(string(b), -1) {
			out[f.Name()] = append(out[f.Name()], m[1])
		}
	}
	return out, nil
}

// Inventory returns the row count of every table in the database.
func (d *DB) Inventory(ctx context.Context) (map[string]int64, error) {
	return inventory(ctx, d.sql)
}

// InventoryFile returns the row count of every table in the SQLite file at
// path without applying any schema, so a table missing from the file stays
// missing. Use it on a copy: opening a WAL-mode file can create -wal/-shm
// files next to it.
func InventoryFile(ctx context.Context, path string) (map[string]int64, error) {
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		return nil, fmt.Errorf("store: inventory: %w", err)
	}
	defer db.Close()
	return inventory(ctx, db)
}

func inventory(ctx context.Context, db *sql.DB) (map[string]int64, error) {
	rows, err := db.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		return nil, fmt.Errorf("store: inventory: %w", err)
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("store: inventory: %w", err)
		}
		names = append(names, n)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("store: inventory: %w", err)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: inventory: %w", err)
	}
	sort.Strings(names)
	out := make(map[string]int64, len(names))
	for _, n := range names {
		if !identRE.MatchString(n) {
			return nil, fmt.Errorf("store: inventory: unexpected table name %q", strings.ToValidUTF8(n, "?"))
		}
		var c int64
		// #nosec G202 -- the name came from sqlite_master and matched identRE
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM "`+n+`"`).Scan(&c); err != nil {
			return nil, fmt.Errorf("store: inventory %s: %w", n, err)
		}
		out[n] = c
	}
	return out, nil
}
