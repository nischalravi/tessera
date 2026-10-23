package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
)

// SchemaCurrent reports nil when the database holds every table and (on
// Postgres) every migration this binary ships. A newer schema is fine (a
// replica of the next release already migrated); an older one is not: this
// binary's statements would fail. It backs /readyz. A pass is remembered.
func (d *DB) SchemaCurrent(ctx context.Context) error {
	d.schemaMu.Lock()
	defer d.schemaMu.Unlock()
	if d.schemaOK {
		return nil
	}
	var err error
	if d.d == dialectPostgres {
		err = d.pgSchemaCurrent(ctx)
	} else {
		err = d.sqliteSchemaCurrent(ctx)
	}
	d.schemaOK = err == nil
	return err
}

func (d *DB) sqliteSchemaCurrent(ctx context.Context) error {
	rows, err := d.sql.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table'`)
	if err != nil {
		return err
	}
	defer rows.Close()
	have := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return err
		}
		have[n] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, t := range tables {
		if !have[t] {
			return fmt.Errorf("store: schema is not current: table %s is missing", t)
		}
	}
	return nil
}

// pgWantVersion is the highest goose migration number this binary embeds.
func pgWantVersion() (int64, error) {
	var want int64
	err := fs.WalkDir(pgSchemaFS, "schema/postgres", func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() || !strings.HasSuffix(p, ".sql") || strings.HasSuffix(p, pgRLSFile) {
			return err
		}
		name := p[strings.LastIndex(p, "/")+1:]
		n, perr := strconv.ParseInt(name[:strings.IndexByte(name+"_", '_')], 10, 64)
		if perr == nil && n > want {
			want = n
		}
		return nil
	})
	return want, err
}

const pgSchemaVersion = `SELECT COALESCE(max(version_id), 0) FROM ` + pgGooseTable + ` WHERE is_applied`

func (d *DB) pgSchemaCurrent(ctx context.Context) error {
	want, err := pgWantVersion()
	if err != nil {
		return err
	}
	var have int64
	err = d.owner.QueryRowContext(ctx, pgSchemaVersion).Scan(&have)
	if errors.Is(err, sql.ErrNoRows) {
		have = 0
	} else if err != nil {
		return fmt.Errorf("store: read schema version: %w", err)
	}
	if have < want {
		return fmt.Errorf("store: schema is not current: database at migration %d, this binary needs %d", have, want)
	}
	return nil
}
