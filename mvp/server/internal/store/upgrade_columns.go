package store

import (
	"context"
	"fmt"
)

// addMissingColumns adds each (name, definition) column an existing table lacks; a table that does not exist
// yet is left to the schema files. The names and definitions are fixed lists, never input.
func (d *DB) addMissingColumns(ctx context.Context, table string, cols [][2]string) error {
	var exists int
	if err := d.sql.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&exists); err != nil || exists == 0 {
		return err
	}
	for _, c := range cols {
		var n int
		if err := d.sql.QueryRowContext(ctx, `SELECT count(*) FROM pragma_table_info(?) WHERE name = ?`, table, c[0]).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			if _, err := d.sql.ExecContext(ctx, "ALTER TABLE "+table+" ADD COLUMN "+c[0]+" "+c[1]); err != nil { // #nosec G202 -- fixed names
				return fmt.Errorf("store: upgrade %s: %w", table, err)
			}
		}
	}
	return nil
}
