package store

import (
	"context"
	"fmt"
	"strings"
)

const siemSinksTable = "siem_sinks"

// siemSinkNewColumns are the columns an old siem_sinks lacks: the event filter and the S3 region and access
// key id (issue #498). Each takes its default on existing rows.
var siemSinkNewColumns = [][2]string{
	{"event_filter", "TEXT NOT NULL DEFAULT '[]'"},
	{"region", "TEXT NOT NULL DEFAULT ''"},
	{"access_key_id", "TEXT NOT NULL DEFAULT ''"},
}

// upgradeSiemSinks lets a SQLite database created before the S3 sink kind and the per-sink event filter
// take them. CREATE TABLE IF NOT EXISTS can neither widen a CHECK nor add a column, and the table holds
// sealed tokens that must survive. Like upgradeGrpInboxKinds, the table is rebuilt in place in one
// transaction when its kind CHECK is the narrow one (a new table, every row copied, the old one dropped and
// the new one renamed, the table's own indexes and triggers recreated; foreign keys are off for the rebuild
// and checked before it commits); then the missing columns are added. It does nothing when the table is
// missing or already current, so running it on every open is safe. Postgres does this in migration 0750.
func (d *DB) upgradeSiemSinks(ctx context.Context) error {
	var def string
	if err := d.sql.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?`, siemSinksTable).Scan(&def); err != nil {
		return nil // no such table yet: the schema files create it as it should be
	}
	const narrow = "CHECK (kind IN ('syslog','webhook'))"
	if strings.Contains(def, narrow) {
		if err := d.rebuildSiemSinks(ctx, strings.Replace(def, narrow, "CHECK (kind IN ('syslog','webhook','s3'))", 1)); err != nil {
			return err
		}
	}
	return d.addMissingColumns(ctx, siemSinksTable, siemSinkNewColumns)
}

func (d *DB) rebuildSiemSinks(ctx context.Context, wider string) error {
	conn, err := d.sql.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	var fk int
	if err := conn.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&fk); err != nil {
		return err
	}
	for _, p := range []string{"PRAGMA foreign_keys = OFF", "PRAGMA legacy_alter_table = ON"} {
		if _, err := conn.ExecContext(ctx, p); err != nil {
			return err
		}
	}
	defer func() {
		_, _ = conn.ExecContext(ctx, "PRAGMA legacy_alter_table = OFF")
		if fk == 1 {
			_, _ = conn.ExecContext(ctx, "PRAGMA foreign_keys = ON")
		}
	}()
	rows, err := conn.QueryContext(ctx, `SELECT sql FROM sqlite_master WHERE tbl_name = ? AND type IN ('index','trigger') AND sql IS NOT NULL ORDER BY type DESC, name`, siemSinksTable)
	if err != nil {
		return err
	}
	var recreate []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			_ = rows.Close()
			return err
		}
		recreate = append(recreate, s)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	tmp := siemSinksTable + "_upgrade"
	wider = strings.Replace(wider, siemSinksTable, tmp, 1)
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	steps := append([]string{wider,
		"INSERT INTO " + tmp + " SELECT * FROM " + siemSinksTable,
		"DROP TABLE " + siemSinksTable,
		"ALTER TABLE " + tmp + " RENAME TO " + siemSinksTable}, recreate...)
	for _, s := range steps {
		if _, err := tx.ExecContext(ctx, s); err != nil { // #nosec G202 -- fixed names and the database's own DDL
			_ = tx.Rollback()
			return fmt.Errorf("store: upgrade %s: %w", siemSinksTable, err)
		}
	}
	var bad int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM pragma_foreign_key_check`).Scan(&bad); err != nil {
		_ = tx.Rollback()
		return err
	}
	if bad > 0 {
		_ = tx.Rollback()
		return fmt.Errorf("store: upgrade %s: %d rows break a foreign key", siemSinksTable, bad)
	}
	return tx.Commit()
}
