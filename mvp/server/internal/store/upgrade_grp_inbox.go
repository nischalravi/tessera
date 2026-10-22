package store

import (
	"context"
	"fmt"
	"strings"
)

const grpInboxTable = "grp_inbox_tasks"

// grpInboxReplacements widen the CHECKs of an old grp_inbox_tasks: the task kind deletion_held and the
// object type deletion_hold (a task for a held deletion, internal/deleteguard).
var grpInboxReplacements = [][2]string{
	{"'attestation_overdue'))", "'attestation_overdue','deletion_held'))"},
	{"object_type IN ('folder','group'))", "object_type IN ('folder','group','deletion_hold'))"},
}

// upgradeGrpInboxKinds widens the kind and object_type CHECKs of grp_inbox_tasks in a SQLite database created
// before the deletion_held task existed (CREATE TABLE IF NOT EXISTS cannot change a CHECK). Like
// upgradeAdminChangeTypes, the table is rebuilt in place in one transaction: a new table with the wider
// definition, every row copied as it is, the old table dropped, the new one renamed, and the table's own
// indexes and triggers recreated; foreign keys are off for the rebuild and checked before it commits. It does
// nothing when the table is missing or already admits the kind, so running it on every open is safe. Postgres
// changes the CHECKs in migration 0691.
func (d *DB) upgradeGrpInboxKinds(ctx context.Context) error {
	var def string
	err := d.sql.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?`, grpInboxTable).Scan(&def)
	if err != nil {
		return nil // no such table yet: the schema files create it with the wider CHECKs
	}
	wider, changed := def, false
	for _, r := range grpInboxReplacements {
		if strings.Contains(wider, r[0]) {
			wider, changed = strings.Replace(wider, r[0], r[1], 1), true
		}
	}
	if !changed {
		return nil
	}
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
	rows, err := conn.QueryContext(ctx, `SELECT sql FROM sqlite_master WHERE tbl_name = ? AND type IN ('index','trigger') AND sql IS NOT NULL ORDER BY type DESC, name`, grpInboxTable)
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
	tmp := grpInboxTable + "_upgrade"
	wider = strings.Replace(wider, grpInboxTable, tmp, 1)
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	steps := append([]string{wider,
		"INSERT INTO " + tmp + " SELECT * FROM " + grpInboxTable,
		"DROP TABLE " + grpInboxTable,
		"ALTER TABLE " + tmp + " RENAME TO " + grpInboxTable}, recreate...)
	for _, s := range steps {
		if _, err := tx.ExecContext(ctx, s); err != nil { // #nosec G202 -- fixed names and the database's own DDL
			_ = tx.Rollback()
			return fmt.Errorf("store: upgrade %s: %w", grpInboxTable, err)
		}
	}
	var bad int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM pragma_foreign_key_check`).Scan(&bad); err != nil {
		_ = tx.Rollback()
		return err
	}
	if bad > 0 {
		_ = tx.Rollback()
		return fmt.Errorf("store: upgrade %s: %d rows break a foreign key", grpInboxTable, bad)
	}
	return tx.Commit()
}
