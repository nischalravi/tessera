package store

import (
	"context"
	"fmt"
	"strings"
)

const adminChangeTable = "admin_change_requests"

// adminChangeNewTypes are the types an old CHECK may lack, each with the one it is placed after, in order.
var adminChangeNewTypes = [][2]string{
	{"'groups.folder.delete_recursive'", "'groups.loader.save'"},
	{"'deletion_guard.update'", "'groups.folder.delete_recursive'"},
	{"'siem.sink.filter'", "'deletion_guard.update'"},
	{"'siem.sink.target'", "'siem.sink.filter'"},
	{"'alerts.rule.loosen'", "'siem.sink.target'"},
	{"'breach.item.attest'", "'alerts.rule.loosen'"},
	{"'provisioning.write_back.enable'", "'breach.item.attest'"},
	{"'lp.settings.update'", "'provisioning.write_back.enable'"},
	{"'roles.bundle.apply'", "'lp.settings.update'"},
	{"'config.proposal'", "'roles.bundle.apply'"},
	{"'api_client.propose.grant'", "'config.proposal'"},
	{"'jit.bundle.apply'", "'api_client.propose.grant'"},
}

// upgradeAdminChangeTypes widens the type CHECK of admin_change_requests in a SQLite database created before
// groups.folder.delete_recursive existed (CREATE TABLE IF NOT EXISTS cannot change a CHECK). The table is rebuilt
// in one transaction: new table with the same definition and the wider CHECK, every row copied as it is, old
// table dropped, new one renamed, and the table's own indexes and triggers recreated. Foreign keys are off for
// the rebuild (and checked before it commits), so the tables that point at it keep their rows. It does nothing
// when the table is missing or already admits the type, so running it on every open is safe. Postgres changes
// the CHECK in migrations 0640, 0671, 0770, 0790, 0820, 0937, 0950, 0952, 0956 and 0958.
func (d *DB) upgradeAdminChangeTypes(ctx context.Context) error {
	var def string
	err := d.sql.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?`, adminChangeTable).Scan(&def)
	if err != nil {
		return nil // no such table yet: the schema files create it with the wider CHECK
	}
	wider, changed := def, false
	for _, t := range adminChangeNewTypes {
		if !strings.Contains(wider, t[0]) && strings.Contains(wider, t[1]) {
			wider, changed = strings.Replace(wider, t[1], t[1]+",\n    "+t[0], 1), true
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

	rows, err := conn.QueryContext(ctx, `SELECT sql FROM sqlite_master WHERE tbl_name = ? AND type IN ('index','trigger') AND sql IS NOT NULL ORDER BY type DESC, name`, adminChangeTable)
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

	tmp := adminChangeTable + "_upgrade"
	wider = strings.Replace(wider, adminChangeTable, tmp, 1) // the name after CREATE TABLE [IF NOT EXISTS]
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	steps := append([]string{wider,
		"INSERT INTO " + tmp + " SELECT * FROM " + adminChangeTable,
		"DROP TABLE " + adminChangeTable,
		"ALTER TABLE " + tmp + " RENAME TO " + adminChangeTable}, recreate...)
	for _, s := range steps {
		if _, err := tx.ExecContext(ctx, s); err != nil { // #nosec G202 -- fixed names and the database's own DDL
			_ = tx.Rollback()
			return fmt.Errorf("store: upgrade %s: %w", adminChangeTable, err)
		}
	}
	var bad int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM pragma_foreign_key_check`).Scan(&bad); err != nil {
		_ = tx.Rollback()
		return err
	}
	if bad > 0 {
		_ = tx.Rollback()
		return fmt.Errorf("store: upgrade %s: %d rows break a foreign key", adminChangeTable, bad)
	}
	return tx.Commit()
}
