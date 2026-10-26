package store

import (
	"context"
	"fmt"
	"strings"
)

const provOpTable = "provisioning_ops"

// awsOpKindList is the operation kinds of the AWS write target (issue #660), in the order the schema file lists them.
const awsOpKindList = "'aws_detach_policy','aws_delete_inline_policy','aws_set_policy_version',\n" +
	"    'aws_remove_from_group','aws_delete_assignment','aws_attach_policy',\n" +
	"    'aws_put_inline_policy','aws_restore_policy_version','aws_add_to_group',\n" +
	"    'aws_create_assignment'"

// upgradeProvOpKinds widens the kind CHECK of provisioning_ops in a SQLite database created before the AWS operation
// kinds existed (CREATE TABLE IF NOT EXISTS cannot change a CHECK). Other tables point at provisioning_ops, so the
// table is rebuilt the way admin_change_requests is (upgradeAdminChangeTypes): in one transaction, with foreign keys
// off for the rebuild and checked before it commits, every row copied as it is, and the table's own indexes and
// triggers recreated. It does nothing when the table is missing or already admits the kinds, so running it on every
// open is safe. Postgres changes the CHECK in migration 0944.
func (d *DB) upgradeProvOpKinds(ctx context.Context) error {
	var def string
	err := d.sql.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?`, provOpTable).Scan(&def)
	const tail = "'add_entitlement','remove_entitlement')"
	if err != nil || strings.Contains(def, "'aws_detach_policy'") || !strings.Contains(def, tail) {
		return nil // no such table yet (the schema files create it with the wider CHECK), or nothing to widen
	}
	wider := strings.Replace(def, tail, "'add_entitlement','remove_entitlement',\n    "+awsOpKindList+")", 1)
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
	rows, err := conn.QueryContext(ctx, `SELECT sql FROM sqlite_master WHERE tbl_name = ? AND type IN ('index','trigger') AND sql IS NOT NULL ORDER BY type DESC, name`, provOpTable)
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
	tmp := provOpTable + "_upgrade"
	wider = strings.Replace(wider, provOpTable, tmp, 1) // the name after CREATE TABLE [IF NOT EXISTS]
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	steps := append([]string{wider,
		"INSERT INTO " + tmp + " SELECT * FROM " + provOpTable,
		"DROP TABLE " + provOpTable,
		"ALTER TABLE " + tmp + " RENAME TO " + provOpTable}, recreate...)
	for _, s := range steps {
		if _, err := tx.ExecContext(ctx, s); err != nil { // #nosec G202 -- fixed names and the database's own DDL
			_ = tx.Rollback()
			return fmt.Errorf("store: upgrade %s: %w", provOpTable, err)
		}
	}
	var bad int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM pragma_foreign_key_check`).Scan(&bad); err != nil {
		_ = tx.Rollback()
		return err
	}
	if bad > 0 {
		_ = tx.Rollback()
		return fmt.Errorf("store: upgrade %s: %d rows break a foreign key", provOpTable, bad)
	}
	return tx.Commit()
}
