package store

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// A SQLite database whose provisioning_ops has the CHECK of before the AWS operation kinds (issue #660) takes them on
// open: the rows and the findings that point at them are kept, the indexes and guard triggers come back, every AWS
// kind is accepted, an unknown kind is still refused, and a second open changes nothing.
func TestUpgradeProvOpKinds_KeepsRowsAndWidensTheCheck(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "ops.db")
	d, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	var ddl string
	if err := d.sql.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE name = 'provisioning_ops'`).Scan(&ddl); err != nil {
		t.Fatal(err)
	}
	old := strings.Replace(ddl, ",\n    "+awsOpKindList, "", 1)
	if old == ddl {
		t.Fatal("the schema does not list the AWS kinds")
	}
	rows, err := d.sql.QueryContext(ctx, `SELECT sql FROM sqlite_master WHERE tbl_name = 'provisioning_ops' AND type IN ('index','trigger') AND sql IS NOT NULL`)
	if err != nil {
		t.Fatal(err)
	}
	var extra []string
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		extra = append(extra, s)
	}
	_ = rows.Close()
	if len(extra) < 4 {
		t.Fatalf("indexes and triggers on provisioning_ops = %d", len(extra))
	}
	insertOp := func(d *DB, id, kind string) error {
		_, err := d.sql.ExecContext(ctx, `INSERT INTO provisioning_ops (id, tenant_id, connection_id, kind, target_ref, payload, source, idempotency_key, status, next_attempt_at, requested_by, created_at, updated_at)
			VALUES (?, 't1', 'c1', ?, 'x', '{}', 'test', ?, 'queued', 'x', 'a', 'x', 'x')`, id, kind, id)
		return err
	}
	exec := func(q string) {
		t.Helper()
		if _, err := d.sql.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	d.sql.SetMaxOpenConns(1) // PRAGMA foreign_keys is per connection
	exec(`PRAGMA foreign_keys = OFF`)
	exec(`DROP TABLE provisioning_ops`)
	exec(old)
	for _, q := range extra {
		exec(q)
	}
	exec(`INSERT INTO tenants (id, slug, name, created_at) VALUES ('t1', 'tenant-one', 'One', '2026-10-01T00:00:00Z')`)
	exec(`INSERT INTO connections (id, tenant_id, name, connector_type, system, created_at, updated_at) VALUES ('c1', 't1', 'c', 'demo-okta', 'okta', 'x', 'x')`)
	if err := insertOp(d, "op1", "disable_account"); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO provisioning_findings (id, tenant_id, op_id, connection_id, code, severity, title, expected, observed, created_at)
		VALUES ('f1', 't1', 'op1', 'c1', 'verify_mismatch', 'high', 't', 'e', 'o', 'x')`)
	if err := insertOp(d, "op2", "aws_detach_policy"); err == nil {
		t.Fatal("the old table accepted an AWS kind")
	}
	_ = d.Close()

	for pass := 0; pass < 2; pass++ { // the second open finds nothing to do
		d, err = Open(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		var kind string
		var findings int
		if err := d.sql.QueryRowContext(ctx, `SELECT kind FROM provisioning_ops WHERE id = 'op1'`).Scan(&kind); err != nil || kind != "disable_account" {
			t.Fatalf("pass %d: row after the upgrade: %q %v", pass, kind, err)
		}
		if err := d.sql.QueryRowContext(ctx, `SELECT count(*) FROM provisioning_findings WHERE op_id = 'op1'`).Scan(&findings); err != nil || findings != 1 {
			t.Fatalf("pass %d: findings after the upgrade: %d %v", pass, findings, err)
		}
		if pass == 0 {
			for i, k := range []string{"aws_detach_policy", "aws_delete_inline_policy", "aws_set_policy_version", "aws_remove_from_group", "aws_delete_assignment",
				"aws_attach_policy", "aws_put_inline_policy", "aws_restore_policy_version", "aws_add_to_group", "aws_create_assignment"} {
				if err := insertOp(d, fmt.Sprintf("a%d", i), k); err != nil {
					t.Errorf("kind %s refused after the upgrade: %v", k, err)
				}
			}
			if err := insertOp(d, "bad", "aws_nuke"); err == nil {
				t.Error("an unknown kind was accepted")
			}
			var n int
			if err := d.sql.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE tbl_name = 'provisioning_ops' AND type IN ('index','trigger')`).Scan(&n); err != nil || n < len(extra) {
				t.Errorf("indexes and triggers on provisioning_ops = %d (want %d), %v", n, len(extra), err)
			}
		}
		_ = d.Close()
	}
}
