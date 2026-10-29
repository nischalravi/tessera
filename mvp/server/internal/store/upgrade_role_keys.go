package store

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// RoleKeyMax is the longest role key (policybundle's key pattern allows 64 characters).
const RoleKeyMax = 64

// RoleKeySlug makes a role key from its name: lower-case letters and digits, runs of anything else
// as one '-', at most 56 characters (room for a numeric suffix), "role" when nothing is left. taken
// says whether a key is in use; a taken slug gets -2, -3, ... until it is free.
func RoleKeySlug(name string, taken func(string) bool) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			if dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			dash = false
			b.WriteRune(r)
		} else {
			dash = true
		}
	}
	base := b.String()
	if len(base) > RoleKeyMax-8 {
		base = strings.TrimRight(base[:RoleKeyMax-8], "-")
	}
	if base == "" {
		base = "role"
	}
	key := base
	for n := 2; taken(key); n++ {
		key = base + "-" + strconv.Itoa(n)
	}
	return key
}

// upgradeRoleKeys adds business_roles.key and business_role_versions.policy_ref (issue #650) to a SQLite
// database created before them, and gives every role without a key the slug of its name, in creation
// order, unique within its tenant. Postgres does this in migration 0951. It does nothing once every role has a key.
func (d *DB) upgradeRoleKeys(ctx context.Context) error {
	if err := d.addMissingColumns(ctx, "business_roles", [][2]string{{"key", "TEXT"}}); err != nil {
		return err
	}
	if err := d.addMissingColumns(ctx, "business_role_versions", [][2]string{{"policy_ref", "TEXT"}}); err != nil {
		return err
	}
	var exists int
	if err := d.sql.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'business_roles'`).Scan(&exists); err != nil || exists == 0 {
		return err
	}
	rows, err := d.sql.QueryContext(ctx, `SELECT id, tenant_id, name, key FROM business_roles ORDER BY tenant_id, created_at, id`)
	if err != nil {
		return err
	}
	type row struct{ id, tenant, name string }
	var missing []row
	used := map[string]bool{}
	for rows.Next() {
		var r row
		var key *string
		if err := rows.Scan(&r.id, &r.tenant, &r.name, &key); err != nil {
			_ = rows.Close()
			return err
		}
		if key != nil {
			used[r.tenant+"\x00"+*key] = true
		} else {
			missing = append(missing, r)
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, r := range missing {
		key := RoleKeySlug(r.name, func(k string) bool { return used[r.tenant+"\x00"+k] })
		used[r.tenant+"\x00"+key] = true
		if _, err := d.sql.ExecContext(ctx, `UPDATE business_roles SET key = ? WHERE id = ? AND tenant_id = ? AND key IS NULL`, key, r.id, r.tenant); err != nil {
			return fmt.Errorf("store: upgrade business_roles: %w", err)
		}
	}
	return rows.Err()
}
