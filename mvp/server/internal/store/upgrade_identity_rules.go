package store

import "context"

// upgradeIdentityRules adds identity_rules.dormant_people_days to a SQLite database created before it. Postgres does
// this in migration 0975.
func (d *DB) upgradeIdentityRules(ctx context.Context) error {
	return d.addMissingColumns(ctx, "identity_rules", [][2]string{
		{"dormant_people_days", "INTEGER NOT NULL DEFAULT 90 CHECK (dormant_people_days BETWEEN 1 AND 3650)"}})
}
