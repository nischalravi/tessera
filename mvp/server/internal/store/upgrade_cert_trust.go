package store

import "context"

// upgradeCertTrust adds tenant_certificates.trust_pem (issue #498) to a SQLite database created before it.
// Postgres does this in migration 0750.
func (d *DB) upgradeCertTrust(ctx context.Context) error {
	return d.addMissingColumns(ctx, "tenant_certificates", [][2]string{{"trust_pem", "TEXT NOT NULL DEFAULT ''"}})
}
