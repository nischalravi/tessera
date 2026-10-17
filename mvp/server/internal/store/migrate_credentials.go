package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// CredentialMigration reports what MigrateCredentials moved.
type CredentialMigration struct {
	Bind        int // connection_secrets rows re-sealed as purpose "bind"
	Containment int // containment_credentials rows re-sealed as purpose "containment"
	Orphaned    int // connection_secrets rows no revision referenced; dropped, never readable
}

// The two tables merged into connection_credentials (#220). Their DDL is gone
// from schema/, so a database that still has them is from an older server.
const (
	legacySecretsTable     = "connection_secrets"
	legacyContainmentTable = "containment_credentials"
)

// MigrateCredentials moves the rows of connection_secrets and
// containment_credentials into connection_credentials and drops the old
// tables, in one transaction. The AAD of a sealed blob names its table, column
// and row, so each blob is opened with its old AAD and re-sealed with the new
// one (CredentialAAD); copying the bytes would leave them unreadable.
//
// It is idempotent: with neither old table present it does nothing. It fails
// closed: a blob that cannot be opened (a different KEK, a tampered row), or
// rows to move with no sealer, abort the whole migration and the old tables
// stay as they were. Run it with the KEK after Open and before serving.
//
// It is the one place that reads across tenants, so it is not a TenantTx
// statement: every row keeps its own tenant_id, and the guard trigger of the
// new table still refuses a reference to another tenant's connection.
func (d *DB) MigrateCredentials(ctx context.Context, sealer *seal.Sealer) (CredentialMigration, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var res CredentialMigration
	hasSecrets, err := d.tableExists(ctx, legacySecretsTable)
	if err != nil {
		return res, err
	}
	hasContainment, err := d.tableExists(ctx, legacyContainmentTable)
	if err != nil {
		return res, err
	}
	if !hasSecrets && !hasContainment {
		return res, nil
	}
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return res, fmt.Errorf("store: migrate credentials: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // a no-op after Commit

	if hasSecrets {
		if res.Bind, res.Orphaned, err = migrateBindSecrets(ctx, tx, sealer); err != nil {
			return CredentialMigration{}, err
		}
	}
	if hasContainment {
		if res.Containment, err = migrateContainment(ctx, tx, sealer); err != nil {
			return CredentialMigration{}, err
		}
	}
	for _, t := range []struct {
		name string
		has  bool
	}{{legacySecretsTable, hasSecrets}, {legacyContainmentTable, hasContainment}} {
		if !t.has {
			continue
		}
		// t.name is one of the two constants above, never input.
		if _, err := tx.ExecContext(ctx, "DROP TABLE "+t.name); err != nil { // #nosec G202 -- fixed table names
			return CredentialMigration{}, fmt.Errorf("store: migrate credentials: drop %s: %w", t.name, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return CredentialMigration{}, fmt.Errorf("store: migrate credentials: commit: %w", err)
	}
	return res, nil
}

func (d *DB) tableExists(ctx context.Context, name string) (bool, error) {
	var n int
	err := d.sql.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&n)
	return n == 1, err
}

const insertMigratedRow = `
	INSERT INTO connection_credentials (tenant_id, connection_id, purpose, ref, sealed, base_url, org, updated_by, updated_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

// migrateBindSecrets moves connection_secrets. The old key was (tenant, ref)
// and the connection is the one whose revisions carry that ref; a row no
// revision references can never be read again and is dropped (counted).
func migrateBindSecrets(ctx context.Context, tx *sql.Tx, sealer *seal.Sealer) (moved, orphaned int, err error) {
	type row struct {
		tenant, ref, created string
		conn                 sql.NullString
		sealed               []byte
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT s.tenant_id, s.secret_ref, s.sealed, s.created_at,
			(SELECT min(r.connection_id) FROM connection_revisions r
			 WHERE r.tenant_id = s.tenant_id AND r.secret_ref = s.secret_ref)
		FROM connection_secrets s ORDER BY s.tenant_id, s.secret_ref`)
	if err != nil {
		return 0, 0, fmt.Errorf("store: migrate credentials: read %s: %w", legacySecretsTable, err)
	}
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.tenant, &r.ref, &r.sealed, &r.created, &r.conn); err != nil {
			_ = rows.Close()
			return 0, 0, err
		}
		all = append(all, r)
	}
	if err := rows.Close(); err != nil {
		return 0, 0, err
	}
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}
	for _, r := range all {
		if !r.conn.Valid {
			orphaned++
			continue
		}
		t, err := parseMigratedTenant(r.tenant)
		if err != nil {
			return 0, 0, err
		}
		if sealer == nil {
			return 0, 0, errNoSealerToMigrate
		}
		pt, err := sealer.Open(r.sealed, seal.AAD(t, legacySecretsTable, "sealed", r.ref))
		if err != nil {
			return 0, 0, fmt.Errorf("store: migrate credentials: %s row %q of tenant %s cannot be opened: %w",
				legacySecretsTable, r.ref, r.tenant, err)
		}
		blob, err := sealer.Seal(pt, CredentialAAD(t, r.conn.String, PurposeBind, r.ref))
		if err != nil {
			return 0, 0, err
		}
		if _, err := tx.ExecContext(ctx, insertMigratedRow, r.tenant, r.conn.String, PurposeBind, r.ref, blob,
			"", "", "migration", r.created); err != nil {
			return 0, 0, fmt.Errorf("store: migrate credentials: insert: %w", err)
		}
		moved++
	}
	return moved, orphaned, nil
}

// migrateContainment moves containment_credentials.
func migrateContainment(ctx context.Context, tx *sql.Tx, sealer *seal.Sealer) (moved int, err error) {
	type row struct {
		tenant, conn, baseURL, org, by, at string
		enc                                []byte
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT k.tenant_id, k.connection_id, k.base_url, k.org, k.token_enc, k.updated_by, k.updated_at
		FROM containment_credentials k ORDER BY k.tenant_id, k.connection_id`)
	if err != nil {
		return 0, fmt.Errorf("store: migrate credentials: read %s: %w", legacyContainmentTable, err)
	}
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.tenant, &r.conn, &r.baseURL, &r.org, &r.enc, &r.by, &r.at); err != nil {
			_ = rows.Close()
			return 0, err
		}
		all = append(all, r)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, r := range all {
		t, err := parseMigratedTenant(r.tenant)
		if err != nil {
			return 0, err
		}
		if sealer == nil {
			return 0, errNoSealerToMigrate
		}
		pt, err := sealer.Open(r.enc, seal.AAD(t, legacyContainmentTable, "token_enc", r.conn))
		if err != nil {
			return 0, fmt.Errorf("store: migrate credentials: %s row of connection %q (tenant %s) cannot be opened: %w",
				legacyContainmentTable, r.conn, r.tenant, err)
		}
		blob, err := sealer.Seal(pt, CredentialAAD(t, r.conn, PurposeContainment, ""))
		if err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, insertMigratedRow, r.tenant, r.conn, PurposeContainment, "", blob,
			r.baseURL, r.org, r.by, r.at); err != nil {
			return 0, fmt.Errorf("store: migrate credentials: insert: %w", err)
		}
		moved++
	}
	return moved, nil
}

var errNoSealerToMigrate = fmt.Errorf("store: migrate credentials: sealed credentials exist but no KEK is configured")

func parseMigratedTenant(s string) (tenancy.ID, error) {
	t, err := tenancy.Parse(s)
	if err != nil {
		return t, fmt.Errorf("store: migrate credentials: bad tenant id: %w", err)
	}
	return t, nil
}
