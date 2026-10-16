package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ExtSQLite is the database of the SQL provisioning target (GR-11): a SQLite
// file in an operator-chosen directory (TESSERA_GROUPS_PROV_SQL_DIR) holding
// one table of (group_name, member) rows for applications that read group
// memberships from SQL.
//
// This is not tenant data and not Tessera's own database, so it is outside the
// tenant statements; the archtest keeps database/sql inside this package, which
// is why it lives here. Every statement is a constant with bound parameters
// and a fixed table name; nothing from a tenant's configuration is ever
// concatenated into SQL. A tenant chooses only a file name, which must be a
// plain name inside the operator's directory, and a file that holds Tessera's
// own tables is refused.

// ExtSQLiteTable is the fixed table the target writes.
const ExtSQLiteTable = "tessera_group_members"

// ErrExtSQLite is returned for an unusable target database.
var ErrExtSQLite = errors.New("store: SQL target database")

var extFileRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}\.(db|sqlite|sqlite3)$`)

// ExtPair is one membership row.
type ExtPair struct{ Group, Member string }

// ExtSQLite is an open target database.
type ExtSQLite struct{ db *sql.DB }

const (
	extCreate = `CREATE TABLE IF NOT EXISTS tessera_group_members (
		group_name TEXT NOT NULL, member TEXT NOT NULL, PRIMARY KEY (group_name, member)) WITHOUT ROWID`
	extForeign  = `SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name IN ('tenants','identities','grp_events')`
	extReadAll  = `SELECT group_name, member FROM tessera_group_members ORDER BY group_name, member`
	extReadOne  = `SELECT group_name, member FROM tessera_group_members WHERE group_name = @g ORDER BY member`
	extInsert   = `INSERT OR IGNORE INTO tessera_group_members (group_name, member) VALUES (@g, @m)`
	extDeletion = `DELETE FROM tessera_group_members WHERE group_name = @g AND member = @m`
)

// ValidExtSQLiteName reports whether name is an acceptable database file name.
func ValidExtSQLiteName(name string) bool {
	return extFileRE.MatchString(name) && !strings.Contains(name, "..")
}

// OpenExtSQLite opens (creating if needed) file name inside dir. dir is the
// operator's setting; name is a plain file name from the tenant's configuration.
func OpenExtSQLite(ctx context.Context, dir, name string) (*ExtSQLite, error) {
	if dir == "" {
		return nil, fmt.Errorf("%w: no directory is configured (TESSERA_GROUPS_PROV_SQL_DIR)", ErrExtSQLite)
	}
	if !ValidExtSQLiteName(name) {
		return nil, fmt.Errorf("%w: file must be a plain name ending in .db, .sqlite or .sqlite3", ErrExtSQLite)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrExtSQLite, err)
	}
	path := filepath.Join(dir, name)
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "journal_mode(WAL)")
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrExtSQLite, err)
	}
	db.SetMaxOpenConns(1)
	x := &ExtSQLite{db: db}
	var n int
	if err := db.QueryRowContext(ctx, extForeign).Scan(&n); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("%w: %v", ErrExtSQLite, err)
	}
	if n > 0 {
		_ = db.Close()
		return nil, fmt.Errorf("%w: %s holds Tessera tables", ErrExtSQLite, name)
	}
	if _, err := db.ExecContext(ctx, extCreate); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("%w: %v", ErrExtSQLite, err)
	}
	return x, nil
}

// Close closes the database.
func (x *ExtSQLite) Close() error { return x.db.Close() }

// Members returns the rows of the named groups, or of every group when groups is nil.
func (x *ExtSQLite) Members(ctx context.Context, groups []string) (map[string][]string, error) {
	out := map[string][]string{}
	read := func(q string, args ...any) error {
		rows, err := x.db.QueryContext(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var g, m string
			if err := rows.Scan(&g, &m); err != nil {
				return err
			}
			out[g] = append(out[g], m)
		}
		return rows.Err()
	}
	if groups == nil {
		return out, read(extReadAll)
	}
	for _, g := range groups {
		if err := read(extReadOne, sql.Named("g", g)); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Apply deletes remove and inserts add in one transaction.
func (x *ExtSQLite) Apply(ctx context.Context, add, remove []ExtPair) (err error) {
	tx, err := x.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	for _, p := range remove {
		if _, err = tx.ExecContext(ctx, extDeletion, sql.Named("g", p.Group), sql.Named("m", p.Member)); err != nil {
			return err
		}
	}
	for _, p := range add {
		if _, err = tx.ExecContext(ctx, extInsert, sql.Named("g", p.Group), sql.Named("m", p.Member)); err != nil {
			return err
		}
	}
	return tx.Commit()
}
