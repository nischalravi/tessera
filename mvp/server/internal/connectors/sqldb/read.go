package sqldb

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// rowset is the result of one read: values as text, NULL as "".
type rowset struct {
	Cols      []string
	Rows      [][]string
	Truncated bool // the row cap was reached; more rows exist
}

// beginRead starts the transaction of a read. PostgreSQL and MySQL are asked
// for a read-only transaction. Their drivers support it; go-mssqldb and go-ora
// refuse the option, so Oracle takes SET TRANSACTION READ ONLY (a fixed
// statement) and SQL Server relies on the statement being a fixed catalogue
// query or a validated SELECT, on an ApplicationIntent=ReadOnly connection.
func beginRead(ctx context.Context, db *sql.DB, engine string) (*sql.Tx, error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: engine == Postgres || engine == MySQL})
	if err != nil {
		return nil, err
	}
	if engine == Oracle {
		if _, err := tx.ExecContext(ctx, "SET TRANSACTION READ ONLY"); err != nil {
			_ = tx.Rollback()
			return nil, err
		}
	}
	return tx, nil
}

// query runs one read in a read-only transaction with a timeout and returns at
// most maxRows rows. The transaction is always rolled back.
func query(ctx context.Context, db *sql.DB, engine string, timeout time.Duration, maxRows int, q string, args ...any) (rowset, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var rs rowset
	tx, err := beginRead(ctx, db, engine)
	if err != nil {
		return rs, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return rs, err
	}
	defer rows.Close()
	if rs.Cols, err = rows.Columns(); err != nil {
		return rs, err
	}
	for rows.Next() {
		if len(rs.Rows) >= maxRows {
			rs.Truncated = true
			break
		}
		vals := make([]any, len(rs.Cols))
		ptrs := make([]any, len(vals))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return rs, err
		}
		row := make([]string, len(vals))
		for i, v := range vals {
			row[i] = text(v)
		}
		rs.Rows = append(rs.Rows, row)
	}
	return rs, rows.Err()
}

func text(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case []byte:
		return string(x)
	case time.Time:
		return x.UTC().Format(time.RFC3339)
	case bool:
		return strconv.FormatBool(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return fmt.Sprint(v)
}

// col is the index of a column by case-insensitive name, or -1.
func (r rowset) col(name string) int {
	for i, c := range r.Cols {
		if strings.EqualFold(c, name) {
			return i
		}
	}
	return -1
}

// pair reads a two-column rowset (an error if it has fewer columns).
func (r rowset) need(n int) error {
	if len(r.Cols) < n {
		return fmt.Errorf("the statement returned %d columns, want %d", len(r.Cols), n)
	}
	return nil
}

// catalog is what a native-mode read found.
type catalog struct {
	Accounts []catAccount
	Roles    []string // entitlement ids, prefix included
	Members  [][2]string
	Privs    [][2]string
	Partial  string // why the read is incomplete, empty when complete
}

type catAccount struct{ Name, Status string }

// readCatalog runs the engine's fixed catalogue statements.
func readCatalog(ctx context.Context, db *sql.DB, c Config) (*catalog, error) {
	cq, ok := catalogues[c.Engine]
	if !ok {
		return nil, fmt.Errorf("unknown engine %q", c.Engine)
	}
	out := &catalog{}
	run := func(what, q string, n int) (rowset, error) {
		rs, err := query(ctx, db, c.Engine, c.timeout(), c.maxRows(), q)
		if err == nil {
			err = rs.need(n)
		}
		if err != nil {
			return rs, fmt.Errorf("%s: %w", what, err)
		}
		if rs.Truncated {
			out.Partial = fmt.Sprintf("%s: more than %d rows, the read stopped at the cap", what, c.maxRows())
		}
		return rs, nil
	}
	rs, err := run("accounts", cq.Accounts, 2)
	if err != nil {
		return nil, err
	}
	for _, r := range rs.Rows {
		out.Accounts = append(out.Accounts, catAccount{r[0], r[1]})
	}
	for _, p := range cq.Roles {
		rs, err := run("roles", p.SQL, 1)
		if err != nil {
			return nil, err
		}
		for _, r := range rs.Rows {
			out.Roles = append(out.Roles, p.Prefix+r[0])
		}
	}
	for _, p := range cq.Members {
		rs, err := run("members", p.SQL, 2)
		if err != nil {
			return nil, err
		}
		for _, r := range rs.Rows {
			out.Members = append(out.Members, [2]string{r[0], p.Prefix + r[1]})
		}
	}
	rs, err = run("privileges", cq.Privs, 2)
	if err != nil {
		return nil, err
	}
	for _, r := range rs.Rows {
		out.Privs = append(out.Privs, [2]string{r[0], r[1]})
	}
	return out, nil
}
