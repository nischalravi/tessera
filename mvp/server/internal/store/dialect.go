package store

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// dialect is the SQL dialect a DB speaks. Every registered statement is
// written once, in SQLite's dialect with @name parameters; for Postgres the
// executors translate it (translatePG) and the schema comes from
// schema/postgres. SQLite is the default and is never translated.
type dialect int

const (
	dialectSQLite dialect = iota
	dialectPostgres
)

// IsPostgresDSN reports whether a database setting is a Postgres connection
// URL (postgres:// or postgresql://) rather than a SQLite path.
func IsPostgresDSN(s string) bool {
	return strings.HasPrefix(s, "postgres://") || strings.HasPrefix(s, "postgresql://")
}

// xtx is a transaction that translates statements for its dialect. It has the
// method set of *sql.Tx that the store uses.
type xtx struct {
	tx *sql.Tx
	d  dialect
}

func (x *xtx) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	if x.d == dialectSQLite {
		return x.tx.ExecContext(ctx, q, args...)
	}
	if isSavepointControl(q) {
		// a caller's own savepoint (TenantTx.Savepoint): wrapping it in the statement
		// guard would let the guard's RELEASE destroy it (or its ROLLBACK TO the guard)
		return x.tx.ExecContext(ctx, q, args...)
	}
	q, args, err := translatePG(q, args)
	if err != nil {
		return nil, err
	}
	var res sql.Result
	err = x.guard(ctx, func() error {
		var err error
		res, err = x.tx.ExecContext(ctx, q, args...)
		return err
	})
	return res, err
}

// isSavepointControl is true for the statements of TenantTx.Savepoint.
func isSavepointControl(q string) bool {
	return strings.HasPrefix(q, "SAVEPOINT tessera_sp") || strings.HasPrefix(q, "RELEASE SAVEPOINT tessera_sp") ||
		strings.HasPrefix(q, "ROLLBACK TO SAVEPOINT tessera_sp")
}

// guard runs a write statement inside a savepoint so that a failing statement
// (a unique or foreign-key violation, a trigger's refusal) leaves the
// transaction usable, as it does in SQLite, where a statement is atomic and the
// transaction carries on. Plain Postgres aborts the whole transaction instead,
// which would turn every handled ErrDuplicate or ErrCrossTenant into a failed
// request. Two extra round trips per write; batching is future work.
func (x *xtx) guard(ctx context.Context, run func() error) error {
	if _, err := x.tx.ExecContext(ctx, "SAVEPOINT tessera_stmt"); err != nil {
		return err
	}
	if err := run(); err != nil {
		// Keep the statement's error; if the rollback itself fails the
		// transaction is unusable and the caller's next statement says so.
		_, _ = x.tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT tessera_stmt")
		_, _ = x.tx.ExecContext(ctx, "RELEASE SAVEPOINT tessera_stmt")
		return err
	}
	_, err := x.tx.ExecContext(ctx, "RELEASE SAVEPOINT tessera_stmt")
	return err
}

func (x *xtx) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	if x.d == dialectSQLite {
		return x.tx.QueryContext(ctx, q, args...)
	}
	q, args, err := translatePG(q, args)
	if err != nil {
		return nil, err
	}
	return x.tx.QueryContext(ctx, q, args...)
}

func (x *xtx) QueryRowContext(ctx context.Context, q string, args ...any) rowScanner {
	if x.d == dialectSQLite {
		return x.tx.QueryRowContext(ctx, q, args...)
	}
	q, args, err := translatePG(q, args)
	if err != nil {
		return errScanner{err}
	}
	return x.tx.QueryRowContext(ctx, q, args...)
}

func (x *xtx) Commit() error   { return x.tx.Commit() }
func (x *xtx) Rollback() error { return x.tx.Rollback() }

// rowScanner is what QueryRowContext returns.
type rowScanner interface{ Scan(dest ...any) error }

// pgStmt is a statement translated for Postgres: its text and the names of
// its parameters in $1, $2, ... order.
type pgStmt struct {
	sql   string
	names []string
}

var pgCache sync.Map // SQLite statement text -> *pgStmt (or error)

type pgCacheErr struct{ err error }

// pgOverrides replaces the generic translation of a statement whose SQLite
// text has no mechanical Postgres equivalent. Keyed by registered statement
// name; registered by register().
var pgOverrides = map[string]string{
	// json_valid/json_type are SQLite functions; Postgres 16 has IS JSON.
	"tenants.set_settings": `
		UPDATE tenants SET settings = CAST(@settings AS TEXT) WHERE id = @id AND slug != '_platform'
			AND CAST(@settings AS TEXT) IS JSON OBJECT`,
	// Two workers must never claim one row: lock the candidates, skip the ones
	// another transaction holds (issue #300).
	"queue_jobs.candidates": `
		SELECT ` + queueJobCols + ` FROM queue_jobs q
		WHERE q.tenant_id = @tenant AND instr(@kinds, ',' || q.kind || ',') > 0 AND ` + queueDue + `
		ORDER BY q.run_at, q.id LIMIT @limit FOR UPDATE OF q SKIP LOCKED`,
	// The application role has no DELETE on audit_events; archiving an audit range
	// calls the SECURITY DEFINER function of schema/postgres/0402 (issue #298).
	"audit_events.archive_purge": `SELECT tessera_archive_purge_audit(@tenant, @segment)`,
	"tenants.set_security_contacts": `
		UPDATE tenants SET security_contacts = CAST(@contacts AS TEXT) WHERE id = @id AND slug != '_platform'
			AND CAST(@contacts AS TEXT) IS JSON ARRAY`,
}

// pgBySQL maps the SQLite text of an overridden statement to its override.
var pgBySQL = map[string]string{}

var (
	reInsertOrIgnore = regexp.MustCompile(`(?is)^\s*INSERT\s+OR\s+IGNORE\s+INTO\b`)
	reInstr          = regexp.MustCompile(`(?i)\binstr\(`)
	// SQLite treats a negative LIMIT as "no limit" (AuditLog(-1)); Postgres
	// refuses it, but LIMIT NULL is no limit.
	reLimitParam = regexp.MustCompile(`(?i)\bLIMIT\s+(\$\d+)`)
)

// translatePG turns a SQLite-dialect statement and its sql.NamedArg
// arguments into Postgres text with $n placeholders and ordered arguments.
func translatePG(q string, args []any) (string, []any, error) {
	var ps *pgStmt
	if v, ok := pgCache.Load(q); ok {
		switch v := v.(type) {
		case *pgStmt:
			ps = v
		case pgCacheErr:
			return "", nil, v.err
		}
	} else {
		built, err := buildPG(q)
		if err != nil {
			pgCache.Store(q, pgCacheErr{err})
			return "", nil, err
		}
		pgCache.Store(q, built)
		ps = built
	}
	if len(ps.names) == 0 {
		return ps.sql, nil, nil
	}
	byName := make(map[string]any, len(args))
	for _, a := range args {
		na, ok := a.(sql.NamedArg)
		if !ok {
			return "", nil, fmt.Errorf("store: postgres statements take named arguments only (got %T)", a)
		}
		byName[na.Name] = na.Value
	}
	out := make([]any, len(ps.names))
	for i, n := range ps.names {
		v, ok := byName[n]
		if !ok {
			return "", nil, fmt.Errorf("store: statement parameter @%s has no argument", n)
		}
		out[i] = v
	}
	return ps.sql, out, nil
}

func buildPG(q string) (*pgStmt, error) {
	if o, ok := pgBySQL[q]; ok {
		q = o
	}
	text, names, err := positional(q)
	if err != nil {
		return nil, err
	}
	if reInsertOrIgnore.MatchString(text) {
		text = reInsertOrIgnore.ReplaceAllString(text, "INSERT INTO")
		text = strings.TrimRight(text, " \t\r\n;") + " ON CONFLICT DO NOTHING"
	}
	text = reInstr.ReplaceAllString(text, "strpos(")
	text = reLimitParam.ReplaceAllString(text, "LIMIT NULLIF(CAST(${1} AS BIGINT), -1)")
	return &pgStmt{sql: text, names: names}, nil
}

// positional rewrites @name parameters to $1..$n, outside string literals,
// quoted identifiers and comments. A name used twice shares one placeholder.
func positional(q string) (string, []string, error) {
	var b strings.Builder
	var names []string
	index := map[string]int{}
	for i := 0; i < len(q); {
		c := q[i]
		switch {
		case c == '\'' || c == '"':
			j := i + 1
			for j < len(q) {
				if q[j] == c {
					if j+1 < len(q) && q[j+1] == c { // doubled quote
						j += 2
						continue
					}
					break
				}
				j++
			}
			if j >= len(q) {
				return "", nil, fmt.Errorf("store: unterminated quote in statement")
			}
			b.WriteString(q[i : j+1])
			i = j + 1
		case c == '-' && i+1 < len(q) && q[i+1] == '-':
			j := strings.IndexByte(q[i:], '\n')
			if j < 0 {
				j = len(q) - i
			}
			b.WriteString(q[i : i+j])
			i += j
		case c == '/' && i+1 < len(q) && q[i+1] == '*':
			j := strings.Index(q[i+2:], "*/")
			if j < 0 {
				return "", nil, fmt.Errorf("store: unterminated comment in statement")
			}
			b.WriteString(q[i : i+2+j+2])
			i += 2 + j + 2
		case c == '@' && i+1 < len(q) && isNameStart(q[i+1]):
			j := i + 1
			for j < len(q) && isNameChar(q[j]) {
				j++
			}
			name := q[i+1 : j]
			n, ok := index[name]
			if !ok {
				names = append(names, name)
				n = len(names)
				index[name] = n
			}
			b.WriteString("$" + strconv.Itoa(n))
			i = j
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String(), names, nil
}

func isNameStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isNameChar(c byte) bool { return isNameStart(c) || (c >= '0' && c <= '9') }

// ---------------------------------------------------------------- error classes

// isUniqueViolation reports a UNIQUE or PRIMARY KEY violation in either dialect.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	m := err.Error()
	return strings.Contains(m, "UNIQUE constraint failed") ||
		strings.Contains(m, "duplicate key value violates unique constraint") || strings.Contains(m, "(SQLSTATE 23505)")
}

// isReferenceViolation reports a cross-tenant or dangling reference refused
// by the schema: SQLite's guard triggers, or Postgres composite foreign keys
// and guard triggers.
func isReferenceViolation(err error) bool {
	if err == nil {
		return false
	}
	m := err.Error()
	return strings.Contains(m, "cross-tenant reference") ||
		strings.Contains(m, "violates foreign key constraint") || strings.Contains(m, "(SQLSTATE 23503)")
}
