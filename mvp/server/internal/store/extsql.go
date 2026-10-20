package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// The read-only query of a SQL loader (issue #53, GR-10; design
// docs/design/groups-grouper-parity.md §9.1). It runs against a SQLite file
// that is NOT Tessera's database, so it is not a tenant statement and touches
// no tenant table; it lives here because only this package may use
// database/sql. The caller (internal/groups/loaders) has already confined the
// path to the loader data directory. Two lines of defence stand here: the
// statement must pass CheckReadOnlySQL (one SELECT or WITH statement, no ATTACH
// or PRAGMA), and the connection itself is read-only (mode=ro and query_only),
// so a statement that writes anyway (a WITH ... REPLACE INTO) fails instead of
// running.

// ExtQuery is one query of a loader's source database.
type ExtQuery struct {
	// Path is the absolute path of the SQLite file.
	Path string
	// SQL is the statement; Args are its named parameters (@name).
	SQL  string
	Args map[string]string
	// MaxRows is the row limit: more is an error (ErrExtRowLimit), never a
	// silent truncation, which would look like members who left. Zero: 1,000,000.
	MaxRows int
	// Timeout bounds the whole query. Zero: 120 s.
	Timeout time.Duration
}

// ExtResult is the column names and the rows of a query, every value as text
// (NULL is the empty string).
type ExtResult struct {
	Columns []string
	Rows    [][]string
}

// Errors of RunExtQuery.
var (
	ErrExtRowLimit = errors.New("store: the query returned more rows than the limit")
	ErrExtPath     = errors.New("store: invalid source database path")
)

// Defaults of ExtQuery.
const (
	DefaultExtMaxRows = 1_000_000
	DefaultExtTimeout = 120 * time.Second
)

// RunExtQuery runs q on a read-only connection to the SQLite file at q.Path
// and returns its rows.
func RunExtQuery(ctx context.Context, q ExtQuery) (*ExtResult, error) {
	if !filepath.IsAbs(q.Path) || strings.ContainsAny(q.Path, "?#%\x00") {
		return nil, ErrExtPath
	}
	if err := CheckReadOnlySQL(q.SQL); err != nil {
		return nil, err
	}
	if q.MaxRows <= 0 {
		q.MaxRows = DefaultExtMaxRows
	}
	if q.Timeout <= 0 {
		q.Timeout = DefaultExtTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, q.Timeout)
	defer cancel()
	v := url.Values{}
	v.Add("mode", "ro")
	v.Add("_pragma", "query_only(1)")
	v.Add("_pragma", "busy_timeout(5000)")
	db, err := sql.Open("sqlite", "file:"+q.Path+"?"+v.Encode())
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	args := make([]any, 0, len(q.Args))
	for k, val := range q.Args {
		args = append(args, sql.Named(k, val))
	}
	rows, err := db.QueryContext(ctx, q.SQL, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	out := &ExtResult{Columns: cols}
	for rows.Next() {
		if len(out.Rows) >= q.MaxRows {
			return nil, ErrExtRowLimit
		}
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make([]string, len(cols))
		for i, v := range vals {
			row[i] = extText(v)
		}
		out.Rows = append(out.Rows, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// MaxExtQueryBytes bounds a loader's query.
const MaxExtQueryBytes = 20_000

// CheckReadOnlySQL is the first line of defence of a SQL loader: the statement
// must be one SELECT or WITH statement (design §9.1). It parses the first
// keyword, refuses a second statement, comments and the keywords that write or
// reach outside a query (ATTACH, PRAGMA, load_extension, INSERT, UPDATE, DELETE,
// DROP, CREATE, ...). The second line is the connection itself, which is
// read-only: a WITH that ends in a REPLACE INTO passes this check and fails there.
func CheckReadOnlySQL(q string) error {
	q = strings.TrimSpace(q)
	switch {
	case q == "":
		return errors.New("is required")
	case len(q) > MaxExtQueryBytes:
		return fmt.Errorf("is longer than %d bytes", MaxExtQueryBytes)
	case strings.ContainsRune(q, 0):
		return errors.New("contains a NUL byte")
	case strings.Contains(q, "--") || strings.Contains(q, "/*"):
		return errors.New("must not contain comments")
	}
	trimmed := strings.TrimRight(q, "; \t\r\n")
	if strings.Contains(trimmed, ";") {
		return errors.New("must be a single statement")
	}
	words := sqlWords(trimmed)
	if len(words) == 0 || (words[0] != "select" && words[0] != "with") {
		return errors.New("must start with SELECT or WITH")
	}
	for _, w := range words {
		switch w {
		case "attach", "detach", "pragma", "load_extension", "vacuum", "insert", "update", "delete", "drop", "create", "alter",
			"reindex", "analyze":
			return fmt.Errorf("must be read-only (found %s)", strings.ToUpper(w))
		}
	}
	return nil
}

// sqlWords splits a statement into lower-case words, leaving out the text of
// string literals and quoted identifiers.
func sqlWords(q string) []string {
	var words []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			words = append(words, strings.ToLower(cur.String()))
			cur.Reset()
		}
	}
	var quote rune
	for _, r := range q {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '\'' || r == '"' || r == '`':
			flush()
			quote = r
		case r == '[':
			flush()
			quote = ']'
		case unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_':
			cur.WriteRune(r)
		default:
			flush()
		}
	}
	flush()
	return words
}

func extText(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case []byte:
		return string(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	case time.Time:
		return x.UTC().Format(time.RFC3339)
	}
	return fmt.Sprint(v)
}
