package store

import (
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strings"
)

// A small CREATE TABLE reader, enough for this repository's two DDL dialects.
// It serves `tessera admin gen-rls` (which tables are tenant-scoped) and the
// schema parity test (same tables and columns in SQLite and Postgres). It is
// not a SQL parser: it understands comments, quotes, nesting and the column
// and constraint shapes the schema files use, and refuses what it cannot read.

// DDLColumn is one column of a parsed table.
type DDLColumn struct {
	Name string
	// Type is the storage family: int, text, real or blob.
	Type    string
	NotNull bool
}

// DDLTable is one parsed CREATE TABLE.
type DDLTable struct {
	Name    string
	Columns []DDLColumn
}

// Column returns the named column.
func (t DDLTable) Column(name string) (DDLColumn, bool) {
	for _, c := range t.Columns {
		if c.Name == name {
			return c, true
		}
	}
	return DDLColumn{}, false
}

// ParseDDL reads the CREATE TABLE statements of one or more DDL files.
func ParseDDL(src string) ([]DDLTable, error) {
	src = stripComments(src)
	upper := strings.ToUpper(src)
	var out []DDLTable
	for pos := 0; ; {
		i := strings.Index(upper[pos:], "CREATE TABLE")
		if i < 0 {
			return out, nil
		}
		i += pos
		j := i + len("CREATE TABLE")
		rest := strings.TrimLeft(src[j:], " \t\r\n")
		if strings.HasPrefix(strings.ToUpper(rest), "IF NOT EXISTS") {
			rest = strings.TrimLeft(rest[len("IF NOT EXISTS"):], " \t\r\n")
		}
		open := strings.IndexByte(rest, '(')
		if open < 0 {
			return nil, fmt.Errorf("ddl: CREATE TABLE without a column list near %q", clip(src[i:]))
		}
		name := strings.TrimSpace(rest[:open])
		body, end, err := balanced(rest[open:])
		if err != nil {
			return nil, fmt.Errorf("ddl: table %s: %w", name, err)
		}
		t, err := parseTable(name, body)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
		// continue after the body
		consumed := len(src) - len(rest) + open + end
		pos = consumed
	}
}

func clip(s string) string {
	if len(s) > 60 {
		return s[:60]
	}
	return s
}

// stripComments removes -- and /* */ comments outside single-quoted strings.
func stripComments(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		switch {
		case s[i] == '\'':
			j := i + 1
			for j < len(s) {
				if s[j] == '\'' {
					if j+1 < len(s) && s[j+1] == '\'' {
						j += 2
						continue
					}
					break
				}
				j++
			}
			if j >= len(s) {
				j = len(s) - 1
			}
			b.WriteString(s[i : j+1])
			i = j + 1
		case strings.HasPrefix(s[i:], "--"):
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case strings.HasPrefix(s[i:], "/*"):
			k := strings.Index(s[i+2:], "*/")
			if k < 0 {
				return b.String()
			}
			i += 2 + k + 2
		default:
			b.WriteByte(s[i])
			i++
		}
	}
	return b.String()
}

// balanced returns the text inside the parentheses that start s, and the
// offset just past the closing one.
func balanced(s string) (string, int, error) {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			for i++; i < len(s); i++ {
				if s[i] == '\'' {
					if i+1 < len(s) && s[i+1] == '\'' {
						i++
						continue
					}
					break
				}
			}
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return s[1:i], i + 1, nil
			}
		}
	}
	return "", 0, fmt.Errorf("unbalanced parentheses")
}

// splitTop splits s at commas that are outside parentheses and quotes.
func splitTop(s string) []string {
	var parts []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			for i++; i < len(s); i++ {
				if s[i] == '\'' {
					if i+1 < len(s) && s[i+1] == '\'' {
						i++
						continue
					}
					break
				}
			}
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	return append(parts, strings.TrimSpace(s[start:]))
}

var constraintStarts = []string{"PRIMARY", "UNIQUE", "FOREIGN", "CHECK", "CONSTRAINT"}

func parseTable(name, body string) (DDLTable, error) {
	t := DDLTable{Name: name}
	var pkCols []string
	for _, part := range splitTop(body) {
		if part == "" {
			continue
		}
		fields := strings.Fields(part)
		first := strings.ToUpper(fields[0])
		if slices.Contains(constraintStarts, first) {
			if first == "PRIMARY" {
				if o := strings.IndexByte(part, '('); o >= 0 {
					cols, _, err := balanced(part[o:])
					if err != nil {
						return t, fmt.Errorf("ddl: table %s: %w", name, err)
					}
					for _, c := range strings.Split(cols, ",") {
						pkCols = append(pkCols, strings.TrimSpace(c))
					}
				}
			}
			continue
		}
		if len(fields) < 2 {
			return t, fmt.Errorf("ddl: table %s: cannot read column %q", name, part)
		}
		typ := strings.ToUpper(fields[1])
		if typ == "DOUBLE" {
			typ = "REAL"
		}
		family, ok := typeFamily(typ)
		if !ok {
			return t, fmt.Errorf("ddl: table %s: column %s: unknown type %s", name, fields[0], fields[1])
		}
		up := strings.ToUpper(part)
		t.Columns = append(t.Columns, DDLColumn{
			Name: fields[0], Type: family,
			NotNull: strings.Contains(up, "NOT NULL") || strings.Contains(up, "PRIMARY KEY"),
		})
	}
	for _, c := range pkCols {
		for i := range t.Columns {
			if t.Columns[i].Name == c {
				t.Columns[i].NotNull = true
			}
		}
	}
	if len(t.Columns) == 0 {
		return t, fmt.Errorf("ddl: table %s has no columns", name)
	}
	return t, nil
}

func typeFamily(t string) (string, bool) {
	switch t {
	case "INTEGER", "INT", "BIGINT", "SMALLINT":
		return "int", true
	case "TEXT", "VARCHAR":
		return "text", true
	case "REAL":
		return "real", true
	case "BLOB", "BYTEA":
		return "blob", true
	}
	return "", false
}

// ---------------------------------------------------------------- schema files

// pgRLSFile is the generated row-level-security file next to the migrations.
const pgRLSFile = "rls.sql"

// SQLiteTables parses the embedded SQLite schema.
func SQLiteTables() ([]DDLTable, error) { return parseFS(schemaFS, "schema", "") }

// PostgresTables parses the embedded Postgres migrations.
func PostgresTables() ([]DDLTable, error) { return parseFS(pgSchemaFS, "schema/postgres", pgRLSFile) }

func parseFS(fsys fs.FS, dir, skip string) ([]DDLTable, error) {
	files, err := fs.Glob(fsys, dir+"/*.sql")
	if err != nil {
		return nil, err
	}
	slices.Sort(files)
	var out []DDLTable
	for _, f := range files {
		if skip != "" && strings.HasSuffix(f, "/"+skip) {
			continue
		}
		b, err := fs.ReadFile(fsys, f)
		if err != nil {
			return nil, err
		}
		ts, err := ParseDDL(string(b))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		out = append(out, ts...)
		// forward migrations that add a column: fold it into its table
		for _, m := range addColumnRe.FindAllStringSubmatch(stripComments(string(b)), -1) {
			for i := range out {
				if out[i].Name != m[1] {
					continue
				}
				col, err := parseTable(m[1], m[2]+" "+m[3]+" "+m[4])
				if err != nil {
					return nil, fmt.Errorf("%s: %w", f, err)
				}
				out[i].Columns = append(out[i].Columns, col.Columns...)
			}
		}
	}
	return out, nil
}

// addColumnRe matches ALTER TABLE t ADD COLUMN [IF NOT EXISTS] name TYPE rest;
// (table, column, type, the rest of the statement).
var addColumnRe = regexp.MustCompile(`(?is)ALTER\s+TABLE\s+(\w+)\s+ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\s+(\w+)([^;]*);`)

// PostgresRLSFile returns the embedded generated rls.sql.
func PostgresRLSFile() ([]byte, error) { return pgSchemaFS.ReadFile("schema/postgres/" + pgRLSFile) }

// hashLookupSetting is the app.lookup value that unlocks the narrow SELECT
// policy of each GlobalHashLookups table (design §14.2, §14.3).
var hashLookupSetting = map[string]string{"sessions": "session_hash", "login_transactions": "login_cookie_hash",
	"agent_enrolments": "agent_enrolment_hash", "directory_agents": "agent_cert_pin"}

// GenerateRLS renders rls.sql from the Postgres schema (design §14.3): for
// every table with a tenant_id column that is not a GlobalTable, ENABLE and
// FORCE row-level security and one tenant_isolation policy that matches the
// transaction-local app.tenant_id setting. A missing or empty setting matches
// no row (fail closed). The two hash-lookup tables also get a SELECT-only
// lookup_by_hash policy keyed on app.lookup. The output is deterministic and
// idempotent (DROP POLICY IF EXISTS first), so it can be re-applied.
func GenerateRLS() ([]byte, error) {
	tbls, err := PostgresTables()
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString("-- Code generated by `tessera admin gen-rls`; DO NOT EDIT.\n")
	b.WriteString("-- Row-level security for every tenant-scoped table (design §14.3).\n")
	b.WriteString("-- The application role (tessera_app) is NOSUPERUSER, NOBYPASSRLS and not the\n")
	b.WriteString("-- table owner. Each tenant transaction runs\n")
	b.WriteString("--   SELECT set_config('app.tenant_id', <tenant>, true)\n")
	b.WriteString("-- so with no setting (or an empty one) no row matches.\n")
	for _, t := range tbls {
		if slices.Contains(GlobalTables, t.Name) {
			continue
		}
		if _, ok := t.Column("tenant_id"); !ok {
			continue
		}
		const match = "tenant_id = NULLIF(current_setting('app.tenant_id', true), '')"
		fmt.Fprintf(&b, "\nALTER TABLE %s ENABLE ROW LEVEL SECURITY;\n", t.Name)
		fmt.Fprintf(&b, "ALTER TABLE %s FORCE ROW LEVEL SECURITY;\n", t.Name)
		fmt.Fprintf(&b, "DROP POLICY IF EXISTS tenant_isolation ON %s;\n", t.Name)
		fmt.Fprintf(&b, "CREATE POLICY tenant_isolation ON %s\n  USING (%s)\n  WITH CHECK (%s);\n", t.Name, match, match)
		if setting, ok := hashLookupSetting[t.Name]; ok {
			fmt.Fprintf(&b, "DROP POLICY IF EXISTS lookup_by_hash ON %s;\n", t.Name)
			fmt.Fprintf(&b, "CREATE POLICY lookup_by_hash ON %s FOR SELECT\n  USING (current_setting('app.lookup', true) = '%s');\n", t.Name, setting)
		}
	}
	return []byte(b.String()), nil
}
