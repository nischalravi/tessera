package store

import (
	"embed"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
)

// Deployment-readiness tables live in schema/*.sql (one file per design
// migration, §8.1) and are appended to the main schema at init, so the
// existing schema list stays untouched and reseeding drops them too.

//go:embed schema/*.sql
var readinessSchemaFS embed.FS

var createTable = regexp.MustCompile(`(?i)^CREATE TABLE IF NOT EXISTS ([a-z_]+)`)

func init() {
	stmts, names, err := readinessSchema(readinessSchemaFS)
	if err != nil {
		panic(err) // embedded files: a failure here is a build defect
	}
	schema = append(schema, stmts...)
	tables = append(tables, names...)
}

// readinessSchema returns the statements in file order and the tables they create.
func readinessSchema(fsys fs.FS) (stmts, tables []string, err error) {
	files, err := fs.Glob(fsys, "schema/*.sql")
	if err != nil {
		return nil, nil, err
	}
	sort.Strings(files)
	for _, f := range files {
		data, err := fs.ReadFile(fsys, f)
		if err != nil {
			return nil, nil, err
		}
		var lines []string
		for _, l := range strings.Split(string(data), "\n") {
			if t := strings.TrimSpace(l); t != "" && !strings.HasPrefix(t, "--") {
				lines = append(lines, l)
			}
		}
		for _, s := range strings.Split(strings.Join(lines, "\n"), ";") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if !strings.HasPrefix(strings.ToUpper(s), "CREATE ") {
				return nil, nil, fmt.Errorf("store: %s: only CREATE statements are allowed: %.40s", f, s)
			}
			stmts = append(stmts, s)
			if m := createTable.FindStringSubmatch(s); m != nil {
				tables = append(tables, m[1])
			}
		}
	}
	return stmts, tables, nil
}
