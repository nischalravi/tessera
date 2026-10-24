package sqldb

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Placeholders an app statement may name. Anything else is refused when the
// config is validated, so a typo never reaches the database. attr_<name>
// reads Account.Attrs[<name>] (lower case letters, digits, underscore).
var placeholders = map[string]bool{
	"username": true, "external_id": true, "email": true, "display_name": true,
	"entitlement": true, "entitlement_name": true,
}

var attrPlaceholderRE = regexp.MustCompile(`^attr_[a-z0-9_]{1,60}$`)

func knownPlaceholder(n string) bool { return placeholders[n] || attrPlaceholderRE.MatchString(n) }

// Template is a parsed statement: SQL with named placeholders replaced by the
// engine's positional bind markers. Values are only ever bound, never spliced.
type Template struct {
	// Names lists the placeholder of every bind marker, in order (a name used
	// twice appears twice).
	Names []string
	parts []string // text between markers; len(parts) == len(Names)+1
}

type stmtClass int

const (
	classSelect stmtClass = iota
	classWrite
)

// selectBanned are words a read statement may not contain outside quotes: it
// is a SELECT (or WITH ... SELECT), nothing that writes or defines.
var selectBanned = map[string]bool{
	"INSERT": true, "UPDATE": true, "DELETE": true, "MERGE": true, "DROP": true, "ALTER": true,
	"CREATE": true, "TRUNCATE": true, "GRANT": true, "REVOKE": true, "EXEC": true, "EXECUTE": true,
	"CALL": true, "INTO": true, "COPY": true, "REPLACE": true, "LOCK": true,
}

var errTemplate = errors.New("invalid statement")

// ParseTemplate checks and parses a statement. Rules, applied outside quoted
// text: one statement (no ";"), no comments ("--", "/*", "#"), placeholders
// are :name with a known name. A read (classSelect) starts with SELECT or
// WITH, has no placeholders and none of selectBanned. A write starts with
// INSERT, UPDATE or DELETE. Quoted text ('...', "...", `...`) is copied as is
// and never scanned, so a literal like '12:30' holds no placeholder.
func ParseTemplate(sqlText string, class stmtClass, engine string) (*Template, error) {
	s := strings.TrimSpace(sqlText)
	if s == "" || len(s) > 8192 {
		return nil, fmt.Errorf("%w: empty or longer than 8192 characters", errTemplate)
	}
	if !cleanTextAllowNL(s) {
		return nil, fmt.Errorf("%w: control characters", errTemplate)
	}
	t := &Template{}
	var cur strings.Builder
	first, seenFirst := "", false
	words := []string{}
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '\'' || c == '"' || c == '`':
			j, err := skipQuoted(s, i)
			if err != nil {
				return nil, err
			}
			cur.WriteString(s[i:j])
			i = j
			continue
		case c == ';':
			return nil, fmt.Errorf("%w: only one statement is allowed (no \";\")", errTemplate)
		case c == '#' || (c == '-' && i+1 < len(s) && s[i+1] == '-') || (c == '/' && i+1 < len(s) && s[i+1] == '*'):
			return nil, fmt.Errorf("%w: comments are not allowed", errTemplate)
		case c == ':' && i+1 < len(s) && s[i+1] == ':': // PostgreSQL cast
			cur.WriteString("::")
			i += 2
			continue
		case c == ':':
			j := i + 1
			for j < len(s) && (s[j] == '_' || s[j] >= 'a' && s[j] <= 'z' || s[j] >= '0' && s[j] <= '9') {
				j++
			}
			name := s[i+1 : j]
			if name == "" || (s[i+1] >= '0' && s[i+1] <= '9') {
				return nil, fmt.Errorf("%w: a placeholder is :name in lower case", errTemplate)
			}
			if class == classSelect {
				return nil, fmt.Errorf("%w: a read statement takes no placeholders", errTemplate)
			}
			if !knownPlaceholder(name) {
				return nil, fmt.Errorf("%w: unknown placeholder :%s", errTemplate, name)
			}
			t.parts = append(t.parts, cur.String())
			cur.Reset()
			t.Names = append(t.Names, name)
			i = j
			continue
		case isWordByte(c):
			j := i
			for j < len(s) && isWordByte(s[j]) {
				j++
			}
			w := strings.ToUpper(s[i:j])
			if !seenFirst {
				first, seenFirst = w, true
			}
			words = append(words, w)
			cur.WriteString(s[i:j])
			i = j
			continue
		}
		cur.WriteByte(c)
		i++
	}
	t.parts = append(t.parts, cur.String())
	switch class {
	case classSelect:
		if first != "SELECT" && first != "WITH" {
			return nil, fmt.Errorf("%w: a read statement must start with SELECT or WITH", errTemplate)
		}
		for _, w := range words {
			if selectBanned[w] {
				return nil, fmt.Errorf("%w: a read statement may not use %s", errTemplate, w)
			}
		}
	case classWrite:
		if first != "INSERT" && first != "UPDATE" && first != "DELETE" {
			return nil, fmt.Errorf("%w: a write statement must start with INSERT, UPDATE or DELETE", errTemplate)
		}
	}
	return t, nil
}

func isWordByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// skipQuoted returns the index after the quoted run that starts at s[i]. A
// doubled quote character inside is an escaped one. A backslash is not an
// escape (it is not in standard SQL; MySQL's sql_mode decides), so a statement
// that ends a literal with one is refused rather than guessed at.
func skipQuoted(s string, i int) (int, error) {
	q := s[i]
	for j := i + 1; j < len(s); j++ {
		if s[j] == '\\' {
			return 0, fmt.Errorf("%w: backslash inside quoted text", errTemplate)
		}
		if s[j] == q {
			if j+1 < len(s) && s[j+1] == q {
				j++
				continue
			}
			return j + 1, nil
		}
	}
	return 0, fmt.Errorf("%w: unterminated quote", errTemplate)
}

func cleanTextAllowNL(s string) bool {
	for _, r := range s {
		if r == '\n' || r == '\t' || r == '\r' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return cleanText(strings.NewReplacer("\n", " ", "\t", " ", "\r", " ").Replace(s))
}

// marker is the engine's positional bind marker for argument n (1-based).
func marker(engine string, n int) string {
	switch engine {
	case Postgres:
		return "$" + strconv.Itoa(n)
	case SQLServer:
		return "@p" + strconv.Itoa(n)
	case Oracle:
		return ":" + strconv.Itoa(n)
	}
	return "?"
}

// Bind returns the statement text for the engine and the argument list, one
// argument per marker in order. vals maps a placeholder to its value; a
// missing or empty value (other than username) binds NULL.
func (t *Template) Bind(engine string, vals map[string]string) (string, []any) {
	var b strings.Builder
	args := make([]any, 0, len(t.Names))
	for i, p := range t.parts {
		b.WriteString(p)
		if i < len(t.Names) {
			b.WriteString(marker(engine, i+1))
			if v := vals[t.Names[i]]; v != "" {
				args = append(args, v)
			} else {
				args = append(args, nil)
			}
		}
	}
	return b.String(), args
}

// validate parses every statement of an App.
func (a *App) validate() error {
	var errs []error
	chk := func(name, text string, class stmtClass, required bool) {
		if text == "" {
			if required {
				errs = append(errs, fmt.Errorf("app.%s is required", name))
			}
			return
		}
		// the engine only changes the markers, not what is accepted
		if _, err := ParseTemplate(text, class, Postgres); err != nil {
			errs = append(errs, fmt.Errorf("app.%s: %w", name, err))
		}
	}
	chk("accounts_query", a.AccountsQuery, classSelect, true)
	chk("entitlements_query", a.EntitlementsQuery, classSelect, false)
	for _, w := range []struct{ n, s string }{{"create_account", a.CreateAccount}, {"update_account", a.UpdateAccount},
		{"disable_account", a.DisableAccount}, {"delete_account", a.DeleteAccount},
		{"add_entitlement", a.AddEntitlement}, {"remove_entitlement", a.RemoveEntitlement}} {
		chk(w.n, w.s, classWrite, false)
	}
	return errors.Join(errs...)
}
