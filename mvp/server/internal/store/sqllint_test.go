package store

import (
	"fmt"
	"slices"
	"strings"
)

// A small SQL tokenizer and tenant-scope linter for the statements in
// store.statements (design §14.4, TestIsolation_EveryStatementBindsTenant).
// It understands exactly the SQL subset the store writes and rejects anything
// it cannot parse rather than skipping it.

type tokKind int

const (
	tIdent tokKind = iota // identifiers and keywords (lower-cased in text)
	tParam                // @name (text is the name)
	tString
	tNumber
	tPunct
)

type token struct {
	kind  tokKind
	text  string
	depth int // parenthesis depth the token is at ("(" has the outer depth)
}

func tokenize(sql string) ([]token, error) {
	var out []token
	depth := 0
	isWord := func(c byte) bool {
		return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
	}
	for i := 0; i < len(sql); {
		c := sql[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case strings.HasPrefix(sql[i:], "--"):
			for i < len(sql) && sql[i] != '\n' {
				i++
			}
		case strings.HasPrefix(sql[i:], "/*"):
			end := strings.Index(sql[i+2:], "*/")
			if end < 0 {
				return nil, fmt.Errorf("unterminated comment")
			}
			i += 2 + end + 2
		case c == '\'':
			j := i + 1
			for ; j < len(sql); j++ {
				if sql[j] == '\'' {
					if j+1 < len(sql) && sql[j+1] == '\'' {
						j++
						continue
					}
					break
				}
			}
			if j >= len(sql) {
				return nil, fmt.Errorf("unterminated string literal")
			}
			out = append(out, token{tString, sql[i+1 : j], depth})
			i = j + 1
		case c == '@':
			j := i + 1
			for j < len(sql) && isWord(sql[j]) {
				j++
			}
			if j == i+1 {
				return nil, fmt.Errorf("empty parameter name")
			}
			out = append(out, token{tParam, sql[i+1 : j], depth})
			i = j
		case c >= '0' && c <= '9':
			j := i
			for j < len(sql) && (sql[j] >= '0' && sql[j] <= '9' || sql[j] == '.') {
				j++
			}
			out = append(out, token{tNumber, sql[i:j], depth})
			i = j
		case isWord(c):
			j := i
			for j < len(sql) && isWord(sql[j]) {
				j++
			}
			out = append(out, token{tIdent, strings.ToLower(sql[i:j]), depth})
			i = j
		case c == '(':
			out = append(out, token{tPunct, "(", depth})
			depth++
			i++
		case c == ')':
			depth--
			if depth < 0 {
				return nil, fmt.Errorf("unbalanced )")
			}
			out = append(out, token{tPunct, ")", depth})
			i++
		case strings.ContainsRune(",.=<>!+*-", rune(c)):
			if two := sql[i:min(i+2, len(sql))]; two == "!=" || two == "<=" || two == ">=" || two == "<>" {
				out = append(out, token{tPunct, two, depth})
				i += 2
				continue
			}
			if c == '!' {
				return nil, fmt.Errorf("unsupported operator !")
			}
			out = append(out, token{tPunct, string(c), depth})
			i++
		default:
			// "?" (positional parameters), "$" (dollar quoting or numbered
			// parameters), ";" (more than one statement), quoted identifiers
			// and anything else are outside the subset.
			return nil, fmt.Errorf("unsupported character %q", c)
		}
	}
	if depth != 0 {
		return nil, fmt.Errorf("unbalanced (")
	}
	return out, nil
}

var sqlKeywords = map[string]bool{
	"select": true, "from": true, "where": true, "and": true, "or": true, "not": true, "join": true, "on": true,
	"left": true, "inner": true, "outer": true, "cross": true, "order": true, "by": true, "group": true, "limit": true,
	"insert": true, "into": true, "values": true, "update": true, "set": true, "delete": true, "as": true, "in": true,
	"is": true, "null": true, "case": true, "when": true, "then": true, "else": true, "end": true, "desc": true,
	"asc": true, "distinct": true, "conflict": true, "do": true, "nothing": true, "ignore": true, "having": true,
	"union": true, "with": true, "exists": true, "between": true, "like": true, "glob": true, "returning": true,
}

// Forbidden statement shapes: more than one statement, CTEs, compound
// selects, DDL and connection-level commands.
var sqlForbidden = []string{"with", "union", "intersect", "except", "pragma", "attach", "detach", "create", "drop",
	"alter", "vacuum", "replace", "returning"}

type tableRef struct {
	table, qual string
	depth, pos  int
	kind        string // from | join | update | delete | insert
}

// lintStatement checks one registered statement. globals are the tables that
// may be touched without a tenant predicate.
func lintStatement(sqlText string, system bool, globals []string) error {
	toks, err := tokenize(sqlText)
	if err != nil {
		return fmt.Errorf("cannot parse: %w", err)
	}
	if len(toks) == 0 {
		return fmt.Errorf("empty statement")
	}
	for _, t := range toks {
		if t.kind == tIdent && slices.Contains(sqlForbidden, t.text) {
			return fmt.Errorf("unsupported construct %q", t.text)
		}
	}
	refs, err := tableRefs(toks)
	if err != nil {
		return err
	}
	if len(refs) == 0 && toks[0].text != "select" {
		return fmt.Errorf("no table found")
	}
	isGlobal := func(t string) bool { return slices.Contains(globals, t) }
	if system {
		for _, r := range refs {
			if !isGlobal(r.table) {
				return fmt.Errorf("system statement touches tenant table %q", r.table)
			}
		}
		return nil
	}
	tenantRefs := 0
	for _, r := range refs {
		if !isGlobal(r.table) {
			tenantRefs++
		}
	}
	if tenantRefs == 0 {
		return fmt.Errorf("tenant statement touches no tenant table (declare it with sq)")
	}
	usesTenant := false
	for _, t := range toks {
		if t.kind == tParam && t.text == "tenant" {
			usesTenant = true
		}
	}
	if !usesTenant {
		return fmt.Errorf("never binds @tenant")
	}
	if err := checkSetLists(toks); err != nil {
		return err
	}
	for _, r := range refs {
		if isGlobal(r.table) {
			continue
		}
		switch r.kind {
		case "insert":
			if err := checkInsert(toks, r); err != nil {
				return err
			}
		default:
			if !hasTenantConjunct(toks, r, tenantRefs == 1) {
				return fmt.Errorf("%s %s (alias %s) has no %s.tenant_id = @tenant conjunct at its level", r.kind, r.table, r.qual, r.qual)
			}
		}
	}
	return nil
}

func tableRefs(toks []token) ([]tableRef, error) {
	var refs []tableRef
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if t.kind != tIdent {
			continue
		}
		var kind string
		switch t.text {
		case "from":
			kind = "from"
			if i > 0 && toks[i-1].text == "delete" {
				kind = "delete"
			}
		case "join":
			kind = "join"
		case "update":
			if i > 0 && toks[i-1].text == "do" { // ON CONFLICT ... DO UPDATE
				continue
			}
			kind = "update"
		case "into":
			kind = "insert"
		default:
			continue
		}
		if i+1 >= len(toks) {
			return nil, fmt.Errorf("%s at end of statement", t.text)
		}
		next := toks[i+1]
		if next.text == "(" {
			if kind != "from" {
				return nil, fmt.Errorf("unsupported %s (subquery)", t.text)
			}
			continue // FROM (subquery): its own FROM is found separately
		}
		if next.kind != tIdent || sqlKeywords[next.text] {
			return nil, fmt.Errorf("unsupported %s target %q", t.text, next.text)
		}
		ref := tableRef{table: next.text, qual: next.text, depth: t.depth, pos: i + 1, kind: kind}
		j := i + 2
		if j < len(toks) && toks[j].text == "as" {
			j++
		}
		if j < len(toks) && toks[j].kind == tIdent && !sqlKeywords[toks[j].text] && kind != "insert" {
			ref.qual = toks[j].text
			j++
		}
		if j < len(toks) && toks[j].text == "," && kind == "from" {
			return nil, fmt.Errorf("implicit (comma) join after %s", ref.table)
		}
		refs = append(refs, ref)
	}
	return refs, nil
}

// hasTenantConjunct looks for qual.tenant_id = @tenant (or, when bareOK, a
// bare tenant_id = @tenant) at the table's parenthesis depth, preceded by
// WHERE, ON or AND, with no OR in the same clause at that depth.
func hasTenantConjunct(toks []token, r tableRef, bareOK bool) bool {
	for i := range toks {
		end, ok := matchTenantPred(toks, i, r.qual, bareOK)
		if !ok || toks[i].depth != r.depth || i == 0 {
			continue
		}
		if p := toks[i-1].text; p != "where" && p != "and" && p != "on" {
			continue
		}
		if clauseHasOr(toks, i, end, r.depth) {
			continue
		}
		return true
	}
	return false
}

// matchTenantPred matches [qual .] tenant_id = @tenant or @tenant = [qual .] tenant_id at i.
func matchTenantPred(toks []token, i int, qual string, bareOK bool) (int, bool) {
	col := func(j int) (int, bool) {
		if j+2 < len(toks) && toks[j].text == qual && toks[j+1].text == "." && toks[j+2].text == "tenant_id" {
			return j + 3, true
		}
		if bareOK && j < len(toks) && toks[j].text == "tenant_id" && (j == 0 || toks[j-1].text != ".") {
			return j + 1, true
		}
		return 0, false
	}
	isTenant := func(j int) bool { return j < len(toks) && toks[j].kind == tParam && toks[j].text == "tenant" }
	if j, ok := col(i); ok && j < len(toks) && toks[j].text == "=" && isTenant(j+1) {
		return j + 2, true
	}
	if isTenant(i) && i+1 < len(toks) && toks[i+1].text == "=" {
		if j, ok := col(i + 2); ok {
			return j, true
		}
	}
	return 0, false
}

var clauseEnd = map[string]bool{"order": true, "group": true, "limit": true, "join": true, "left": true, "inner": true,
	"cross": true, "where": true, "on": true, "having": true, "set": true, "select": true, "from": true}

func clauseHasOr(toks []token, start, end, depth int) bool {
	for i := start - 1; i >= 0; i-- {
		t := toks[i]
		if t.depth < depth || (t.depth == depth && clauseEnd[t.text]) {
			break
		}
		if t.depth == depth && t.text == "or" {
			return true
		}
	}
	for i := end; i < len(toks); i++ {
		t := toks[i]
		if t.depth < depth || (t.depth == depth && clauseEnd[t.text]) {
			break
		}
		if t.depth == depth && t.text == "or" {
			return true
		}
	}
	return false
}

// checkSetLists rejects tenant_id as an assignment target in UPDATE ... SET
// and ON CONFLICT ... DO UPDATE SET.
func checkSetLists(toks []token) error {
	for i, t := range toks {
		if t.text != "set" || t.kind != tIdent {
			continue
		}
		expectCol := true
		for j := i + 1; j < len(toks); j++ {
			u := toks[j]
			if u.depth < t.depth || (u.depth == t.depth && (u.text == "where" || u.text == "returning")) {
				break
			}
			if u.depth != t.depth {
				continue
			}
			if expectCol {
				if u.text == "tenant_id" {
					return fmt.Errorf("SET assigns tenant_id")
				}
				expectCol = false
			}
			if u.text == "," {
				expectCol = true
			}
		}
	}
	return nil
}

// checkInsert requires INSERT INTO t (..., tenant_id, ...) VALUES (..., @tenant, ...)
// and, for ON CONFLICT (cols), that the conflict target starts with tenant_id.
func checkInsert(toks []token, r tableRef) error {
	i := r.pos + 1
	if i >= len(toks) || toks[i].text != "(" {
		return fmt.Errorf("INSERT INTO %s without a column list", r.table)
	}
	cols, i, err := list(toks, i)
	if err != nil {
		return err
	}
	if i >= len(toks) || toks[i].text != "values" {
		return fmt.Errorf("INSERT INTO %s is not INSERT ... VALUES", r.table)
	}
	vals, i, err := list(toks, i+1)
	if err != nil {
		return err
	}
	if len(cols) != len(vals) {
		return fmt.Errorf("INSERT INTO %s: %d columns, %d values", r.table, len(cols), len(vals))
	}
	k := slices.IndexFunc(cols, func(c []token) bool { return len(c) == 1 && c[0].text == "tenant_id" })
	if k < 0 {
		return fmt.Errorf("INSERT INTO %s does not set tenant_id", r.table)
	}
	if v := vals[k]; len(v) != 1 || v[0].kind != tParam || v[0].text != "tenant" {
		return fmt.Errorf("INSERT INTO %s sets tenant_id to something other than @tenant", r.table)
	}
	if i < len(toks) && toks[i].text == "," {
		return fmt.Errorf("multi-row INSERT INTO %s", r.table)
	}
	if i+1 < len(toks) && toks[i].text == "on" && toks[i+1].text == "conflict" {
		if i+2 >= len(toks) || toks[i+2].text != "(" {
			return fmt.Errorf("ON CONFLICT without a target")
		}
		target, _, err := list(toks, i+2)
		if err != nil {
			return err
		}
		if len(target) == 0 || len(target[0]) != 1 || target[0][0].text != "tenant_id" {
			return fmt.Errorf("ON CONFLICT target of %s does not start with tenant_id", r.table)
		}
	}
	return nil
}

// list splits a parenthesised, comma-separated list starting at toks[i] == "(".
func list(toks []token, i int) ([][]token, int, error) {
	if i >= len(toks) || toks[i].text != "(" {
		return nil, i, fmt.Errorf("expected (")
	}
	d := toks[i].depth
	var out [][]token
	var cur []token
	for j := i + 1; j < len(toks); j++ {
		t := toks[j]
		if t.depth == d && t.text == ")" {
			return append(out, cur), j + 1, nil
		}
		if t.depth == d+1 && t.text == "," {
			out, cur = append(out, cur), nil
			continue
		}
		cur = append(cur, t)
	}
	return nil, i, fmt.Errorf("unterminated list")
}

// lintLookup checks one of the two §14.2 hash lookups (lq): exactly
//
//	SELECT x.tenant_id, x.id FROM <table> x WHERE x.<hash column> = @hash
//
// for a table and column of GlobalHashLookups, so a lookup can return
// nothing but the pair needed to open the right tenant transaction.
func lintLookup(sqlText string) error {
	toks, err := tokenize(sqlText)
	if err != nil {
		return fmt.Errorf("cannot parse: %w", err)
	}
	var words []string
	for _, t := range toks {
		if t.kind == tParam {
			words = append(words, "@"+t.text)
			continue
		}
		words = append(words, t.text)
	}
	// select a . tenant_id , a . id from T a where a . col = @hash
	bad := fmt.Errorf("a lookup must be SELECT x.tenant_id, x.id FROM t x WHERE x.<hash> = @hash")
	if len(words) != 17 {
		return bad
	}
	a, table, col := words[1], words[9], words[14]
	want := []string{"select", a, ".", "tenant_id", ",", a, ".", "id", "from", table, a, "where", a, ".", col, "=", "@hash"}
	if !slices.Equal(words, want) {
		return bad
	}
	if GlobalHashLookups[table] != col {
		return fmt.Errorf("lookup on %s.%s is not a GlobalHashLookups column", table, col)
	}
	return nil
}
