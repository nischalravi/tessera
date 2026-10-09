package policy

import (
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
)

// globalMultivaluedKeys are the multivalued (ArrayOf*) global condition keys
// in the AWS global condition key reference [S19], lower-cased. The catalog
// (PR-2) adds the service-specific ones through Options.MultivaluedKey.
var globalMultivaluedKeys = map[string]bool{
	"aws:tagkeys":                   true,
	"aws:calledvia":                 true,
	"aws:principalorgpaths":         true,
	"aws:resourceorgpaths":          true,
	"aws:sourceorgpaths":            true,
	"aws:principalservicenameslist": true,
}

// IsGlobalMultivaluedKey reports whether a lower-cased key is one of the
// multivalued global condition keys.
func IsGlobalMultivaluedKey(lowerKey string) bool { return globalMultivaluedKeys[lowerKey] }

// varRef is one ${…} occurrence in a string.
type varRef struct {
	start, end int    // byte offsets of "${" and just past "}"
	key        string // lower-cased key name; "" for an escape
	escape     bool   // ${*}, ${?} or ${$}
	hasDefault bool
}

// variableRefs finds the ${…} references in s using the grammar of §9.3:
// ${key}, ${key, 'default'}, and the escapes ${*}, ${?} and ${$}. An
// unterminated "${" is literal text.
func variableRefs(s string) []varRef {
	var out []varRef
	for i := 0; i < len(s); {
		j := strings.Index(s[i:], "${")
		if j < 0 {
			break
		}
		start := i + j
		k := strings.IndexByte(s[start+2:], '}')
		if k < 0 {
			break
		}
		end := start + 2 + k + 1
		inner := s[start+2 : end-1]
		r := varRef{start: start, end: end}
		switch inner {
		case "*", "?", "$":
			r.escape = true
		default:
			key := inner
			if c := strings.IndexByte(inner, ','); c >= 0 {
				key, r.hasDefault = inner[:c], true
			}
			r.key = strings.ToLower(strings.TrimSpace(key))
		}
		out = append(out, r)
		i = end
	}
	return out
}

// hasVariable reports whether s contains a non-escape variable reference.
func hasVariable(s string) bool {
	for _, r := range variableRefs(s) {
		if !r.escape {
			return true
		}
	}
	return false
}

// variableOutsideResourcePart reports whether an ARN pattern uses a variable
// before its sixth segment. Variables are allowed only in the resource part,
// after the fifth colon (§4.1 fact 9); colons inside ${…} do not count.
func variableOutsideResourcePart(pattern string) bool {
	refs := variableRefs(pattern)
	colons, ri := 0, 0
	for i := 0; i < len(pattern); i++ {
		if ri < len(refs) && i == refs[ri].start {
			if !refs[ri].escape && colons < 5 {
				return true
			}
			i = refs[ri].end - 1
			ri++
			continue
		}
		if pattern[i] == ':' {
			colons++
		}
	}
	return false
}

// variableOperator reports whether policy variables are substituted in the
// values of a base operator: String, ARN and Bool operators only (§9.3).
func variableOperator(op string) bool {
	return strings.HasPrefix(op, "String") || strings.HasPrefix(op, "Arn") || op == "Bool"
}

// multivaluedVariables returns the sorted, unique multivalued keys a statement
// uses as policy variables in the places variables are substituted: Resource
// and NotResource patterns and the values of String, ARN and Bool operators.
func multivaluedVariables(st *model.Statement, multivalued func(string) bool) []string {
	seen := map[string]bool{}
	check := func(s string) {
		for _, r := range variableRefs(s) {
			if !r.escape && multivalued(r.key) {
				seen[r.key] = true
			}
		}
	}
	for _, ps := range []*model.PatternSet{st.Resources, st.NotResources} {
		if ps != nil {
			for _, s := range ps.Patterns {
				check(s)
			}
		}
	}
	for _, a := range st.Condition {
		if variableOperator(a.Op) {
			for _, v := range a.Values {
				check(v)
			}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
