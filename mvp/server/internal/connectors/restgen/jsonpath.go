package restgen

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Path is a compiled JSONPath. The supported subset is what mapping a REST
// response needs: "$" (the root), ".name", "['name']", "[n]" (an index),
// "[*]" and ".*" (every element or member). Filters, slices, unions and
// recursive descent ("..") are refused when the path is compiled, so a path
// that compiled always evaluates in time bounded by the document.
type Path struct {
	src   string
	steps []step
}

type step struct {
	name  string
	index int
	kind  byte // 'n' name, 'i' index, '*' every element
}

// CompilePath parses a JSONPath. A path that does not start with "$" is taken
// as relative to the current node ("name" is "$.name").
func CompilePath(src string) (*Path, error) {
	s := strings.TrimSpace(src)
	if s == "" {
		return nil, fmt.Errorf("empty path")
	}
	if len(s) > 256 {
		return nil, fmt.Errorf("path is longer than 256 characters")
	}
	if s[0] != '$' {
		if s[0] != '.' && s[0] != '[' {
			s = "." + s
		}
		s = "$" + s
	}
	p := &Path{src: src}
	i := 1
	for i < len(s) {
		switch s[i] {
		case '.':
			i++
			if i < len(s) && s[i] == '.' {
				return nil, fmt.Errorf("%q: recursive descent (..) is not supported", src)
			}
			j := i
			for j < len(s) && s[j] != '.' && s[j] != '[' {
				j++
			}
			name := s[i:j]
			switch {
			case name == "":
				return nil, fmt.Errorf("%q: empty member name", src)
			case name == "*":
				p.steps = append(p.steps, step{kind: '*'})
			case strings.ContainsAny(name, "()?@,:"):
				return nil, fmt.Errorf("%q: filters and functions are not supported", src)
			default:
				p.steps = append(p.steps, step{kind: 'n', name: name})
			}
			i = j
		case '[':
			j := strings.IndexByte(s[i:], ']')
			if j < 0 {
				return nil, fmt.Errorf("%q: unclosed [", src)
			}
			inner := s[i+1 : i+j]
			i += j + 1
			switch {
			case inner == "*":
				p.steps = append(p.steps, step{kind: '*'})
			case len(inner) >= 2 && (inner[0] == '\'' || inner[0] == '"') && inner[len(inner)-1] == inner[0]:
				p.steps = append(p.steps, step{kind: 'n', name: inner[1 : len(inner)-1]})
			default:
				n, err := strconv.Atoi(inner)
				if err != nil || n < 0 || n > 100000 {
					return nil, fmt.Errorf("%q: [%s] is not an index, a quoted name or *", src, inner)
				}
				p.steps = append(p.steps, step{kind: 'i', index: n})
			}
		default:
			return nil, fmt.Errorf("%q: unexpected %q", src, string(s[i]))
		}
	}
	return p, nil
}

// String is the source text of the path.
func (p *Path) String() string { return p.src }

// Select returns every node the path reaches in v (a decoded JSON document).
func (p *Path) Select(v any) []any {
	cur := []any{v}
	for _, st := range p.steps {
		var next []any
		for _, n := range cur {
			switch st.kind {
			case 'n':
				if m, ok := n.(map[string]any); ok {
					if c, ok := m[st.name]; ok {
						next = append(next, c)
					}
				}
			case 'i':
				if a, ok := n.([]any); ok && st.index < len(a) {
					next = append(next, a[st.index])
				}
			case '*':
				switch t := n.(type) {
				case []any:
					next = append(next, t...)
				case map[string]any:
					var keys []string
					for k := range t {
						keys = append(keys, k)
					}
					sort.Strings(keys)
					for _, k := range keys {
						next = append(next, t[k])
					}
				}
			}
		}
		cur = next
	}
	return cur
}

// First returns the first node the path reaches, and whether it reached one.
func (p *Path) First(v any) (any, bool) {
	if r := p.Select(v); len(r) > 0 {
		return r[0], true
	}
	return nil, false
}

// Strings returns the non-empty scalar values the path reaches, as strings.
func (p *Path) Strings(v any) []string {
	var out []string
	for _, n := range p.Select(v) {
		if s, ok := Scalar(n); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Scalar renders a string, number or boolean as text. Objects, arrays and null
// are not scalars.
func Scalar(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case bool:
		return strconv.FormatBool(t), true
	case float64:
		if t == math.Trunc(t) && math.Abs(t) < 1e15 {
			return strconv.FormatInt(int64(t), 10), true
		}
		return strconv.FormatFloat(t, 'f', -1, 64), true
	}
	return "", false
}
