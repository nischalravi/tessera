package restgen

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Vars are the values a template may use, by name ("username", "attr.title").
type Vars map[string]string

// expandPath replaces each {name} in a validated path template by the
// path-escaped value of the variable. A value is one path segment: "/" is
// escaped, and "." and ".." (which escaping leaves alone) are refused, so
// untrusted data cannot change which endpoint is called.
func expandPath(tmpl string, v Vars) (string, error) {
	var b strings.Builder
	rest := tmpl
	for {
		i := strings.IndexByte(rest, '{')
		if i < 0 {
			b.WriteString(rest)
			return b.String(), nil
		}
		j := strings.IndexByte(rest[i:], '}')
		if j < 0 {
			return "", fmt.Errorf("path %q has an unclosed {", tmpl)
		}
		name := rest[i+1 : i+j]
		val := v[name]
		switch {
		case val == "":
			return "", fmt.Errorf("the path needs {%s}, which this change does not have", name)
		case val == "." || val == "..", len(val) > 256, hasControl(val):
			return "", fmt.Errorf("{%s} is not a safe path segment", name)
		}
		b.WriteString(rest[:i])
		b.WriteString(url.PathEscape(val))
		rest = rest[i+j+1:]
	}
}

func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// expandQuery renders query templates: "${name}" values are replaced, and a
// parameter whose value is a lone unset variable is left out.
func expandQuery(q map[string]string, v Vars) url.Values {
	out := url.Values{}
	for k, t := range q {
		if val, ok := interpolate(t, v); ok {
			out.Set(k, val)
		}
	}
	return out
}

// interpolate replaces ${name} in s. ok is false when s is exactly one unset
// variable (the caller drops the member); other unset variables become "".
func interpolate(s string, v Vars) (string, bool) {
	if m := varRE.FindStringSubmatchIndex(s); m != nil && m[0] == 0 && m[1] == len(s) {
		val, set := v[s[m[2]:m[3]]]
		return val, set
	}
	return varRE.ReplaceAllStringFunc(s, func(m string) string { return v[m[2:len(m)-1]] }), true
}

// expandBody renders a body template: a JSON value, built as a value and
// marshalled, so a variable can never break out of its string.
func expandBody(tmpl json.RawMessage, v Vars) ([]byte, error) {
	if len(bytes.TrimSpace(tmpl)) == 0 {
		return nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(tmpl))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return nil, fmt.Errorf("body template: %v", err)
	}
	out, keep := expandNode(tree, v)
	if !keep {
		return nil, errors.New("body template is a lone unset variable")
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	if len(b) > 64<<10 {
		return nil, errors.New("rendered body is longer than 64 KiB")
	}
	return b, nil
}

func expandNode(n any, v Vars) (any, bool) {
	switch t := n.(type) {
	case string:
		return interpolate(t, v)
	case []any:
		out := make([]any, 0, len(t))
		for _, e := range t {
			if r, ok := expandNode(e, v); ok {
				out = append(out, r)
			}
		}
		return out, true
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			if r, ok := expandNode(e, v); ok {
				out[k] = r
			}
		}
		return out, true
	}
	return n, true
}

// buildURL joins the base URL, an expanded (already escaped) path and a query.
func buildURL(base *url.URL, escapedPath string, q url.Values) (*url.URL, error) {
	s := base.Scheme + "://" + base.Host + strings.TrimRight(base.EscapedPath(), "/") + escapedPath
	if len(q) > 0 {
		s += "?" + q.Encode()
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("the request URL is not valid: %v", err)
	}
	if !strings.EqualFold(u.Host, base.Host) || u.User != nil {
		return nil, errors.New("the request URL leaves the configured host")
	}
	return u, nil
}

// queryOf is the query of u as values (a malformed pair is dropped).
func queryOf(u *url.URL) url.Values {
	q, _ := url.ParseQuery(u.RawQuery)
	return q
}
