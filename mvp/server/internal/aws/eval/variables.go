package eval

import "strings"

// Seg is a run of pattern text. Lit text is never a wildcard: substituted
// variable values and the ${*}, ${?} and ${$} escapes are literal characters.
type Seg struct {
	Text string
	Lit  bool
}

// Pattern is a policy value after variable substitution.
type Pattern struct{ Segs []Seg }

// String is the pattern's text, wildcards and literals alike.
func (p Pattern) String() string {
	var b strings.Builder
	for _, s := range p.Segs {
		b.WriteString(s.Text)
	}
	return b.String()
}

// Resolution says how substitution ended.
type Resolution uint8

const (
	// Resolved: the pattern is final.
	SubstResolved Resolution = iota
	// SubstNull: a variable named an absent key and had no default. A resource
	// pattern then matches nothing and a condition value is the null marker:
	// positive operators are false against it, negated operators true (A6).
	SubstNull
	// SubstUnknown: a variable named a key whose state is unknown (symbolic mode).
	SubstUnknown
)

// Substitute resolves the policy variables in s (§9.3): ${key},
// ${key, 'default'}, and the escapes ${*}, ${?} and ${$}.
//
// enabled is false for a document whose Version is not 2012-10-17; the text is
// then returned whole, variables and all, as literal characters of the
// pattern. A multivalued key cannot be a variable, so such a reference stays
// as literal text [verify P-MVVAR]. An unterminated "${" is literal text.
//
// Null wins over Unknown: a pattern that matches nothing is decided whatever
// the unknown variable turns out to be.
func Substitute(s string, ctx *Context, enabled bool) (Pattern, Resolution) {
	if !enabled || !strings.Contains(s, "${") {
		return Pattern{Segs: []Seg{{Text: s}}}, SubstResolved
	}
	var segs []Seg
	res := SubstResolved
	text := func(t string) {
		if t != "" {
			segs = append(segs, Seg{Text: t})
		}
	}
	lit := func(t string) { segs = append(segs, Seg{Text: t, Lit: true}) }
	for i := 0; i < len(s); {
		j := strings.Index(s[i:], "${")
		if j < 0 {
			text(s[i:])
			break
		}
		start := i + j
		k := strings.IndexByte(s[start+2:], '}')
		if k < 0 {
			text(s[i:])
			break
		}
		end := start + 2 + k + 1
		text(s[i:start])
		inner := s[start+2 : end-1]
		i = end
		switch inner {
		case "*", "?", "$":
			lit(inner)
			continue
		}
		key, def, hasDef := inner, "", false
		if c := strings.IndexByte(inner, ','); c >= 0 {
			key, def, hasDef = inner[:c], unquote(strings.TrimSpace(inner[c+1:])), true
		}
		key = asciiLower(strings.TrimSpace(key))
		if ctx.multivalued(key) {
			lit(s[start:end])
			continue
		}
		v := ctx.Lookup(key)
		switch v.State {
		case Present:
			if len(v.Values) > 0 {
				lit(v.Values[0])
			}
		case Absent:
			if hasDef {
				lit(def)
			} else {
				res = SubstNull
			}
		case Unknown:
			if res != SubstNull {
				res = SubstUnknown
			}
		}
	}
	return Pattern{Segs: segs}, res
}

// unquote strips one pair of single quotes around a default value.
func unquote(d string) string {
	if len(d) >= 2 && d[0] == '\'' && d[len(d)-1] == '\'' {
		return d[1 : len(d)-1]
	}
	return d
}
