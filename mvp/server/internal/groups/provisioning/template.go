package provisioning

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"text/template"
	"unicode"
	"unicode/utf8"
)

// Translation templates (design §9.2): Go text/template with a fixed set of
// side-effect-free functions (no JEXL, K6). A template sees plain data
// (GroupData, MemberData) and nothing it could call.

// Template limits.
const (
	maxTemplateBytes = 2048
	maxOutputBytes   = 4096
)

// GroupData is what a group's templates see.
type GroupData struct {
	ID               string
	Name             string // the full ':' path
	Extension        string
	DisplayName      string
	DisplayExtension string
	Description      string
	Folder           string // the parent folder's name
	// Meta is the mark's per-group metadata (string values only).
	Meta map[string]string
}

// MemberData is what a member reference template sees: the identity and its
// account in the target system.
type MemberData struct {
	IdentityID int64
	Name       string
	Email      string
	Username   string
	ExternalID string
}

var funcs = template.FuncMap{
	"lower":   strings.ToLower,
	"upper":   strings.ToUpper,
	"replace": func(old, new, s string) string { return strings.ReplaceAll(s, old, new) },
	"truncateHash": func(n int, s string) (string, error) {
		return TruncateHash(n, s)
	},
	"ldapEscape": EscapeDN,
	"join":       func(sep string, elems []string) string { return strings.Join(elems, sep) },
}

// TemplateFuncs lists the functions templates may use.
func TemplateFuncs() []string {
	return []string{"join", "ldapEscape", "lower", "replace", "truncateHash", "upper"}
}

// TruncateHash shortens s to at most n runes. A longer s keeps its first n-9
// runes, then "-" and eight hex digits of its SHA-256, so two long names that
// share a prefix stay distinct (AD's 64-character sAMAccountName). n must be
// at least 12.
func TruncateHash(n int, s string) (string, error) {
	if n < 12 || n > 1024 {
		return "", fmt.Errorf("truncateHash: length %d is outside 12..1024", n)
	}
	if utf8.RuneCountInString(s) <= n {
		return s, nil
	}
	sum := sha256.Sum256([]byte(s))
	rs := []rune(s)
	return string(rs[:n-9]) + "-" + hex.EncodeToString(sum[:])[:8], nil
}

// EscapeDN escapes a value for use in a relative distinguished name
// (RFC 4514 §2.4): the characters , + " \ < > ; = and NUL anywhere, a leading
// space or '#', and a trailing space.
func EscapeDN(s string) string {
	var b strings.Builder
	rs := []rune(s)
	for i, r := range rs {
		switch {
		case r == 0:
			b.WriteString(`\00`)
		case strings.ContainsRune(`,+"\<>;=`, r):
			b.WriteByte('\\')
			b.WriteRune(r)
		case (r == ' ' || r == '#') && i == 0, r == ' ' && i == len(rs)-1:
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Tpl is a parsed template.
type Tpl struct {
	src string
	t   *template.Template
}

// ParseTemplate parses src with the fixed function set.
func ParseTemplate(name, src string) (*Tpl, error) {
	if len(src) > maxTemplateBytes {
		return nil, cfgErr("template %s is longer than %d bytes", name, maxTemplateBytes)
	}
	t, err := template.New(name).Funcs(funcs).Option("missingkey=error").Parse(src)
	if err != nil {
		return nil, cfgErr("template %s: %v", name, err)
	}
	return &Tpl{src: src, t: t}, nil
}

// Render runs the template on data and checks the output: at most 4 KiB, valid
// UTF-8, no control characters. (Not called Exec: the archtest bans that name
// outside internal/store, whatever it runs.)
func (p *Tpl) Render(data any) (string, error) {
	var b strings.Builder
	if err := p.t.Execute(&limitWriter{w: &b, left: maxOutputBytes}, data); err != nil {
		return "", fmt.Errorf("template %s: %w", p.t.Name(), err)
	}
	out := strings.TrimLeftFunc(b.String(), unicode.IsSpace)
	// trailing white space goes, except a space an escape (EscapeDN) protects
	for len(out) > 0 && unicode.IsSpace(rune(out[len(out)-1])) && !(out[len(out)-1] == ' ' && strings.HasSuffix(out[:len(out)-1], `\`)) {
		out = out[:len(out)-1]
	}
	if !utf8.ValidString(out) {
		return "", fmt.Errorf("template %s: output is not valid UTF-8", p.t.Name())
	}
	for _, r := range out {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("template %s: output has a control character", p.t.Name())
		}
	}
	return out, nil
}

type limitWriter struct {
	w    *strings.Builder
	left int
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if len(p) > l.left {
		return 0, fmt.Errorf("output is longer than %d bytes", maxOutputBytes)
	}
	l.left -= len(p)
	return l.w.Write(p)
}
