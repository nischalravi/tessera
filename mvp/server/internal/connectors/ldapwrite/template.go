// Package ldapwrite is the provisioning target of an LDAP directory (389-DS, OpenLDAP and others)
// and of Active Directory: account create, update, enable and disable, move, delete, password
// set and reset, and group membership (issue #586).
//
// The package is the write sibling of internal/connectors/ldap, which is read-only by test. It is
// kept apart so that the read-only guarantee of the readers stays true.
//
// Safety rules, all enforced here and tested:
//
//   - TLS only. The connection is made by internal/safedial (LDAPS on 636, or StartTLS on 389
//     completed before the bind). There is no plain-LDAP setting at all, in any environment, and a
//     password is sent only on a connection safedial calls Secure.
//   - Write scope. Every DN written is checked against the target's named OUs (WriteScope). A DN
//     outside them, including one that a search returned, is refused before any change is sent.
//   - Templates. DN templates are rendered with RFC 4514 escaping of every substituted value, search
//     filters with RFC 4515 escaping, attribute names are validated, and the rendered DN is parsed
//     again. A value cannot add an RDN or a filter clause.
//   - Read first, read back. Each operation reads the directory before it writes (so a repeat
//     converges) and Verify re-reads and reports what it saw. The password cannot be read back; an
//     AD account's pwdLastSet is the evidence, and an LDAP password is never claimed verified.
//   - Passwords are generated with crypto/rand from the target's policy, travel as connsync.Secret
//     values, and are never stored, logged, audited or put in an error.
package ldapwrite

import (
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"

	goldap "github.com/go-ldap/ldap/v3"

	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
)

const (
	maxTemplate = 512
	maxValue    = 256
)

var (
	refRE      = regexp.MustCompile(`^(?:(?:user|group)\.[A-Za-z][A-Za-z0-9_.-]{0,63}|account)$`)
	attrNameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,62}$`)
	pathRE     = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,63}$`)
)

// protectedAttrs are set by the target itself and never by a template or an update map.
var protectedAttrs = map[string]bool{"objectclass": true, "userpassword": true, "unicodepwd": true, "useraccountcontrol": true,
	"nsaccountlock": true, "pwdaccountlockedtime": true, "member": true, "uniquemember": true, "memberuid": true,
	"dn": true, "entrydn": true, "distinguishedname": true, "objectsid": true, "objectguid": true, "pwdlastset": true,
	"grouptype": true, "primarygroupid": true, "memberof": true}

type part struct {
	lit string
	ref string // "user.mail", "group.name" or "account"; empty for a literal
}

// Template is a parsed `${user.<attr>}` string.
type Template struct {
	src   string
	parts []part
}

// ParseTemplate parses s. Placeholders are ${user.<name>}, ${group.<name>} and ${account}; any other
// ${...} is an error, and so is an unterminated one.
func ParseTemplate(s string) (*Template, error) {
	if s == "" || len(s) > maxTemplate || !utf8.ValidString(s) || strings.ContainsAny(s, "\x00\r\n") {
		return nil, errors.New("not a template")
	}
	t := &Template{src: s}
	rest := s
	for rest != "" {
		i := strings.Index(rest, "${")
		if i < 0 {
			t.parts = append(t.parts, part{lit: rest})
			break
		}
		if i > 0 {
			t.parts = append(t.parts, part{lit: rest[:i]})
		}
		j := strings.IndexByte(rest[i:], '}')
		if j < 0 {
			return nil, errors.New("unterminated placeholder")
		}
		ref := rest[i+2 : i+j]
		if !refRE.MatchString(ref) {
			return nil, errors.New("unknown placeholder")
		}
		t.parts = append(t.parts, part{ref: strings.ToLower(ref)})
		rest = rest[i+j+1:]
	}
	return t, nil
}

// Refs lists the placeholders the template uses.
func (t *Template) Refs() []string {
	var out []string
	for _, p := range t.parts {
		if p.ref != "" {
			out = append(out, p.ref)
		}
	}
	return out
}

// Vars are the values a template is rendered with. Keys are lower-case.
type Vars struct {
	User    map[string]string
	Group   map[string]string
	Account string
}

// UserVars are the placeholders of an account: username, email, display_name and external_id, then
// the request's own attributes. The four fixed names cannot be overridden by an attribute.
func UserVars(a target.Account) map[string]string {
	m := map[string]string{}
	for k, v := range a.Attrs {
		if pathRE.MatchString(k) {
			m[strings.ToLower(k)] = v
		}
	}
	for k, v := range map[string]string{"username": a.Username, "email": a.Email, "display_name": a.DisplayName, "external_id": a.ExternalID} {
		if v != "" {
			m[k] = v
		} else {
			delete(m, k)
		}
	}
	return m
}

func (v Vars) get(ref string) string {
	switch {
	case ref == "account":
		return v.Account
	case strings.HasPrefix(ref, "user."):
		return v.User[ref[len("user."):]]
	case strings.HasPrefix(ref, "group."):
		return v.Group[ref[len("group."):]]
	}
	return ""
}

// Errors of rendering. They never carry the value.
var (
	errMissing = &target.Error{Msg: "a template needs a value the request does not have"}
	errBadChar = &target.Error{Msg: "a value has characters a directory name or attribute cannot hold"}
)

func cleanValue(s string) bool {
	if len(s) > maxValue || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// render substitutes every placeholder, through esc. A missing or empty value is an error: a
// half-rendered name would be a different account.
func (t *Template) render(get func(string) string, esc func(string) string) (string, error) {
	var b strings.Builder
	for _, p := range t.parts {
		if p.ref == "" {
			b.WriteString(p.lit)
			continue
		}
		val := get(p.ref)
		if val == "" {
			return "", errMissing
		}
		if !cleanValue(val) {
			return "", errBadChar
		}
		b.WriteString(esc(val))
	}
	return b.String(), nil
}

func identity(s string) string { return s }

// RenderDN renders a DN template: every value is escaped as an RFC 4514 attribute value, the result
// must parse as a DN, and it must have as many RDNs as the template has when every value is a
// plain word, so a value can never add an RDN.
func (t *Template) RenderDN(v Vars) (string, error) {
	dn, err := t.render(v.get, goldap.EscapeDN)
	if err != nil {
		return "", err
	}
	got, err := goldap.ParseDN(dn)
	if err != nil || len(got.RDNs) == 0 {
		return "", target.Permanent("the rendered DN is not valid")
	}
	probe, perr := t.render(func(string) string { return "x" }, goldap.EscapeDN)
	if perr != nil {
		return "", target.Permanent("the DN template is not valid")
	}
	want, err := goldap.ParseDN(probe)
	if err != nil || len(want.RDNs) != len(got.RDNs) {
		return "", target.Permanent("the rendered DN does not have the shape of its template")
	}
	return dn, nil
}

// RenderValue renders an attribute value: the values are substituted as they are.
func (t *Template) RenderValue(v Vars) (string, error) { return t.render(v.get, identity) }

// EqFilter is "(attr=value)" with the value escaped (RFC 4515). attr must be a valid attribute name.
func EqFilter(attr, value string) (string, error) {
	if !attrNameRE.MatchString(attr) {
		return "", target.Permanent("not an attribute name")
	}
	return "(" + attr + "=" + goldap.EscapeFilter(value) + ")", nil
}
