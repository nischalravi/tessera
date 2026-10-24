package ldapwrite

import (
	"sort"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
)

// normRDN is one RDN in a form two equal RDNs share: attribute types lower-cased and sorted, values
// lower-cased with surrounding space trimmed.
func normRDN(r *goldap.RelativeDN) string {
	parts := make([]string, 0, len(r.Attributes))
	for _, a := range r.Attributes {
		parts = append(parts, strings.ToLower(a.Type)+"="+strings.ToLower(strings.TrimSpace(a.Value)))
	}
	sort.Strings(parts)
	return strings.Join(parts, "+")
}

// dnBelow reports whether dn is a descendant of root (strictly below it: the root entry itself is
// not). Both must parse; a name that does not parse is never below anything.
func dnBelow(dn, root string) bool {
	d, err := goldap.ParseDN(dn)
	if err != nil {
		return false
	}
	r, err := goldap.ParseDN(root)
	if err != nil || len(r.RDNs) == 0 || len(d.RDNs) <= len(r.RDNs) {
		return false
	}
	off := len(d.RDNs) - len(r.RDNs)
	for i := range r.RDNs {
		if normRDN(d.RDNs[off+i]) != normRDN(r.RDNs[i]) {
			return false
		}
	}
	return true
}

// sameDN reports whether two DNs name the same entry.
func sameDN(a, b string) bool {
	x, err := goldap.ParseDN(a)
	if err != nil {
		return false
	}
	y, err := goldap.ParseDN(b)
	if err != nil || len(x.RDNs) != len(y.RDNs) {
		return false
	}
	for i := range x.RDNs {
		if normRDN(x.RDNs[i]) != normRDN(y.RDNs[i]) {
			return false
		}
	}
	return true
}

// parentDN is dn without its first RDN ("" if it has one RDN or does not parse).
func parentDN(dn string) string {
	d, err := goldap.ParseDN(dn)
	if err != nil || len(d.RDNs) < 2 {
		return ""
	}
	parts := make([]string, 0, len(d.RDNs)-1)
	for _, r := range d.RDNs[1:] {
		parts = append(parts, rdnString(r))
	}
	return strings.Join(parts, ",")
}

// rdnString writes an RDN with its values escaped.
func rdnString(r *goldap.RelativeDN) string {
	parts := make([]string, 0, len(r.Attributes))
	for _, a := range r.Attributes {
		parts = append(parts, a.Type+"="+goldap.EscapeDN(a.Value))
	}
	return strings.Join(parts, "+")
}

// firstRDN is the leftmost RDN of dn, escaped.
func firstRDN(dn string) (string, bool) {
	d, err := goldap.ParseDN(dn)
	if err != nil || len(d.RDNs) == 0 {
		return "", false
	}
	return rdnString(d.RDNs[0]), true
}

// InScope reports whether dn is strictly below one of the write-scope OUs. It is the check every
// write passes: a DN outside the named OUs, or one that does not parse, is never written.
func (c *Config) InScope(dn string) bool {
	for _, ou := range c.WriteScope {
		if dnBelow(dn, ou) {
			return true
		}
	}
	return false
}
