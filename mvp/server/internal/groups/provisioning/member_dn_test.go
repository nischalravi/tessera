package provisioning

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// The member_ref of a DN-valued LDAP/AD target is DN-escaped (issue #388): a
// username cannot add RDNs, add attribute values to the RDN or end the DN early.
func TestMemberRefDNEscaped(t *testing.T) {
	const tail = ",ou=people,dc=example,dc=com"
	cfg := func(ref, class string) json.RawMessage {
		tgt := map[string]any{"url": "ldaps://ldap.example.com", "base_dn": "dc=example,dc=com", "bind_dn": "cn=svc,dc=x"}
		if class != "" {
			tgt["object_class"] = class
		}
		return scimConfig(map[string]any{"member_ref": ref, "target": tgt})
	}
	hostile := []string{
		"bob,ou=admins", "bob+uid=root", "bob=x", `bob\`, `bob\,ou=admins`, "#bob", " bob", "bob ",
		"bob\x00,ou=admins", "bob,cn=Domain Admins,dc=example,dc=com", `bob"`, "bob;ou=x", "bob<x>",
	}
	for _, typ := range []string{TypeLDAP, TypeAD} {
		for _, ref := range []string{"uid={{.Username}}" + tail, "uid={{.Username | ldapEscape}}" + tail, "uid={{.ExternalID}}" + tail} {
			c, err := ParseCommonFor(typ, cfg(ref, ""))
			if err != nil {
				t.Fatal(err)
			}
			for _, u := range hostile {
				got, err := c.Member(MemberData{IdentityID: 1, Username: u, ExternalID: u})
				if err != nil {
					t.Errorf("%s %q: %v", typ, u, err)
					continue
				}
				dn, err := ldap.ParseDN(got)
				if err != nil {
					t.Errorf("%s %q: %q is not a DN: %v", typ, u, got, err)
					continue
				}
				// exactly the template's RDNs, the first one a single uid=<the username>
				if len(dn.RDNs) != 4 || len(dn.RDNs[0].Attributes) != 1 || dn.RDNs[0].Attributes[0].Type != "uid" ||
					!strings.HasSuffix(got, tail) {
					t.Errorf("%s %q: %q points elsewhere (%d RDNs)", typ, u, got, len(dn.RDNs))
					continue
				}
				// the value is the username (the library trims unescaped edge spaces, never the escaped ones)
				if v := dn.RDNs[0].Attributes[0].Value; v != u {
					t.Errorf("%s %q: value %q", typ, u, v)
				}
			}
		}
	}
	// a template that strips the escapes cannot widen the DN: the shape check refuses it
	c, err := ParseCommonFor(TypeLDAP, cfg(`uid={{.Username | replace "\\" ""}}`+tail, ""))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.Member(MemberData{Username: "bob,ou=admins"}); err == nil {
		t.Errorf("a stripped escape gave %q", got)
	}
	// a non-DN member attribute (memberUid) is left as the template renders it
	c, err = ParseCommonFor(TypeLDAP, cfg("{{.Username}}", "posixGroup"))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := c.Member(MemberData{Username: "a,b"}); got != "a,b" {
		t.Errorf("memberUid reference = %q", got)
	}
	// the default member_ref is not a DN: its value is still escaped
	c, err = ParseCommonFor(TypeAD, scimConfig(map[string]any{"member_ref": "",
		"target": map[string]any{"url": "ldaps://ldap.example.com", "base_dn": "dc=example,dc=com", "bind_dn": "cn=svc,dc=x"}}))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := c.Member(MemberData{Username: "a,b=c"}); got != `a\,b\=c` {
		t.Errorf("default reference = %q", got)
	}
}
