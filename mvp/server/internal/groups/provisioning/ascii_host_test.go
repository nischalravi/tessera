package provisioning

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// A group provisioner whose target URL has a non-ASCII host, written or percent-encoded, is refused when it is saved,
// and the message does not echo the value; ASCII, punycode and IPv6 hosts still pass (#942).
func TestTargetURLs_RefuseNonASCIIHosts(t *testing.T) {
	bad := []string{"exämple.com", "h%E2%88%B6x.example", "h%e2%88%b6x.example", "hooks.slаck.com"}
	for _, h := range bad {
		_, err := httpURL("target.url", "https://"+h+"/x", false)
		if err == nil || !strings.Contains(err.Error(), "must be ASCII") || strings.Contains(err.Error(), h) {
			t.Errorf("httpURL %s: %v", h, err)
		}
		c := &Compiled{Target: json.RawMessage(fmt.Sprintf(`{"url":"ldaps://%s","base_dn":"ou=g,dc=a,dc=b","bind_dn":"cn=svc,dc=a,dc=b"}`, h))}
		if _, err := parseLDAPConfig(TypeLDAP, c, Deps{}); err == nil || !strings.Contains(err.Error(), "must be ASCII") || strings.Contains(err.Error(), h) {
			t.Errorf("ldap %s: %v", h, err)
		}
	}
	for _, h := range []string{"scim.example.com", "xn--exmple-cua.com", "[2001:db8::1]:8443", "scim.example.com:8443"} {
		if _, err := httpURL("target.url", "https://"+h+"/x", false); err != nil {
			t.Errorf("httpURL %s was refused: %v", h, err)
		}
	}
}
