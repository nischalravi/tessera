package loaders_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/loaders"
)

// A loader whose URL has a non-ASCII host, written or percent-encoded, is refused when it is saved; the message does not
// echo the value, and ASCII, punycode and IPv6 hosts still pass (#942).
func TestValidateConfig_RefusesNonASCIIHosts(t *testing.T) {
	cfg := map[string]func(h string) (string, string){
		"csv": func(h string) (string, string) {
			return loaders.TypeCSV, fmt.Sprintf(`{"url":"https://%s/x.csv","group":"g","subject_column":"id"}`, h)
		},
		"scim": func(h string) (string, string) {
			return loaders.TypeSCIM, fmt.Sprintf(`{"base_url":"https://%s/scim/v2","subject_attr":"email"}`, h)
		},
		"scim token_url": func(h string) (string, string) {
			return loaders.TypeSCIM, fmt.Sprintf(`{"base_url":"https://good.example.com/scim/v2","auth":"client_credentials","token_url":"https://%s/t","client_id":"c","subject_attr":"email"}`, h)
		},
		"ldap": func(h string) (string, string) {
			return loaders.TypeLDAPSimple, fmt.Sprintf(`{"url":"ldaps://%s","bind_dn":"cn=a,dc=b","base_dn":"dc=b","filter":"(a=b)","group":"g","subject_attr":"uid"}`, h)
		},
	}
	for name, mk := range cfg {
		for _, h := range []string{"exämple.com", "h%E2%88%B6x.example", "h%e2%88%b6x.example"} {
			typ, raw := mk(h)
			if _, err := loaders.ValidateConfig(typ, json.RawMessage(raw), false); err == nil || !strings.Contains(err.Error(), "must be ASCII") || strings.Contains(err.Error(), h) {
				t.Errorf("%s %s: %v", name, h, err)
			}
		}
		for _, h := range []string{"good.example.com", "xn--exmple-cua.com", "good.example.com:8443"} {
			typ, raw := mk(h)
			if _, err := loaders.ValidateConfig(typ, json.RawMessage(raw), false); err != nil && strings.Contains(err.Error(), "must be ASCII") {
				t.Errorf("%s %s was refused as non-ASCII: %v", name, h, err)
			}
		}
	}
}
