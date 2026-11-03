package loaders_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/loaders"
)

// A loader whose URL names a cloud metadata service is refused when it is saved, in every written form (#855).
func TestValidateConfig_RefusesMetadataHosts(t *testing.T) {
	hosts := []string{"169.254.169.254", "169.254.169.254.", "169.254.169.254:80", "[fd00:ec2::254]", "[::ffff:169.254.169.254]", "metadata.google.internal.", "METADATA.GOOGLE.INTERNAL"}
	cfg := map[string]func(h string) (string, string){
		"csv": func(h string) (string, string) {
			return loaders.TypeCSV, fmt.Sprintf(`{"url":"https://%s/x.csv","group":"g","subject_column":"id"}`, h)
		},
		"scim": func(h string) (string, string) {
			return loaders.TypeSCIM, fmt.Sprintf(`{"base_url":"https://%s/scim/v2","subject_attr":"email"}`, h)
		},
		"ldap": func(h string) (string, string) {
			return loaders.TypeLDAPSimple, fmt.Sprintf(`{"url":"ldaps://%s","bind_dn":"cn=a,dc=b","base_dn":"dc=b","filter":"(a=b)","group":"g"}`, h)
		},
	}
	for name, mk := range cfg {
		for _, h := range hosts {
			typ, raw := mk(h)
			if _, err := loaders.ValidateConfig(typ, json.RawMessage(raw), false); err == nil || !strings.Contains(err.Error(), "metadata") {
				t.Errorf("%s %s: %v", name, h, err)
			}
		}
		typ, raw := mk("good.example.com")
		if _, err := loaders.ValidateConfig(typ, json.RawMessage(raw), false); err != nil && strings.Contains(err.Error(), "metadata") {
			t.Errorf("%s: an ordinary host was refused as metadata: %v", name, err)
		}
	}
}
