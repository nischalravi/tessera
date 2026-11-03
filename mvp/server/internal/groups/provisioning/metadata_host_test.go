package provisioning

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// A group provisioner whose target URL names a cloud metadata service is refused when it is saved (#855).
func TestTargetURLs_RefuseMetadataHosts(t *testing.T) {
	hosts := []string{"169.254.169.254", "169.254.169.254.", "169.254.169.254:80", "[fd00:ec2::254]", "[::ffff:169.254.169.254]", "metadata.google.internal.", "METADATA.GOOGLE.INTERNAL"}
	for _, h := range hosts {
		if _, err := httpURL("target.url", "https://"+h+"/x", false); err == nil || !strings.Contains(err.Error(), "metadata") {
			t.Errorf("httpURL %s: %v", h, err)
		}
		c := &Compiled{Target: json.RawMessage(fmt.Sprintf(`{"url":"ldaps://%s","base_dn":"ou=g,dc=a,dc=b","bind_dn":"cn=svc,dc=a,dc=b"}`, h))}
		if _, err := parseLDAPConfig(TypeLDAP, c, Deps{}); err == nil || !strings.Contains(err.Error(), "metadata") {
			t.Errorf("ldap %s: %v", h, err)
		}
	}
	if _, err := httpURL("target.url", "https://scim.example.com/x", false); err != nil {
		t.Errorf("an ordinary URL was refused: %v", err)
	}
}
