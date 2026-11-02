package rotation

import (
	"strings"
	"testing"
)

// A rotation adapter whose endpoint names a cloud metadata service is refused when it is saved, so no
// credential is sealed for an address the dial guard will never let through.
func TestCleanConfig_RefusesMetadataEndpoints(t *testing.T) {
	hosts := []string{"169.254.169.254", "169.254.169.254.", "169.254.169.254..", "[fd00:ec2::254]", "[::ffff:169.254.169.254]",
		"metadata.google.internal", "METADATA.GOOGLE.INTERNAL.", "100.100.100.200", "168.63.129.16"}
	cases := []struct{ typ, key string }{{TypeVault, "address"}, {TypeGitHub, "api_url"}, {TypeAWSIAM, "endpoint"}, {TypeAWSSM, "endpoint"}}
	for _, c := range cases {
		for _, h := range hosts {
			in := map[string]string{c.key: "https://" + h + "/x"}
			if c.typ == TypeAWSIAM || c.typ == TypeAWSSM {
				in["region"] = "eu-west-1"
			}
			_, err := cleanConfig(c.typ, in, "prod")
			if err == nil || !strings.Contains(err.Error(), "metadata") {
				t.Errorf("%s %s=%s: %v", c.typ, c.key, h, err)
			}
		}
		ok := map[string]string{c.key: "https://good.example.com"}
		if c.typ == TypeAWSIAM || c.typ == TypeAWSSM {
			ok["region"] = "eu-west-1"
		}
		if _, err := cleanConfig(c.typ, ok, "prod"); err != nil {
			t.Errorf("%s: an ordinary endpoint was refused: %v", c.typ, err)
		}
	}
}
