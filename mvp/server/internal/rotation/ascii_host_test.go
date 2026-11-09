package rotation

import (
	"errors"
	"strings"
	"testing"
)

// A rotation adapter endpoint with a non-ASCII host, written or percent-encoded, is refused on save without echoing
// it; ASCII, punycode, IPv6 and host:port forms are not (#939).
func TestCleanConfig_RefusesNonASCIIHost(t *testing.T) {
	cases := []struct{ typ, key string }{{TypeVault, "address"}, {TypeGitHub, "api_url"}, {TypeAWSIAM, "endpoint"}}
	for _, c := range cases {
		mk := func(u string) map[string]string {
			in := map[string]string{c.key: u}
			if c.typ == TypeAWSIAM {
				in["region"] = "eu-west-1"
			}
			return in
		}
		for _, u := range []string{"https://vault.exämple.com/x", "https://vault.%C3%A4.example.com", "https://vault.example.com%E2%88%B6@evil.test/x"} {
			_, err := cleanConfig(c.typ, mk(u), "prod")
			if !errors.Is(err, errNonASCIIHost) || strings.Contains(err.Error(), "example.com") || strings.Contains(err.Error(), "evil") {
				t.Errorf("%s %s: %v", c.typ, u, err)
			}
		}
		for _, u := range []string{"https://vault.example.com", "https://xn--vault-bn.example.com:8443", "https://[2001:db8::1]:8443"} {
			if _, err := cleanConfig(c.typ, mk(u), "prod"); err != nil {
				t.Errorf("%s %s: %v", c.typ, u, err)
			}
		}
	}
}
