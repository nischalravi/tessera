package admin

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// A sign-in endpoint with a non-ASCII host, written or percent-encoded, is refused on save; ASCII, punycode, IPv6
// and host:port forms are not (#939).
func TestIdPConfigConnection_NonASCIIHost(t *testing.T) {
	mk := map[string]func(u string) IdPConfig{
		"oidc": func(u string) IdPConfig {
			return IdPConfig{Protocol: "oidc", Profile: "generic_oidc", Issuer: u, ClientID: "c"}
		},
		"cas": func(u string) IdPConfig { return IdPConfig{Protocol: "cas", Profile: "generic_cas", CASServerURL: u} },
		"wsfed": func(u string) IdPConfig {
			return IdPConfig{Protocol: "wsfed", Profile: "adfs", IdPEntityID: "x", WSFedEndpoint: u}
		},
		"saml": func(u string) IdPConfig {
			return IdPConfig{Protocol: "saml", Profile: "generic_saml", IdPEntityID: "x", IdPSSOURL: u}
		},
		"oauth2": func(u string) IdPConfig {
			return IdPConfig{Protocol: "oauth2", Profile: "generic_oauth2", ClientID: "c", AuthorizationEndpoint: "https://good.example.com/a",
				TokenEndpoint: u, UserinfoEndpoint: "https://good.example.com/u", SubjectField: "id"}
		},
	}
	const want = "scheme and host must be ASCII"
	for name, f := range mk {
		for _, u := range []string{"https://idp.exämple.com/x", "https://idp.%C3%A4.example.com/x", "https://idp.example.com%E2%88%B6@evil.test/x"} {
			c := f(u)
			if _, err := c.Connection(IdPOptions{}, time.Now()); err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), "xample.com%") {
				t.Errorf("%s %s: %v", name, u, err)
			}
		}
		for _, u := range []string{"https://idp.example.com/x", "https://xn--idp-bn.example.com:8443/x", "https://[2001:db8::1]:8443/x"} {
			c := f(u)
			if _, err := c.Connection(IdPOptions{}, time.Now()); err != nil && strings.Contains(err.Error(), want) {
				t.Errorf("%s %s: %v", name, u, err)
			}
		}
	}
	var got []string
	checkIssuer(false, "generic_oidc", "https://idp.%C3%A4.example.com", func(f string, a ...any) { got = append(got, fmt.Sprintf(f, a...)) })
	if len(got) != 1 || !strings.Contains(got[0], want) {
		t.Errorf("checkIssuer: %v", got)
	}
}
