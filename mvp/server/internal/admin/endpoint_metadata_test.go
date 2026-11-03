package admin

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// A sign-in connection endpoint (discovery, SSO, metadata, token and the rest) that names a cloud metadata
// service is refused when it is saved, in every written form.
func TestCheckEndpoint_RefusesMetadataHosts(t *testing.T) {
	for _, h := range []string{"169.254.169.254", "169.254.169.254.", "[fd00:ec2::254]", "[::ffff:169.254.169.254]:443",
		"metadata.google.internal.", "METADATA.GOOGLE.INTERNAL", "100.100.100.200"} {
		for _, prod := range []bool{false, true} {
			var got []string
			checkEndpoint(prod, "discovery_url", "https://"+h+"/.well-known/openid-configuration", func(f string, a ...any) { got = append(got, fmt.Sprintf(f, a...)) })
			if len(got) != 1 {
				t.Errorf("%s prod=%v: %v", h, prod, got)
			}
		}
	}
	var got []string
	checkEndpoint(true, "discovery_url", "https://login.example.com/.well-known/openid-configuration", func(f string, a ...any) { got = append(got, f) })
	if len(got) != 0 {
		t.Errorf("an ordinary endpoint was refused: %v", got)
	}
}

// A new sign-in connection (and an issuer change) that names a cloud metadata service in any of its endpoints is
// refused on save, for every protocol (#854).
func TestIdPConfigConnection_RefusesMetadataHosts(t *testing.T) {
	hosts := []string{"169.254.169.254", "169.254.169.254.", "[fd00:ec2::254]:443", "[::ffff:169.254.169.254]", "metadata.google.internal.", "METADATA.GOOGLE.INTERNAL"}
	mk := map[string]func(u string) IdPConfig{
		"oidc issuer": func(u string) IdPConfig {
			return IdPConfig{Protocol: "oidc", Profile: "generic_oidc", Issuer: u, ClientID: "c"}
		},
		"cas": func(u string) IdPConfig { return IdPConfig{Protocol: "cas", Profile: "generic_cas", CASServerURL: u} },
		"wsfed": func(u string) IdPConfig {
			return IdPConfig{Protocol: "wsfed", Profile: "adfs", IdPEntityID: "x", WSFedEndpoint: u}
		},
		"saml sso": func(u string) IdPConfig {
			return IdPConfig{Protocol: "saml", Profile: "generic_saml", IdPEntityID: "x", IdPSSOURL: u}
		},
		"oauth2 token": func(u string) IdPConfig {
			return IdPConfig{Protocol: "oauth2", Profile: "generic_oauth2", ClientID: "c", AuthorizationEndpoint: "https://good.example.com/a",
				TokenEndpoint: u, UserinfoEndpoint: "https://good.example.com/u", SubjectField: "id"}
		},
	}
	for name, f := range mk {
		for _, h := range hosts {
			for _, prod := range []bool{false, true} {
				c := f("https://" + h + "/x")
				_, err := c.Connection(IdPOptions{Prod: prod}, time.Now())
				if err == nil || !strings.Contains(err.Error(), "metadata") {
					t.Errorf("%s %s prod=%v: %v", name, h, prod, err)
				}
			}
		}
		c := f("https://good.example.com/x")
		if _, err := c.Connection(IdPOptions{Prod: true}, time.Now()); err != nil && strings.Contains(err.Error(), "metadata") {
			t.Errorf("%s: an ordinary host was refused as a metadata host: %v", name, err)
		}
	}
	var got []string
	checkIssuer(true, "generic_oidc", "https://169.254.169.254", func(f string, a ...any) { got = append(got, fmt.Sprintf(f, a...)) })
	if len(got) != 1 || !strings.Contains(got[0], "metadata") {
		t.Errorf("checkIssuer: %v", got)
	}
}
