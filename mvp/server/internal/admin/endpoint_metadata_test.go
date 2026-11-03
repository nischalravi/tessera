package admin

import (
	"fmt"
	"testing"
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
