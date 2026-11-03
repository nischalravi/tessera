package ssf

import (
	"strings"
	"testing"
)

// jwks_url, poll_url and verification_url that name a cloud metadata service are refused at save time.
func TestCheckURL_RefusesMetadataHosts(t *testing.T) {
	for _, h := range []string{"169.254.169.254", "169.254.169.254.", "169.254.169.254..:443", "[fd00:ec2::254]", "[::ffff:169.254.169.254]:443",
		"metadata.google.internal.", "METADATA.GOOGLE.INTERNAL", "100.100.100.200", "168.63.129.16"} {
		if err := checkURL("poll_url", "https://"+h+"/x"); err == nil || !strings.Contains(err.Error(), "metadata") {
			t.Errorf("%s: %v", h, err)
		}
	}
	if err := checkURL("poll_url", "https://ssf.example.com/poll"); err != nil {
		t.Errorf("an ordinary URL was refused: %v", err)
	}
}
