package rules

import (
	"strings"
	"testing"
)

// A webhook rule whose URL names a cloud metadata service is refused when it is saved, in every written form (#865).
func TestCheckURL_RefusesMetadataHosts(t *testing.T) {
	hosts := []string{"169.254.169.254", "169.254.169.254.", "169.254.169.254:80", "[fd00:ec2::254]", "[::ffff:169.254.169.254]", "[::ffff:a9fe:a9fe]:80",
		"metadata.google.internal.", "METADATA.GOOGLE.INTERNAL", "100.100.100.200", "192.0.0.192", "168.63.129.16", "169.254.170.2"}
	for _, h := range hosts {
		for _, scheme := range []string{"https://", "http://"} {
			err := checkURL(scheme + h + "/hook")
			if err == nil || !strings.Contains(err.Error(), "metadata") {
				t.Errorf("checkURL(%s%s/hook) = %v, want a metadata refusal", scheme, h, err)
			}
		}
	}
	for _, ok := range []string{"https://good.example.com/hook", "http://good.example.com:8080/hook", "https://10.1.2.3/hook"} {
		if err := checkURL(ok); err != nil {
			t.Errorf("checkURL(%s) = %v, want nil", ok, err)
		}
	}
}
