package rules

import (
	"strings"
	"testing"
)

// A webhook rule whose URL has a non-ASCII host, written or percent-encoded, is refused when it is saved, with
// url_non_ascii_authority and without echoing the value; ASCII, punycode, IPv6 and host:port forms still pass (#942).
func TestCheckURL_RefusesNonASCIIHosts(t *testing.T) {
	for _, bad := range []string{"https://exämple.com/hook", "https://h%E2%88%B6x.example/hook", "https://h%e2%88%b6x.example/hook",
		"https://h.example∕x@y/hook", "https∶//h.example/hook", "https://hooks.slаck.com/x"} {
		err := checkURL(bad, false)
		e, ok := err.(*Error)
		if !ok || e.Code != "url_non_ascii_authority" || e.Kind != Invalid {
			t.Errorf("checkURL(%q) = %v, want url_non_ascii_authority", bad, err)
			continue
		}
		if strings.Contains(e.Msg, "exämple") || strings.Contains(e.Msg, "%E2") {
			t.Errorf("checkURL(%q) echoes the value: %q", bad, e.Msg)
		}
	}
	for _, ok := range []string{"https://hooks.example.com/hook", "https://xn--exmple-cua.com/hook", "https://[2001:db8::1]:8443/hook",
		"https://hooks.example.com:8443/h", "https://hooks.example.com/ä"} {
		if err := checkURL(ok, false); err != nil {
			t.Errorf("checkURL(%q) = %v, want nil", ok, err)
		}
	}
}
