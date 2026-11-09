package ssf

import (
	"errors"
	"strings"
	"testing"
)

// A transmitter URL with a non-ASCII host, written or percent-encoded, is refused with url_non_ascii_authority and
// not echoed; ASCII, punycode, IPv6 and host:port forms pass (#939).
func TestCheckURL_NonASCIIHost(t *testing.T) {
	for _, u := range []string{"https://ssf.exämple.com/jwks", "https://ssf.%C3%A4.example.com/jwks", "https://ssf.example.com%E2%88%B6@evil.test/jwks"} {
		var ce *ConfigError
		err := checkURL("jwks_url", u)
		if !errors.As(err, &ce) || ce.Code != CodeURLNonASCIIAuthority || strings.Contains(ce.Msg, "example.com") || strings.Contains(ce.Msg, "evil") {
			t.Errorf("%s: %v", u, err)
		}
	}
	for _, u := range []string{"https://ssf.example.com/jwks", "https://xn--ssf-bn.example.com:8443/jwks", "https://[2001:db8::1]:8443/jwks"} {
		if err := checkURL("jwks_url", u); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
}
