package alerts

import (
	"errors"
	"testing"
)

// A webhook URL whose host is non-ASCII, written or percent-encoded, is refused at save (create and update both
// run check) with url_non_ascii_authority; ASCII, punycode, IPv6 and host:port forms pass (#939).
func TestWebhookCheck_NonASCIIHost(t *testing.T) {
	for target, refused := range map[string]bool{
		"https://hooks.exämple.com/x":                    true,
		"https://hooks.example.com%E2%88%B6@evil.test/x": true,
		"https://hooks.%C3%A4.example.com/x":             true,
		"https://hooks.example.com/x":                    false,
		"https://xn--hooks-bn.example.com/x":             false,
		"https://[2001:db8::1]:8443/x":                   false,
		"https://hooks.example.com:8443/ä":               false,
	} {
		s := ChannelSpec{Name: "n", Kind: "webhook", Target: target, MinSeverity: "low"}
		err := s.check(false)
		var e *Error
		got := errors.As(err, &e) && e.Code == CodeURLNonASCIIAuthority
		if got != refused {
			t.Errorf("%s: err %v, refused %v want %v", target, err, got, refused)
		}
		if got && (e.Status != 422 || len(e.Msg) == 0) {
			t.Errorf("%s: %+v", target, e)
		}
	}
}
