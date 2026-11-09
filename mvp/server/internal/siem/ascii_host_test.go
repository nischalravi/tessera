package siem

import (
	"errors"
	"testing"
)

// A sink target whose host is non-ASCII, written or percent-encoded, is refused at save (create and update both
// run check) with url_non_ascii_authority; ASCII, punycode, IPv6 and host:port forms pass (#939).
func TestSinkCheck_NonASCIIHost(t *testing.T) {
	cases := map[string][]string{
		"webhook": {"https://siem.exämple.com/x", "https://siem.%C3%A4.example.com/x", "https://siem.example.com%E2%88%B6@evil.test/x"},
		"s3":      {"https://bücket.example.com/p", "https://b%C3%BCcket.example.com/p"},
		"syslog":  {"sïem.example.com:6514", "s%C3%AFem.example.com:6514"},
	}
	ok := map[string][]string{
		"webhook": {"https://siem.example.com/x", "https://xn--siem-bn.example.com/x", "https://[2001:db8::1]:8443/x", "https://siem.example.com:8443/ä"},
		"s3":      {"https://bucket.example.com/p", "https://xn--bcket-bn.example.com:9000/p"},
		"syslog":  {"siem.example.com:6514", "xn--sem-bn.example.com", "[2001:db8::1]:6514"},
	}
	run := func(kind, target string) *Error {
		s := SinkSpec{Name: "n", Kind: kind, Target: target, Format: FormatJSON, Flavor: FlavorJSON, Region: "eu-west-1"}
		var e *Error
		errors.As(s.check(false), &e)
		return e
	}
	for kind, ts := range cases {
		for _, target := range ts {
			if e := run(kind, target); e == nil || e.Code != CodeURLNonASCIIAuthority || e.Status != 400 {
				t.Errorf("%s %s: %v", kind, target, e)
			}
		}
	}
	for kind, ts := range ok {
		for _, target := range ts {
			if e := run(kind, target); e != nil && e.Code == CodeURLNonASCIIAuthority {
				t.Errorf("%s %s refused as non-ASCII", kind, target)
			}
		}
	}
}
