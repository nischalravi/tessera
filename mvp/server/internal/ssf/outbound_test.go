package ssf

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// TestOutboundURLRefusals: a transmitter-configured URL is checked before a
// request is built, whatever the safehttp client would do at dial time.
func TestOutboundURLRefusals(t *testing.T) {
	tests := []struct {
		name string
		url  string
		dev  bool
		ok   bool
	}{
		{"https host", "https://tx.example.com/jwks", false, true},
		{"https public ip", "https://8.8.8.8/jwks", false, true},
		{"http refused", "http://tx.example.com/jwks", false, false},
		{"http allowed in dev", "http://tx.example.com/jwks", true, true},
		{"ftp", "ftp://tx.example.com/jwks", true, false},
		{"file", "file:///etc/passwd", true, false},
		{"no scheme", "tx.example.com/jwks", false, false},
		{"no host", "https:///jwks", false, false},
		{"user info", "https://user:pw@tx.example.com/jwks", false, false},
		{"loopback v4", "https://127.0.0.1/jwks", false, false},
		{"loopback v6", "https://[::1]/jwks", false, false},
		{"loopback allowed in dev", "http://127.0.0.1:8001/jwks", true, true},
		{"private 10/8", "https://10.0.0.5/jwks", false, false},
		{"private 192.168", "https://192.168.1.1/jwks", true, false},
		{"link-local metadata", "https://169.254.169.254/latest", false, false},
		{"link-local metadata in dev", "http://169.254.169.254/latest", true, false},
		{"unique local v6", "https://[fd00::1]/jwks", false, false},
		{"mapped loopback", "https://[::ffff:127.0.0.1]/jwks", false, false},
		{"unspecified", "https://0.0.0.0/jwks", false, false},
		{"v6 zone", "https://[fe80::1%25eth0]/jwks", false, false},
		{"garbage", "https://exa mple.com/", false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &Service{Dev: tc.dev}
			_, err := s.outboundURL(tc.url)
			if (err == nil) != tc.ok {
				t.Errorf("outboundURL(%q, dev=%v) error = %v, want ok=%v", tc.url, tc.dev, err, tc.ok)
			}
		})
	}
}

// TestDoRefusesBeforeSending: do returns the refusal without touching HTTP, and
// the error never echoes the URL.
func TestDoRefusesBeforeSending(t *testing.T) {
	called := false
	s := &Service{HTTP: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, nil
	})}}
	_, _, err := s.do(context.Background(), http.MethodGet, "https://10.1.2.3/secret-path?token=abc", "", nil, 10)
	if err == nil || called {
		t.Fatalf("err = %v, request sent = %v; want a refusal and no request", err, called)
	}
	if strings.Contains(err.Error(), "secret-path") || strings.Contains(err.Error(), "abc") {
		t.Errorf("the refusal echoes the URL: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestOutboundSyntax: the anchored syntax do checks on the string it sends.
func TestOutboundSyntax(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://tx.example.com/jwks":                   true,
		"https://TX.example.com:8443/a/b?x=1&y=%20":     true,
		"http://127.0.0.1:8001/jwks":                    true,
		"https://[2001:db8::1]/jwks":                    true,
		"https://xn--bcher-kva.example/jwks":            true,
		"https://tx.example.com":                        true,
		"https://bücher.example/jwks":                   false,
		"https://tx.example.com/jwks#frag":              false,
		"https://u:p@tx.example.com/jwks":               false,
		"https://-tx.example.com/jwks":                  false,
		"https://tx.example.com/a b":                    false,
		"https://tx.example.com/a\\b":                   false,
		"ftp://tx.example.com/jwks":                     false,
		"https://tx.example.com/jwks\r\nHost: evil":     false,
		" https://tx.example.com/jwks":                  false,
		"https://tx.example.com/jwks?next=http://x/y?z": true,
	} {
		if got := outboundSyntax.MatchString(raw); got != ok {
			t.Errorf("outboundSyntax(%q) = %v, want %v", raw, got, ok)
		}
	}
}
