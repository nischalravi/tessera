package safehttp

import "testing"

func TestOrigin(t *testing.T) {
	same := [][2]string{
		{"https://a.example/x", "https://A.example:443/y?q=1"},
		{"http://127.0.0.1/a", "http://127.0.0.1:80/b"},
		{"https://[::1]:8443/a", "https://[::1]:8443/"},
	}
	for _, c := range same {
		if Origin(c[0]) != Origin(c[1]) {
			t.Errorf("%s and %s should share an origin: %s, %s", c[0], c[1], Origin(c[0]), Origin(c[1]))
		}
	}
	diff := [][2]string{
		{"https://a.example/x", "https://b.example/x"},
		{"https://a.example/x", "http://a.example/x"},
		{"https://a.example/x", "https://a.example:8443/x"},
		{"https://a.example/x", "https://a.example.evil.example/x"},
	}
	for _, c := range diff {
		if Origin(c[0]) == Origin(c[1]) {
			t.Errorf("%s and %s should differ in origin: %s", c[0], c[1], Origin(c[0]))
		}
	}
}
