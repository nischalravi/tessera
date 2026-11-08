package urlshape

import (
	"testing"

	"golang.org/x/text/unicode/norm"
)

// Fold reads zero-width and compatibility forms as the ASCII a reader sees (issue #932).
func TestFold(t *testing.T) {
	for in, want := range map[string]string{
		"https\u200b://u:p@h":                  "https://u:p@h",
		"https\ufeff\u200e://u:p@h":            "https://u:p@h",
		"https\uff1a\uff0f\uff0fu:p\uff20h":    "https://u:p@h",
		"\uff48\uff54\uff54\uff50\uff53:\\\\h": "https:\\\\h",
		"https\ufe55//u:p\ufe6bh":              "https://u:p@h",
		"h\u3002example\uff61com\uff0eio":      "h.example.com.io",
		"0 3 * * *":                            "0 3 * * *",
		"Thandiwe Mokoena":                     "Thandiwe Mokoena",
		"ラークスパー営業部":                            "ラークスパー営業部",
	} {
		if got := Fold(in); got != want {
			t.Errorf("Fold(%q) = %q, want %q", in, got, want)
		}
		if got := Fold(Fold(in)); got != Fold(in) {
			t.Errorf("Fold is not idempotent on %q", in)
		}
	}
}

// Every confusables entry is something NFKC leaves alone, and Fold maps it to its ASCII look-alike (issue #936).
func TestFoldConfusables(t *testing.T) {
	for r, want := range confusables {
		if n := norm.NFKC.String(string(r)); n != string(r) {
			t.Errorf("U+%04X is changed by NFKC (%q); drop it from confusables", r, n)
		}
		if got := Fold("https" + string(r) + "//u:p" + string(r) + "h"); want == ':' && got != "https://u:p:h" {
			t.Errorf("Fold colon U+%04X = %q", r, got)
		}
		if want == '/' {
			if got := Fold("https:" + string(r) + string(r) + "h"); got != "https://h" {
				t.Errorf("Fold slash U+%04X = %q", r, got)
			}
		}
	}
}

func TestNonASCIIHead(t *testing.T) {
	for v, want := range map[string]bool{
		"https://api.example.com/v2":       false,
		"https://xn--bcher-kva.example/x":  false,
		"https://api.example.com/a@b/café": false,
		"https://api.example.com/p?q=é":    false,
		"https://api.example.com":          false,
		"":                                 false,
		"https∶//u:p@h":                    true,
		"https꞉//h":                        true,
		"https։//h":                        true,
		"https://u:p＠h/x":                  true,
		"https://bücher.example/":          true,
		"https:⁄/h":                        true,
		"https://h∕x":                      true,
		"\\\\bücher.example\\x":            true,
	} {
		if got := NonASCIIHead(v); got != want {
			t.Errorf("NonASCIIHead(%q) = %v, want %v", v, got, want)
		}
	}
}
