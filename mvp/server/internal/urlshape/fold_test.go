package urlshape

import "testing"

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
