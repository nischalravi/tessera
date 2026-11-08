package transport

import "testing"

// Look-alike separators (issue #936): left out of the export; plain, path-@ and punycode URLs are kept.
func TestCleanStringConfusableSeparators(t *testing.T) {
	for _, c := range []string{"∶", "꞉", "։", "׃", "܃", "܄", "᛬", "፡", "˸"} {
		for _, s := range []string{"https" + c + "//u:p@h.example/x", "https" + c + "//h.example/x"} {
			if _, v := cleanString(s); v != verdictExcluded {
				t.Errorf("cleanString(%q) = %v, want excluded", s, v)
			}
		}
	}
	for _, s := range []string{"https:⁄⁄h.example", "https://u:p＠h.example", "https://h.example∕x@y"} {
		if _, v := cleanString(s); v != verdictExcluded {
			t.Errorf("cleanString(%q) = %v, want excluded", s, v)
		}
	}
	for _, s := range []string{"https://api.example.com/v2", "https://xn--bcher-kva.example/x", "https://api.example.com/a@b"} {
		if out, v := cleanString(s); v != verdictKeep || out != s {
			t.Errorf("cleanString(%q) = %q, %v", s, out, v)
		}
	}
	out, cleaned, excl := cleanConfig([]byte(`{"base_url":"https∶//h.example","org_url":"https://o.example"}`))
	if len(excl) != 1 || excl[0] != "base_url" || cleaned {
		t.Errorf("cleanConfig = %s %v %v", out, cleaned, excl)
	}
}
