package urlshape

import "testing"

func TestClassify(t *testing.T) {
	for _, c := range []struct {
		in, canon string
		sh        Shape
	}{
		{"", "", NotURL},
		{"a.okta.com", "a.okta.com", NotURL},
		{"ingrid@corp.example", "ingrid@corp.example", NotURL},
		{"https://a.okta.com/x", "https://a.okta.com/x", Authority},
		{"HTTPS:u:p@a.okta.com", "https://u:p@a.okta.com", Authority},
		{`https:\\u:p@a.okta.com\v2?q=a\b`, `https://u:p@a.okta.com/v2?q=a\b`, Authority},
		{`https:\/u:p@a.okta.com`, "https://u:p@a.okta.com", Authority},
		{"https:///a.okta.com", "https://a.okta.com", Authority},
		{" \x00https:\t/\n/a.okta.com\r ", "https://a.okta.com", Authority},
		{"ws:h", "ws://h", Authority},
		{`\\u:p@h`, "//u:p@h", Authority},
		{`/\h`, "//h", Authority},
		{"/path", "/path", NotURL},
		{"ldap://u:p@h", "ldap://u:p@h", Authority},
		{`ldap:\\u:p@h`, `ldap:\\u:p@h`, Opaque},
		{"mailto:a@b", "mailto:a@b", Opaque},
		{"a.okta.com:443", "a.okta.com:443", Opaque},
		{"u:p@a.okta.com", "u:p@a.okta.com", Opaque},
	} {
		canon, sh := Classify(c.in)
		if canon != c.canon || sh != c.sh {
			t.Errorf("Classify(%q) = %q, %d; want %q, %d", c.in, canon, sh, c.canon, c.sh)
		}
		if again, sh2 := Classify(canon); again != canon || sh2 != sh {
			t.Errorf("Classify is not idempotent on %q: %q, %d", canon, again, sh2)
		}
	}
}

func TestURLSetting(t *testing.T) {
	for k, want := range map[string]bool{"api_url": true, "API_URL": true, "redirect_uri": true, "Token_Endpoint": true, "label": false} {
		if URLSetting(k, "x") != want {
			t.Errorf("URLSetting(%q) != %v", k, want)
		}
	}
	if !URLSetting("feed", "https:h.example") || URLSetting("feed", "plain") || URLSetting("contact", "mailto:a@b") {
		t.Error("value-based classification is wrong")
	}
}
