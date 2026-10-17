package naming

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateExtension(t *testing.T) {
	for _, tc := range []struct {
		in string
		ok bool
	}{
		{"foo", true}, {"Foo_Bar-1.2", true}, {"a", true}, {strings.Repeat("a", 255), true},
		{"", false}, {strings.Repeat("a", 256), false}, {".", false}, {"..", false},
		{"a:b", false}, {"a b", false}, {"a/b", false}, {"é", false}, {"a%", false}, {"a\x00", false}, {"a*", false},
	} {
		err := ValidateExtension(tc.in)
		if (err == nil) != tc.ok {
			t.Errorf("ValidateExtension(%q) = %v, want ok=%t", tc.in, err, tc.ok)
		}
		var ne *Error
		if err != nil && (!errors.As(err, &ne) || ne.Code != CodeInvalidName) {
			t.Errorf("ValidateExtension(%q) error %v is not invalid_name", tc.in, err)
		}
	}
}

func TestValidateDisplay(t *testing.T) {
	for in, ok := range map[string]bool{"Foo application": true, "Café": true, "": true, "a\nb": false,
		strings.Repeat("x", 256): false, "\xff": false} {
		if err := ValidateDisplay(in); (err == nil) != ok {
			t.Errorf("ValidateDisplay(%q) = %v, want ok=%t", in, err, ok)
		}
	}
}

func TestParseJoinSplit(t *testing.T) {
	if segs, err := Parse("app:foo:bar"); err != nil || len(segs) != 3 {
		t.Errorf("Parse = %v, %v", segs, err)
	}
	if segs, err := Parse(""); err != nil || len(segs) != 0 {
		t.Errorf("Parse(root) = %v, %v", segs, err)
	}
	for _, bad := range []string{":a", "a:", "a::b", "a:b c", strings.Repeat("a:", MaxDepth) + "a"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
	if n, err := Join("", "app"); err != nil || n != "app" {
		t.Errorf("Join(root) = %q, %v", n, err)
	}
	if n, err := Join("app", "foo"); err != nil || n != "app:foo" {
		t.Errorf("Join = %q, %v", n, err)
	}
	if _, err := Join("app", "a:b"); err == nil {
		t.Error("Join accepted a segment holding the separator")
	}
	if p, e := Split("app:foo:bar"); p != "app:foo" || e != "bar" {
		t.Errorf("Split = %q, %q", p, e)
	}
	if p, e := Split("app"); p != "" || e != "app" {
		t.Errorf("Split(top) = %q, %q", p, e)
	}
}

func TestCaseInsensitive(t *testing.T) {
	if !Equal("App:Foo", "app:FOO") || Equal("app:foo", "app:fooo") {
		t.Error("Equal is not case-insensitive exact")
	}
	for _, tc := range []struct {
		name, prefix string
		want         bool
	}{
		{"app:foo", "app", true}, {"APP:foo", "app", true}, {"app", "app", true}, {"application:foo", "app", false},
		{"app:foo", "", true}, {"app_x:foo", "app", false},
	} {
		if got := IsWithin(tc.name, tc.prefix); got != tc.want {
			t.Errorf("IsWithin(%q, %q) = %t", tc.name, tc.prefix, got)
		}
	}
}

func TestRebase(t *testing.T) {
	for _, tc := range []struct {
		name, old, new, want string
		ok                   bool
	}{
		{"a:b:c", "a:b", "x", "x:c", true},
		{"a:b", "a:b", "x:y", "x:y", true},
		{"A:B:c", "a:b", "x", "x:c", true},
		{"a:b:c", "a:b", "", ":c", true},
		{"a:bc", "a:b", "x", "", false},
	} {
		got, ok := Rebase(tc.name, tc.old, tc.new)
		if tc.new == "" && ok {
			got = strings.TrimPrefix(got, ":") // moving to the root: no stray separator
		}
		if ok != tc.ok || (ok && strings.TrimPrefix(got, ":") != strings.TrimPrefix(tc.want, ":")) {
			t.Errorf("Rebase(%q, %q, %q) = %q, %t; want %q, %t", tc.name, tc.old, tc.new, got, ok, tc.want, tc.ok)
		}
	}
	if got, ok := Rebase("x", "", "top"); !ok || got != "top:x" {
		t.Errorf("Rebase from root = %q, %t", got, ok)
	}
}

// memIndex is an in-memory Index: live names and aliases, folded.
type memIndex struct{ live, alias map[string]string }

func (m memIndex) Live(n string) (string, bool, error) { id, ok := m.live[Fold(n)]; return id, ok, nil }
func (m memIndex) Alias(n string) (string, bool, error) {
	id, ok := m.alias[Fold(n)]
	return id, ok, nil
}

func TestCheckAvailable(t *testing.T) {
	ix := memIndex{live: map[string]string{"app:foo": "1"}, alias: map[string]string{"app:old": "2"}}
	for _, tc := range []struct {
		name, self, code string
	}{
		{"app:new", "", ""},
		{"APP:FOO", "", CodeNameTaken},  // case-insensitive uniqueness
		{"app:foo", "1", ""},            // an object keeps its own name
		{"app:foo", "9", CodeNameTaken}, // another object cannot take it
		{"app:old", "", CodeNameAlias},  // an old name stays reserved
		{"App:Old", "3", CodeNameAlias},
		{"app:old", "2", ""}, // its owner may take it back
	} {
		err := CheckAvailable(ix, tc.name, tc.self)
		var ne *Error
		switch {
		case tc.code == "" && err != nil:
			t.Errorf("CheckAvailable(%q, %q) = %v", tc.name, tc.self, err)
		case tc.code != "" && (!errors.As(err, &ne) || ne.Code != tc.code):
			t.Errorf("CheckAvailable(%q, %q) = %v, want %s", tc.name, tc.self, err, tc.code)
		}
	}
}
