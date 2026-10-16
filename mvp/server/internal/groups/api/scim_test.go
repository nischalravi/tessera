package api

import (
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

var userAttrs = []string{"id", "username", "displayname", "emails.value", "active", "title"}

// resource is a fake user for the evaluator.
func resource(kv map[string][]string) func(string) []string {
	return func(a string) []string { return kv[a] }
}

func TestFilter_Evaluates(t *testing.T) {
	alice := resource(map[string][]string{"username": {"alice@x.example"}, "displayname": {"Alice"}, "active": {"true"},
		"emails.value": {"alice@x.example", "a2@y.example"}, "id": {"7"}})
	bare := resource(map[string][]string{"username": {"bot"}, "active": {"false"}})
	for _, tc := range []struct {
		filter      string
		alice, bare bool
	}{
		{`userName eq "ALICE@x.example"`, true, false}, // without case
		{`userName ne "alice@x.example"`, false, true},
		{`userName co "lice"`, true, false},
		{`userName sw "ali"`, true, false},
		{`userName ew ".example"`, true, false},
		{`userName gt "b"`, false, true},
		{`userName ge "bot"`, false, true},
		{`userName lt "b"`, true, false},
		{`userName le "alice@x.example"`, true, false},
		{`title pr`, false, false},
		{`displayName pr`, true, false},
		{`emails.value eq "a2@y.example"`, true, false}, // any value of a multi-valued attribute
		{`emails.value ne "a2@y.example"`, false, true}, // no value equals it; none at all is not equal either
		{`active eq true`, true, false},
		{`active eq false`, false, true},
		{`id eq 7`, true, false},
		{`active eq true and displayName pr`, true, false},
		{`active eq false or displayName pr`, true, true},
		// and binds tighter than or
		{`active eq false or displayName pr and userName sw "x"`, false, true},
		{`(active eq false or displayName pr) and userName sw "x"`, false, false},
		{`not (active eq true)`, false, true},
		{`not (active eq true or active eq false)`, false, false},
		{`NOT (ACTIVE EQ TRUE) OR USERNAME CO "lic"`, true, true},
		{`  displayName   eq   "Alice"  `, true, false},
		{`displayName eq "Al\"ice"`, false, false}, // escapes are decoded
		{`displayName eq "Alice" and (userName sw "a" and (id eq 7))`, true, false},
	} {
		f, err := ParseFilter(tc.filter, userAttrs)
		if err != nil {
			t.Errorf("%s: %v", tc.filter, err)
			continue
		}
		if got := f.Eval(alice); got != tc.alice {
			t.Errorf("%s on alice = %v, want %v", tc.filter, got, tc.alice)
		}
		if got := f.Eval(bare); got != tc.bare {
			t.Errorf("%s on a user without a display name = %v, want %v", tc.filter, got, tc.bare)
		}
	}
	// no filter matches everything
	if f, err := ParseFilter("  ", userAttrs); err != nil || f != nil || !f.Eval(alice) {
		t.Errorf("empty filter = %v, %v", f, err)
	}
}

func TestFilter_Refuses(t *testing.T) {
	for name, s := range map[string]string{
		"unknown attribute": `nickName eq "x"`,
		"no operator":       `userName`,
		"no value":          `userName eq`,
		"bad operator":      `userName like "x"`,
		"unquoted text":     `userName eq alice`,
		"unterminated":      `userName eq "alice`,
		"bad escape":        `userName eq "al\qice"`,
		"open paren":        `(userName eq "x"`,
		"extra paren":       `userName eq "x")`,
		"two comparisons":   `userName eq "x" userName eq "y"`,
		"trailing and":      `userName eq "x" and`,
		"leading or":        `or userName eq "x"`,
		"not without paren": `not userName eq "x"`,
		"empty parens":      `()`,
		"too long":          strings.Repeat("a", MaxFilterLen+1),
		"too deep":          strings.Repeat("(", 40) + `userName eq "x"` + strings.Repeat(")", 40),
		"value path":        `emails[value eq "x"]`,
		"bad utf8":          "userName eq \"\xff\"",
		"value after pr":    `userName pr "x"`,
	} {
		_, err := ParseFilter(s, userAttrs)
		if _, ok := IsFilterError(err); !ok {
			t.Errorf("%s: %q gave %v, want an ErrFilter", name, s, err)
		}
	}
}

func TestFilter_Single(t *testing.T) {
	f, _ := ParseFilter(`displayName eq "App:Team"`, []string{"displayname"})
	if a, op, v, ok := f.Single(); !ok || a != "displayname" || op != "eq" || v != "app:team" {
		t.Errorf("single = %q %q %q %v", a, op, v, ok)
	}
	for _, s := range []string{`displayName eq "a" and displayName eq "b"`, `not (displayName eq "a")`, `(displayName eq "a" or displayName eq "b")`} {
		f, _ := ParseFilter(s, []string{"displayname"})
		if _, _, _, ok := f.Single(); ok {
			t.Errorf("%s is not a single comparison", s)
		}
	}
	var none *Filter
	if _, _, _, ok := none.Single(); ok {
		t.Error("a nil filter has no comparison")
	}
}

func TestSelect(t *testing.T) {
	u := NewUser(&store.Identity{ID: 7, ExternalID: "alice", Name: "Alice", Type: "human", Status: "active"}, "https://t.example")
	for _, tc := range []struct {
		attributes, excluded string
		want                 []string
		not                  []string
	}{
		{"", "", []string{"userName", "displayName", "active", "meta"}, nil},
		{"userName", "", []string{"id", "schemas", "meta", "userName"}, []string{"displayName", "active"}},
		{" USERNAME , active ", "", []string{"userName", "active", "id"}, []string{"displayName"}},
		{"", "displayName,id,meta", []string{"userName", "id", "meta", "schemas"}, []string{"displayName"}}, // id, schemas and meta stay
		{"userName", "userName", []string{"userName"}, []string{"displayName"}},                             // attributes wins
	} {
		got, err := Select(u, tc.attributes, tc.excluded)
		if err != nil {
			t.Fatal(err)
		}
		if tc.attributes == "" && tc.excluded == "" {
			if _, ok := got.(User); !ok {
				t.Errorf("no selection should return the resource itself, got %T", got)
			}
			continue
		}
		m := got.(map[string]any)
		for _, k := range tc.want {
			if _, ok := m[k]; !ok {
				t.Errorf("attributes=%q excluded=%q lost %s: %v", tc.attributes, tc.excluded, k, m)
			}
		}
		for _, k := range tc.not {
			if _, ok := m[k]; ok {
				t.Errorf("attributes=%q excluded=%q kept %s", tc.attributes, tc.excluded, k)
			}
		}
	}
	if u.Meta.Location != "https://t.example/scim/v2/Users/7" {
		t.Errorf("location = %s", u.Meta.Location)
	}
}

func TestResources_ShapeAndNeverNull(t *testing.T) {
	g := &store.NativeGroup{ID: "g1", Name: "app:team", Kind: store.KindGroup, Definition: store.DefinitionBasic, Status: store.GroupActive}
	gr := NewGroup(g, nil, 0, "")
	if gr.Members == nil || gr.Ext.MembersTruncated || gr.DisplayName != "app:team" || gr.Meta.Location != "/scim/v2/Groups/g1" {
		t.Errorf("group = %+v", gr)
	}
	if gr := NewGroup(g, []Ref{MemberRef(1, "A", "")}, 5, ""); !gr.Ext.MembersTruncated || gr.Ext.MemberCount != 5 {
		t.Errorf("truncated group = %+v", gr.Ext)
	}
	if l := NewList(0, 1, nil); l.Resources == nil || l.ItemsPerPage != 0 || l.Schemas[0] != SchemaListResponse {
		t.Errorf("list = %+v", l)
	}
	if e := NewError(404, "", "no"); e.Status != "404" || e.Schemas[0] != SchemaError {
		t.Errorf("error = %+v", e)
	}
	email := "a@x.example"
	if u := NewUser(&store.Identity{ID: 1, ExternalID: "x", Name: "N", Email: &email, Status: "terminated"}, ""); u.UserName != email || u.Active ||
		len(u.Emails) != 1 {
		t.Errorf("user = %+v", u)
	}
	if u := NewUser(&store.Identity{ID: 1, ExternalID: "x", Name: "N", Status: "active"}, ""); u.UserName != "x" || len(u.Emails) != 0 {
		t.Errorf("user without email = %+v", u)
	}
}
