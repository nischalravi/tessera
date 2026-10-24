package scim

import (
	"strings"
	"testing"
)

func TestPresets_TableIsValid(t *testing.T) {
	if err := ValidatePresets(Presets); err != nil {
		t.Fatal(err)
	}
	want := []string{"slack", "zoom", "box", "dropbox", "zendesk", "databricks", "atlassian", "pingone", "onelogin", "jumpcloud", "keycloak", "auth0"}
	if len(Presets) != len(want) {
		t.Fatalf("%d presets, want %d", len(Presets), len(want))
	}
	for _, id := range want {
		if _, ok := PresetByID(id); !ok {
			t.Errorf("missing preset %s", id)
		}
	}
}

func TestPresets_ValidateRejects(t *testing.T) {
	good := Presets[0]
	mut := func(f func(p *Preset)) []Preset {
		p := good
		f(&p)
		return []Preset{p}
	}
	tests := []struct {
		name string
		in   []Preset
		want string
	}{
		{"duplicate", []Preset{good, good}, "duplicate"},
		{"bad id", mut(func(p *Preset) { p.ID = "Bad ID" }), "bad id"},
		{"bad category", mut(func(p *Preset) { p.Category = "Other" }), "category"},
		{"bad auth", mut(func(p *Preset) { p.Auth = "basic" }), "auth"},
		{"http source", mut(func(p *Preset) { p.Source = "http://x" }), "source"},
		{"no hint", mut(func(p *Preset) { p.Hint = "" }), "hint"},
		{"bad quirk", mut(func(p *Preset) { p.Quirks.OpCase = "shouting" }), "op_case"},
		{"bad tri", mut(func(p *Preset) { p.Quirks.BoolAsString = "maybe" }), "tri"},
		{"pattern not matching example", mut(func(p *Preset) { p.BaseURLExample = "https://example.com/x" }), "does not match"},
		{"unanchored pattern", mut(func(p *Preset) { p.BaseURLPattern = `https://api\.slack\.com/scim/v2` }), "anchored"},
		{"no username mapping", mut(func(p *Preset) { p.Mapping = Mapping{} }), "username"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePresets(tc.in)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestPresets_UnverifiedFactsAreUnknown(t *testing.T) {
	// A preset with no URL pattern must not claim any confirmed quirk, and the
	// only confirmed quirk anywhere is Slack's documented lower-case operations.
	for _, p := range Presets {
		if p.BaseURLPattern == "" && p.BaseURLExample != "" {
			t.Errorf("%s: example without a verified pattern", p.ID)
		}
		if p.ID != "slack" && p.Quirks != UnknownQuirks() {
			t.Errorf("%s: quirks %+v are not unknown; cite the documentation and update this test", p.ID, p.Quirks)
		}
	}
}

func TestPreset_ValidateBaseURL(t *testing.T) {
	tests := []struct {
		preset, url string
		ok          bool
	}{
		{"slack", "https://api.slack.com/scim/v2", true},
		{"slack", "https://api.slack.com/scim/v2/", true},
		{"slack", "https://api.slack.com/scim/v1", false},
		{"slack", "http://api.slack.com/scim/v2", false},
		{"slack", "https://evil.example/scim/v2", false},
		{"slack", "https://u:p@api.slack.com/scim/v2", false},
		{"slack", "https://api.slack.com/scim/v2?x=1", false},
		{"atlassian", "https://api.atlassian.com/scim/directory/2fb21891-7bee-4c2d-a61a-ade3834c8b2b", true},
		{"atlassian", "https://api.atlassian.com/scim/directory/", false},
		{"auth0", "https://acme.us.auth0.com/scim/v2/connections/con_AbC123/", true},
		{"auth0", "https://acme.us.auth0.com/scim/v2", false},
		{"zoom", "https://anything.example/scim", true}, // unverified: generic https check only
		{"zoom", "ftp://anything.example/scim", false},
	}
	for _, tc := range tests {
		p, _ := PresetByID(tc.preset)
		if err := p.ValidateBaseURL(tc.url); (err == nil) != tc.ok {
			t.Errorf("%s %s: err = %v, want ok %v", tc.preset, tc.url, err, tc.ok)
		}
	}
}

func TestStandardMapping(t *testing.T) {
	m := StandardMapping()
	for k, v := range map[string]string{"username": "userName", "email": `emails[type eq "work"].value`, "active": "active"} {
		if m[k] != v {
			t.Errorf("%s -> %q, want %q", k, m[k], v)
		}
	}
	for _, p := range Presets {
		for k, v := range p.Mapping {
			if !attrRE.MatchString(v) {
				t.Errorf("%s: mapping %s -> %q is not a valid attribute path", p.ID, k, v)
			}
		}
	}
}

func TestApplyOps(t *testing.T) {
	doc := map[string]any{"id": "g", "members": []any{map[string]any{"value": "a"}, map[string]any{"value": "b"}}}
	ops := []map[string]any{
		{"op": "Add", "path": "members", "value": []member{{Value: "c"}, {Value: "a"}}},
		{"op": "remove", "path": `members[value eq "b"]`},
		{"op": "replace", "path": "name.givenName", "value": "Ann"},
		{"op": "replace", "path": "active", "value": "False"},
	}
	if err := applyOps(doc, ops); err != nil {
		t.Fatal(err)
	}
	got := memberValues(doc["members"])
	if strings.Join(got, ",") != "a,c" {
		t.Fatalf("members = %v", got)
	}
	if doc["name"].(map[string]any)["givenName"] != "Ann" || doc["active"] != "False" {
		t.Fatalf("doc = %v", doc)
	}
	if err := applyOps(doc, []map[string]any{{"op": "move", "path": "x"}}); err == nil {
		t.Fatal("unsupported op accepted")
	}
}
