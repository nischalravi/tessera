package readiness

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

const credURL = "https://u:pwSECRET@h.example"

// A legacy row's attr_map and privileged_expected values that hold a credentialed URL are shown masked, in the view and
// in a change-request payload; clean values are left as they are (#962).
func TestMaskedConfig_AttrMapAndPrivileged(t *testing.T) {
	cfg := ConnConfig{
		AttrMap:            []AttrMapping{{LDAP: "mail", Target: "email", Scope: "account"}, {LDAP: credURL, Target: "x", Scope: "identity"}},
		PrivilegedExpected: map[string][]string{"admins": {"alice", credURL}, credURL: {"bob"}, "ops": {"carol"}},
	}
	m, masked := MaskedConfig(cfg)
	if !slices.Equal(masked, []string{"attr_map", "privileged_expected"}) {
		t.Fatalf("masked=%v", masked)
	}
	if m.AttrMap[0] != cfg.AttrMap[0] || m.AttrMap[1].LDAP == credURL || strings.Contains(m.AttrMap[1].LDAP, "SECRET") {
		t.Errorf("attr_map %v", m.AttrMap)
	}
	if cfg.AttrMap[1].LDAP != credURL || cfg.PrivilegedExpected[credURL] == nil {
		t.Error("the stored config was modified")
	}
	pe := m.PrivilegedExpected
	if _, ok := pe[credURL]; ok || !slices.Equal(pe["ops"], []string{"carol"}) || len(pe["admins"]) != 2 || pe["admins"][0] != "alice" ||
		strings.Contains(pe["admins"][1], "SECRET") || len(pe) != 3 {
		t.Errorf("privileged_expected %v", pe)
	}
	for _, v := range pe {
		for _, s := range v {
			if strings.Contains(s, "SECRET") {
				t.Errorf("leaks: %v", pe)
			}
		}
	}

	if _, masked := MaskedConfig(ConnConfig{AttrMap: cfg.AttrMap[:1], PrivilegedExpected: map[string][]string{"ops": {"carol"}}}); len(masked) != 0 {
		t.Errorf("clean values masked: %v", masked)
	}

	cm := map[string]any{
		"attr_map":            []any{map[string]any{"ldap": credURL, "target": "t", "scope": "account"}},
		"privileged_expected": map[string]any{credURL: []any{"a", credURL}},
	}
	got := MaskConfigMap(cm)
	if !slices.Equal(got, []string{"attr_map", "privileged_expected"}) || strings.Contains(strings.Join(flat(cm), " "), "SECRET") {
		t.Errorf("payload %v %v", got, cm)
	}
}

func flat(m map[string]any) []string {
	var out []string
	for k, v := range m {
		out = append(out, k)
		switch x := v.(type) {
		case []any:
			for _, e := range x {
				if em, ok := e.(map[string]any); ok {
					for _, f := range em {
						out = append(out, f.(string))
					}
				} else {
					out = append(out, e.(string))
				}
			}
		case map[string]any:
			for pk, pv := range x {
				out = append(out, pk)
				for _, e := range pv.([]any) {
					out = append(out, e.(string))
				}
			}
		}
	}
	return out
}

// Sending the masked view back unchanged keeps the stored attr_map and privileged_expected values; a changed value
// is not restored and a new credentialed one is refused (#962).
func TestKeepMasked_AttrMapAndPrivileged(t *testing.T) {
	cur := ConnConfig{
		AttrMap:            []AttrMapping{{LDAP: credURL, Target: "x", Scope: "account"}},
		PrivilegedExpected: map[string][]string{credURL: {"bob", credURL}},
	}
	view, _ := MaskedConfig(cur)
	next := view
	next.PrivilegedExpected = map[string][]string{}
	for k, v := range view.PrivilegedExpected {
		next.PrivilegedExpected[k] = slices.Clone(v)
	}
	next.AttrMap = slices.Clone(view.AttrMap)
	keepMaskedURLs(&cur, &next)
	if next.AttrMap[0] != cur.AttrMap[0] || !slices.Equal(next.PrivilegedExpected[credURL], cur.PrivilegedExpected[credURL]) || len(next.PrivilegedExpected) != 1 {
		t.Fatalf("not kept: %v %v", next.AttrMap, next.PrivilegedExpected)
	}
	if err := urlCredentialError(cur, next); err != nil {
		t.Errorf("a kept value was refused: %v", err)
	}

	// a replaced value stays replaced
	repl := ConnConfig{AttrMap: []AttrMapping{{LDAP: "mail", Target: "x", Scope: "account"}}, PrivilegedExpected: map[string][]string{"admins": {"bob", "dan"}}}
	keepMaskedURLs(&cur, &repl)
	if repl.AttrMap[0].LDAP != "mail" || !slices.Equal(repl.PrivilegedExpected["admins"], []string{"bob", "dan"}) {
		t.Errorf("replaced value changed: %v", repl)
	}
	// a new credentialed value is refused
	bad := ConnConfig{AttrMap: []AttrMapping{{LDAP: "https://a:b@c.example", Target: "x", Scope: "account"}}}
	if err := urlCredentialError(cur, bad); err == nil || strings.Contains(err.Error(), "c.example") {
		t.Errorf("got %v", err)
	}
}

// KeepMaskedLegacy restores a stored legacy value only where the incoming one is exactly its mask (#975).
func TestKeepMaskedLegacy(t *testing.T) {
	cur := json.RawMessage(`{"attr_map":[{"ldap":"` + credURL + `","target":"x","scope":"account"}],"privileged_expected":{"admins":["alice","` + credURL + `"]},"host":"h"}`)
	cases := []struct {
		name, next, want string
	}{
		{"masked", `{"attr_map":[{"ldap":"` + maskText(credURL) + `","target":"x","scope":"account"}],"privileged_expected":{"admins":["alice","` + maskText(credURL) + `"]},"host":"h"}`, "keep"},
		{"replaced", `{"attr_map":[{"ldap":"mail","target":"x","scope":"account"}],"host":"h"}`, "mail"},
		{"no legacy keys", `{"host":"h2"}`, `{"host":"h2"}`},
		{"not json", `[1]`, `[1]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := string(KeepMaskedLegacy(cur, json.RawMessage(tc.next)))
			switch tc.want {
			case "keep":
				if strings.Count(got, "pwSECRET") != 2 || strings.Contains(got, "masked") {
					t.Errorf("not kept: %s", got)
				}
			case "mail":
				if strings.Contains(got, "pwSECRET") || !strings.Contains(got, "mail") {
					t.Errorf("replaced value changed: %s", got)
				}
			default:
				if got != tc.want {
					t.Errorf("got %s", got)
				}
			}
		})
	}
}

// A bundle that names a stored privileged group and also its mask must not have the two merged (map order would pick
// which survives, and a real change could be planned as unchanged); a mask at another position or in another field
// does not pull a stored value across.
func TestKeepMaskedLegacy_NoCollisionOrMove(t *testing.T) {
	cur := json.RawMessage(`{"attr_map":[{"ldap":"mail","target":"x"},{"ldap":"` + credURL + `","target":"y"}],"privileged_expected":{"` + credURL + `":["alice"]}}`)
	next := json.RawMessage(`{"attr_map":[{"ldap":"` + maskText(credURL) + `","target":"x"},{"ldap":"cn","target":"` + maskText(credURL) + `"}],` +
		`"privileged_expected":{"` + credURL + `":["alice","bob"],"` + maskText(credURL) + `":["alice"]}}`)
	for range 50 {
		var got ConnConfig
		if err := json.Unmarshal(KeepMaskedLegacy(cur, next), &got); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got.PrivilegedExpected[credURL], []string{"alice", "bob"}) || len(got.PrivilegedExpected) != 2 {
			t.Fatalf("privileged_expected collided: %v", got.PrivilegedExpected)
		}
		if got.AttrMap[0].LDAP == credURL || got.AttrMap[1].Target == credURL {
			t.Fatalf("a stored value moved: %v", got.AttrMap)
		}
	}
}
