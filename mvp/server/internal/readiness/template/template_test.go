package template

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/nischalravi/tessera/mvp/server/internal/readiness/templates"
)

var update = flag.Bool("update", false, "rewrite testdata/counts.golden")

func TestTemplates_Lint(t *testing.T) {
	probs, err := LintFS(templates.FS)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range probs {
		t.Error(p)
	}
	reg, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(reg.IDs(), ","); got != "ad,entra,google,ldap,okta,scim_app,workday" {
		t.Errorf("templates = %s", got)
	}
	for _, id := range reg.IDs() {
		r, _ := reg.Get(id)
		seen := map[string]bool{}
		for _, it := range r.Items {
			if seen[it.ID] {
				t.Errorf("%s: duplicate %s after resolve", id, it.ID)
			}
			seen[it.ID] = true
			if it.Remediation.Hint == "" || it.Why == "" || len(it.Verify) == 0 {
				t.Errorf("%s: %s is missing why, verification or remediation", id, it.ID)
			}
		}
	}
}

// lintYAML parses base plus one extra template and lints them.
func lintYAML(t *testing.T, extra string) []Problem {
	t.Helper()
	baseData, err := templates.FS.ReadFile("base.yaml")
	if err != nil {
		t.Fatal(err)
	}
	probs, err := LintFS(fstest.MapFS{
		"base.yaml": {Data: baseData},
		"ad.yaml":   {Data: []byte(extra)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return probs
}

const header = `template: ad
version: 1.0.0
extends: base@1
display_name: AD
connector_types: [ad]
default_correlation_key: objectGUID
required_attributes: { user: [objectGUID] }
items:
`

func item(id, extra string) string {
	return fmt.Sprintf(`  - id: %s
    title: T
    category: scope
    level: required
    why: W
    verify: [{ kind: attestation }]
    remediation: { hint: H }
%s`, id, extra)
}

func TestLint_RejectsBadTemplates(t *testing.T) {
	cases := []struct{ name, yaml, want string }{
		{"ok", header + item("ad.a", ""), ""},
		{"duplicate id", header + item("ad.a", "") + item("ad.a", ""), "duplicate item id"},
		{"duplicates base", header + item("base.owner", ""), "duplicate item id"},
		{"unknown check", header + strings.Replace(item("ad.a", ""), "{ kind: attestation }", "{ kind: live, check: rm_rf }", 1), `unknown check "rm_rf"`},
		{"check for another template", header + strings.Replace(item("ad.a", ""), "{ kind: attestation }", "{ kind: live, check: token_scopes }", 1), "not available for template ad"},
		{"kind mismatch", header + strings.Replace(item("ad.a", ""), "{ kind: attestation }", "{ kind: data, check: tls_chain }", 1), "is a live check"},
		{"cycle", header + item("ad.a", "    depends_on: [ad.b]\n") + item("ad.b", "    depends_on: [ad.a]\n"), "dependency cycle"},
		{"unknown dependency", header + item("ad.a", "    depends_on: [ad.nope]\n"), "unknown item"},
		{"no remediation", header + strings.Replace(item("ad.a", ""), "remediation: { hint: H }", "remediation: { hint: '' }", 1), "remediation hint is empty"},
		{"no verification", header + strings.Replace(item("ad.a", ""), "verify: [{ kind: attestation }]", "verify: []", 1), "no verification"},
		{"bad level", header + strings.Replace(item("ad.a", ""), "level: required", "level: mandatory", 1), "level"},
		{"bad category", header + strings.Replace(item("ad.a", ""), "category: scope", "category: vibes", 1), "category"},
		{"narrower dependency", header + item("ad.a", "    applies_when: { write_mode: [scoped] }\n") + item("ad.b", "    depends_on: [ad.a]\n"), "not applicable in every configuration"},
		{"bad config field", header + item("ad.a", "    config_fields: [password]\n"), `unknown config field "password"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			probs := lintYAML(t, tc.yaml)
			var msgs []string
			for _, p := range probs {
				msgs = append(msgs, p.String())
			}
			all := strings.Join(msgs, "\n")
			if tc.want == "" {
				if len(probs) > 0 {
					t.Fatalf("unexpected problems:\n%s", all)
				}
				return
			}
			if !strings.Contains(all, tc.want) {
				t.Fatalf("want a problem containing %q, got:\n%s", tc.want, all)
			}
		})
	}
}

func TestTemplates_Counts(t *testing.T) {
	reg := MustDefault()
	var b strings.Builder
	b.WriteString("# Item counts per template (design §3.14). Columns: template items, with base,\n")
	b.WriteString("# required, recommended, optional (the last three include the base items).\n")
	b.WriteString("# Regenerate with: go test ./internal/readiness/template -run TestTemplates_Counts -update\n")
	base := len(reg.base.Items)
	var req, rec, opt int
	for _, it := range reg.base.Items {
		switch it.Level {
		case Required:
			req++
		case Recommended:
			rec++
		case Optional:
			opt++
		}
	}
	fmt.Fprintf(&b, "%-9s %2d %2d %2d %2d %d\n", "base", base, base, req, rec, opt)
	for _, id := range reg.IDs() {
		r, _ := reg.Get(id)
		c := r.Count()
		fmt.Fprintf(&b, "%-9s %2d %2d %2d %2d %d\n", id, c.Items-base, c.Items, c.Required, c.Recommended, c.Optional)
	}
	const golden = "testdata/counts.golden"
	if *update {
		if err := os.WriteFile(golden, []byte(b.String()), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if b.String() != string(want) {
		t.Errorf("counts differ from %s (design §3.14):\n--- got\n%s--- want\n%s", golden, b.String(), want)
	}
}

func TestOverlay_NoDowngrade(t *testing.T) {
	reg := MustDefault()
	ad, _ := reg.Get("ad")
	custom := func(id string, lvl Level, v Verify) Item {
		return Item{ID: id, Title: "Change ticket linked", Category: "ownership", Level: lvl, Why: "Our auditors ask for it.",
			Verify: []Verify{v}, Remediation: Remediation{Hint: "Link the change ticket."}}
	}
	cases := []struct {
		name string
		o    Overlay
		code string // "" means accepted
	}{
		{"raise optional to required", Overlay{RaiseLevels: map[string]Level{"ad.svc.no_interactive": Required}}, ""},
		{"raise recommended to required", Overlay{RaiseLevels: map[string]Level{"ad.tls.signing_cb": Required}}, ""},
		{"same level is a no-op", Overlay{RaiseLevels: map[string]Level{"ad.bind": Required}}, ""},
		{"lower required to recommended", Overlay{RaiseLevels: map[string]Level{"ad.bind": Recommended}}, CodeDowngrade},
		{"lower recommended to optional", Overlay{RaiseLevels: map[string]Level{"ad.tls.signing_cb": Optional}}, CodeDowngrade},
		{"remove an item", Overlay{RemoveItems: []string{"ad.groups.range"}}, CodeDowngrade},
		{"disable an item", Overlay{DisableItems: []string{"base.owner"}}, CodeDowngrade},
		{"redefine a template item", Overlay{AddItems: []Item{custom("ad.bind", Optional, Verify{Kind: Attestation})}}, CodeDowngrade},
		{"tighten fill rate", Overlay{Thresholds: map[string]float64{"fill_rate.required": 0.99}}, ""},
		{"loosen fill rate", Overlay{Thresholds: map[string]float64{"fill_rate.required": 0.5}}, CodeDowngrade},
		{"tighten stale days", Overlay{Thresholds: map[string]float64{"stale_days": 60}}, ""},
		{"loosen stale days", Overlay{Thresholds: map[string]float64{"stale_days": 365}}, CodeDowngrade},
		{"add attested item", Overlay{AddItems: []Item{custom("custom.change_ticket", Required, Verify{Kind: Attestation})}}, ""},
		{"add data item", Overlay{AddItems: []Item{custom("custom.fill", Recommended, Verify{Kind: Data, Check: "fill_rate", Params: map[string]any{"attr": "department", "min": 0.9}})}}, ""},
		{"add live item", Overlay{AddItems: []Item{custom("custom.live", Required, Verify{Kind: Live, Check: "bind"})}}, CodeInvalidOverlay},
		{"custom id prefix", Overlay{AddItems: []Item{custom("ad.mine", Required, Verify{Kind: Attestation})}}, CodeInvalidOverlay},
		{"unknown item", Overlay{RaiseLevels: map[string]Level{"ad.nope": Required}}, CodeInvalidOverlay},
		{"unknown threshold", Overlay{Thresholds: map[string]float64{"fun": 1}}, CodeInvalidOverlay},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := Apply(ad, &tc.o)
			if tc.code == "" {
				if err != nil {
					t.Fatalf("rejected: %v", err)
				}
				for id, lvl := range tc.o.RaiseLevels {
					if it, _ := out.Item(id); it.Level != lvl || it.TemplateLevel.Rank() > lvl.Rank() {
						t.Errorf("%s level = %s (template %s)", id, it.Level, it.TemplateLevel)
					}
				}
				return
			}
			var oe *OverlayError
			if !errors.As(err, &oe) || oe.Code != tc.code {
				t.Fatalf("want %s, got %v", tc.code, err)
			}
		})
	}
	// Apply never mutates the input.
	if it, _ := ad.Item("ad.svc.no_interactive"); it.Level != Optional {
		t.Errorf("input mutated: %s", it.Level)
	}
}

func TestAppliesWhen_ClosedVocabulary(t *testing.T) {
	cases := []struct{ name, aw, want string }{
		{"known keys", "{ write_mode: [scoped], role: [account_source], tenant_has_connection_type: [entra], config_flag: hybrid }", ""},
		{"expression key", `{ expr: "config.host != ''" }`, "field expr not found"},
		{"unknown key", "{ when_tuesday: true }", "field when_tuesday not found"},
		{"bad write mode", "{ write_mode: [yolo] }", `write_mode "yolo"`},
		{"bad role", "{ role: [admin] }", `role "admin"`},
		{"bad connection type", "{ tenant_has_connection_type: [mainframe] }", `"mainframe" is not a template id`},
		{"bad flag", "{ config_flag: anything }", `config_flag "anything"`},
		{"empty", "{}", "applies_when is empty"},
	}
	baseData, _ := templates.FS.ReadFile("base.yaml")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			y := header + item("ad.a", "    applies_when: "+tc.aw+"\n")
			probs, err := LintFS(fstest.MapFS{"base.yaml": {Data: baseData}, "ad.yaml": {Data: []byte(y)}})
			msg := ""
			if err != nil {
				msg = err.Error()
			}
			for _, p := range probs {
				msg += "\n" + p.String()
			}
			if tc.want == "" {
				if msg != "" {
					t.Fatalf("unexpected: %s", msg)
				}
				return
			}
			if !strings.Contains(msg, tc.want) {
				t.Fatalf("want %q in %q", tc.want, msg)
			}
		})
	}
	// Unknown keys anywhere in an item are rejected too.
	if _, err := Parse("x.yaml", []byte(header+item("ad.a", "    script: rm -rf /\n"))); err == nil {
		t.Error("unknown item key accepted")
	}
}

func TestVersionPinning(t *testing.T) {
	reg := MustDefault()
	ad, _ := reg.Get("ad")
	if ad.Pin() != "ad@1.0" {
		t.Fatalf("pin = %s", ad.Pin())
	}
	cases := []struct {
		pin string
		ok  bool
	}{
		{"ad@1.0", true},
		{"ad@1.1", false},   // a minor release this build does not have
		{"ad@2.0", false},   // a major release requires a new revision
		{"ad@1", false},     // malformed
		{"ad@1.0.0", false}, // patch is not pinned
		{"nope@1.0", false},
		{"ad", false},
	}
	for _, tc := range cases {
		r, err := reg.Resolve(tc.pin)
		if tc.ok != (err == nil) {
			t.Errorf("Resolve(%q) err = %v", tc.pin, err)
		}
		if tc.ok && r.ID != "ad" {
			t.Errorf("Resolve(%q) = %s", tc.pin, r.ID)
		}
	}
	// A patch release applies automatically to an existing pin.
	baseData, _ := templates.FS.ReadFile("base.yaml")
	adData, _ := templates.FS.ReadFile("ad.yaml")
	patched := strings.Replace(string(adData), "version: 1.0.0", "version: 1.0.7", 1)
	reg2, err := Load(fstest.MapFS{"base.yaml": {Data: baseData}, "ad.yaml": {Data: []byte(patched)}})
	if err != nil {
		t.Fatal(err)
	}
	if r, err := reg2.Resolve("ad@1.0"); err != nil || r.Version != "1.0.7" {
		t.Errorf("patch release not applied: %v %v", r, err)
	}
	minor := strings.Replace(string(adData), "version: 1.0.0", "version: 1.1.0", 1)
	reg3, err := Load(fstest.MapFS{"base.yaml": {Data: baseData}, "ad.yaml": {Data: []byte(minor)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg3.Resolve("ad@1.0"); !errors.Is(err, ErrVersionUnavailable) {
		t.Errorf("minor release substituted silently: %v", err)
	}
}

func TestForConnectorType(t *testing.T) {
	reg := MustDefault()
	for ct, want := range map[string]string{"demo-ad": "ad", "ad": "ad", "demo-okta": "okta", "demo-workday": "workday", "scim_app": "scim_app"} {
		r, ok := reg.ForConnectorType(ct)
		if !ok || r.ID != want {
			t.Errorf("%s -> %v", ct, r)
		}
	}
	if _, ok := reg.ForConnectorType("demo-aws"); ok {
		t.Error("demo-aws has no template yet")
	}
	wd, _ := reg.Get("workday")
	if wd.Role != "authoritative" {
		t.Errorf("workday role = %s", wd.Role)
	}
}
