package rolesascode

import (
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/cedarx"
	"github.com/nischalravi/tessera/mvp/server/internal/roles"
)

// A rule written as Cedar reads back as the same rule, whatever its values hold.
func TestBirthrightCedarRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		rule roles.Rule
		abac string
	}{
		{"department only", roles.Rule{Department: []string{"Finance"}}, ""},
		{"all three", roles.Rule{Department: []string{"Finance", "R&D"}, Type: []string{"human", "service"}, Title: []string{"Analyst"}}, ""},
		{"awkward values", roles.Rule{Department: []string{`Quote " and \ slash`, "tab\there", "ünï", "line\nbreak"}}, ""},
		{"abac only", roles.Rule{}, "Cost centre 4410"},
		{"abac and list", roles.Rule{Title: []string{"Engineer"}}, `Policy "x"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := birthrightCedar("my-role", &tc.rule, tc.abac)
			ps, err := cedarx.ParsePolicies("x.cedar", []byte(src))
			if err != nil {
				t.Fatalf("the written policy does not parse: %v\n%s", err, src)
			}
			ids := ps.IDs()
			if len(ids) != 1 {
				t.Fatalf("ids = %v", ids)
			}
			if r, _ := ps.Annotation(ids[0], "role"); r != "my-role" {
				t.Errorf("@role = %q", r)
			}
			if a, ok := ps.Annotation(ids[0], "abac"); (a != tc.abac) || ok != (tc.abac != "") {
				t.Errorf("@abac = %q, %v; want %q", a, ok, tc.abac)
			}
			c, err := compileRule(ps, ids[0], "my-role")
			if err != nil {
				t.Fatalf("compile: %v\n%s", err, src)
			}
			got := c.Rule
			if !sameRule(got.Normalized(), tc.rule.Normalized()) {
				t.Errorf("read back %+v; wrote %+v", got, tc.rule)
			}
		})
	}
}

func TestCompileRuleRefusals(t *testing.T) {
	scope := `permit (principal is Tessera::Identity, action == Tessera::Action::"birthright", resource == Tessera::Role::"r")`
	cases := []struct{ name, src, want string }{
		{"wrong role", `permit (principal, action == Tessera::Action::"birthright", resource == Tessera::Role::"other") when { principal.status == "active" };`, "resource"},
		{"wrong action", `permit (principal, action == Tessera::Action::"jit_request", resource == Tessera::Role::"r") when { principal.status == "active" };`, "action"},
		{"unless", scope + ` when { principal.status == "active" } unless { principal.type == "service" };`, "exactly one when"},
		{"scoped principal", `permit (principal == Tessera::Identity::"x", action == Tessera::Action::"birthright", resource == Tessera::Role::"r") when { principal.status == "active" };`, "every identity"},
		{"negation", scope + ` when { principal.status == "active" && !(principal.type == "service") };`, "conjunction"},
		{"twice", scope + ` when { principal.status == "active" && principal.type == "human" && ["service"].contains(principal.type) };`, "twice"},
		{"inactive", scope + ` when { principal.status == "inactive" };`, "comparisons"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ps, err := cedarx.ParsePolicies("x.cedar", []byte(tc.src))
			if err != nil {
				t.Fatal(err)
			}
			_, err = compileRule(ps, ps.IDs()[0], "r")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v; want one mentioning %q", err, tc.want)
			}
		})
	}
}
