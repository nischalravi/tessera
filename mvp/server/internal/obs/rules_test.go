package obs

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// The shipped Prometheus rules parse and refer only to metrics that exist
// (promtool is not required to run the test suite).
func TestPrometheusRules_ReferenceRealMetrics(t *testing.T) {
	raw, err := os.ReadFile("../../../../deploy/prometheus/tessera-rules.yml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Groups []struct {
			Name  string `yaml:"name"`
			Rules []struct {
				Record string `yaml:"record"`
				Alert  string `yaml:"alert"`
				Expr   string `yaml:"expr"`
			} `yaml:"rules"`
		} `yaml:"groups"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, d := range Default.Descriptors() {
		known[d.Name] = true
	}
	re := regexp.MustCompile(`tessera_[a-z0-9_]+`)
	rules := 0
	for _, g := range doc.Groups {
		for _, r := range g.Rules {
			rules++
			if (r.Record == "") == (r.Alert == "") || strings.TrimSpace(r.Expr) == "" {
				t.Errorf("%s: rule needs exactly one of record/alert and an expr: %+v", g.Name, r)
			}
			for _, m := range re.FindAllString(r.Expr, -1) {
				base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(m, "_bucket"), "_count"), "_sum")
				if !known[m] && !known[base] {
					t.Errorf("%s %s%s uses unknown metric %s", g.Name, r.Alert, r.Record, m)
				}
			}
		}
	}
	if rules < 40 {
		t.Errorf("only %d rules parsed", rules)
	}
}
