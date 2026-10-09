// Package reconcile runs dry-run reconciliation over a staged snapshot
// (design §6): tiered, deterministic correlation against the authoritative
// HR source, the RF-01 to RF-12 findings with impact and probable causes,
// and the read-only Snapshot that data checks evaluate.
//
// Correlation never links on self-asserted attributes: tier 1 is an exact HR
// id match, tier 2 an immutable cross-system link, and tier 3 (email or UPN)
// only proposes a match for review (K12).
package reconcile

import (
	"bytes"
	_ "embed"
	"fmt"
	"sync"

	"go.yaml.in/yaml/v3"
)

//go:embed rules.yaml
var rulesYAML []byte

// Rule is one finding rule.
type Rule struct {
	Title       string `yaml:"title"`
	Severity    string `yaml:"severity"`
	Privileged  string `yaml:"privileged,omitempty"`  // severity when privileged access is involved
	Recommended string `yaml:"recommended,omitempty"` // severity for recommended attributes (RF-04)
}

// Rules are the finding rules and default thresholds.
type Rules struct {
	Thresholds map[string]float64 `yaml:"thresholds"`
	Rules      map[string]Rule    `yaml:"rules"`
}

var (
	rulesOnce sync.Once
	rules     *Rules
	rulesErr  error
)

var severities = map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}

// LoadRules returns the embedded rules.
func LoadRules() (*Rules, error) {
	rulesOnce.Do(func() {
		dec := yaml.NewDecoder(bytes.NewReader(rulesYAML))
		dec.KnownFields(true)
		var r Rules
		if rulesErr = dec.Decode(&r); rulesErr != nil {
			return
		}
		for code, rule := range r.Rules {
			for _, s := range []string{rule.Severity, rule.Privileged, rule.Recommended} {
				if s != "" && !severities[s] {
					rulesErr = fmt.Errorf("reconcile: %s: unknown severity %q", code, s)
					return
				}
			}
		}
		rules = &r
	})
	return rules, rulesErr
}

// SeverityRank orders severities, critical first.
func SeverityRank(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	}
	return 4
}
