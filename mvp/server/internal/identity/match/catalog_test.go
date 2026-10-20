package match

import "testing"

// TestCatalogNamesEveryRule keeps the admin page's list in step with the engine: every Rule constant is described
// once, with the tier it fires at.
func TestCatalogNamesEveryRule(t *testing.T) {
	want := map[string]Tier{RuleSignedIn: TierA, RuleSourceLinked: TierA, RuleAuthIdent: TierA, RuleFederated: TierA,
		RuleEmailDOBName: TierB, RuleNameDOB: TierC, RuleEmailOnly: TierC, RulePhoneOnly: TierC}
	got := map[string]Tier{}
	for _, r := range Catalog() {
		if _, dup := got[r.Name]; dup || r.Description == "" {
			t.Errorf("rule %q listed twice or without a description", r.Name)
		}
		got[r.Name] = r.Tier
	}
	if len(got) != len(want) {
		t.Fatalf("catalog has %d rules, the engine %d", len(got), len(want))
	}
	for n, tier := range want {
		if got[n] != tier {
			t.Errorf("rule %q: catalog tier %q, engine %q", n, got[n], tier)
		}
	}
}
