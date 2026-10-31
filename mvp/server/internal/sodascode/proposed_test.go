package sodascode_test

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/policybundle"
	"github.com/nischalravi/tessera/mvp/server/internal/sod"
	"github.com/nischalravi/tessera/mvp/server/internal/sodascode"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Proposed is the risks checked after the bundle: a listed risk replaces the one of its key, a retired ruleset's risks
// drop out, and in full mode a listed ruleset's unlisted risks do too. It writes nothing.
func TestProposed(t *testing.T) {
	w := newWorld(t)
	keys := func(rs []*sod.Risk) string {
		var ks []string
		for _, r := range rs {
			ks = append(ks, r.Key)
		}
		sort.Strings(ks)
		return strings.Join(ks, ",")
	}
	var current []*sod.Risk
	proposed := func(files policybundle.Files) []*sod.Risk {
		var out []*sod.Risk
		w.tx(func(c *store.TenantTx) (err error) {
			if current, err = sod.Compile(c); err != nil {
				return err
			}
			out, err = sodascode.Proposed(c, files, w.opt, current)
			return err
		})
		return out
	}
	// nothing applied yet: the bundle's risk is the only one, and nothing was stored
	if got := keys(proposed(w.baseline())); got != "pay-create-approve" || len(current) != 0 {
		t.Fatalf("before the apply: proposed %q, current %d", got, len(current))
	}
	w.applyPlanned(w.baseline())
	other := `  - key: pay-other
    name: Another pairing
    priority: medium
    functions: [create, approve]
`
	// partial: the stored risk stays and the new one is added
	if got := keys(proposed(bundle(w.f.B.Slug, "partial", map[string]string{"payments": ruleset("payments", other)}))); got != "pay-create-approve,pay-other" {
		t.Errorf("partial: %q", got)
	}
	// full: the ruleset is the bundle's, so the stored risk it no longer lists drops out
	if got := keys(proposed(bundle(w.f.B.Slug, "full", map[string]string{"payments": ruleset("payments", other)}))); got != "pay-other" {
		t.Errorf("full: %q", got)
	}
	// full with no ruleset at all: the ruleset is retired, an empty set (not nil: an empty set is a change)
	if got := proposed(bundle(w.f.B.Slug, "full", nil)); got == nil || len(got) != 0 {
		t.Errorf("retired: %v", got)
	}
	// a changed risk of the same key replaces the stored one
	changed := strings.Replace(payRisk, "priority: high", "priority: low", 1)
	rs := proposed(bundle(w.f.B.Slug, "partial", map[string]string{"payments": ruleset("payments", changed)}))
	if len(rs) != 1 || rs[0].Priority != "low" {
		t.Errorf("replaced: %+v", rs)
	}
	now := compiled(t, w.f.DB, w.f.B.ID, func(fn func(c *store.TenantTx) error) error {
		return w.f.DB.ReadTenant(context.Background(), w.f.B.ID, fn)
	})
	if !strings.Contains(now, `"priority":"high"`) {
		t.Errorf("Proposed changed the stored risk: %s", now)
	}
}

// A tenant with no stored ruleset is checked against its legacy YAML SoD risks; the first ruleset an apply writes replaces
// them, so the proposed set holds the bundle's risks only. A bundle that writes no ruleset leaves them (issue #657).
func TestProposed_FirstRulesetReplacesLegacyRisks(t *testing.T) {
	w := newWorld(t)
	legacy := []*sod.Risk{{ID: "legacy", Key: "legacy-risk", Ruleset: sod.RulesetRef{Key: "legacy"}}}
	var withBundle, without []*sod.Risk
	w.tx(func(c *store.TenantTx) (err error) {
		if withBundle, err = sodascode.Proposed(c, w.baseline(), w.opt, legacy); err != nil {
			return err
		}
		without, err = sodascode.Proposed(c, bundle(w.f.B.Slug, "partial", nil), w.opt, legacy)
		return err
	})
	if len(withBundle) != 1 || withBundle[0].Key != "pay-create-approve" {
		t.Errorf("with a ruleset in the bundle: %+v", withBundle)
	}
	if len(without) != 1 || without[0].Key != "legacy-risk" {
		t.Errorf("with no ruleset in the bundle: %+v", without)
	}
}
