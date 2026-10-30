package agentscopeascode_test

import (
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/agentscope"
	"github.com/nischalravi/tessera/mvp/server/internal/agentscopeascode"
	"github.com/nischalravi/tessera/mvp/server/internal/policybundle"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Proposed is the set of active scopes after the bundle is applied: written scopes replace stored ones, a full-mode
// bundle drops the scopes it no longer lists, and the result is never nil and is sorted by key.
func TestProposed(t *testing.T) {
	w := newWorld(t)
	linked := "  source: entra\n  external_id: linked\n"
	proposed := func(files policybundle.Files) []*agentscope.Doc {
		var out []*agentscope.Doc
		w.tx(func(c *store.TenantTx) (err error) {
			out, err = agentscopeascode.Proposed(c, files, w.opt)
			return err
		})
		return out
	}
	keys := func(ds []*agentscope.Doc) string {
		var ks []string
		for _, d := range ds {
			ks = append(ks, d.Key)
		}
		return strings.Join(ks, ",")
	}
	// nothing stored yet
	if got := keys(proposed(w.baseline())); got != "hb" {
		t.Fatalf("before the apply: %q", got)
	}
	if n := len(w.export()); n != 1 { // tessera.yaml only: nothing was written
		t.Fatalf("Proposed wrote: export has %d files", n)
	}
	w.applyPlanned(bundle(w.f.B.Slug, "partial", map[string]string{"hb": scope("hb", hb, "[read]", ""), "linked": scope("linked", linked, "[read]", "")}))

	// partial: an update replaces the stored scope, the other stays
	got := proposed(bundle(w.f.B.Slug, "partial", map[string]string{"hb": scope("hb", hb, "[write]", "")}))
	if keys(got) != "hb,linked" || got[0].Allow.Actions[0] != "write" || got[1].Allow.Actions[0] != "read" {
		t.Errorf("partial: %q %+v", keys(got), got)
	}
	// full: the scope the bundle no longer lists drops out
	if got := keys(proposed(bundle(w.f.B.Slug, "full", map[string]string{"hb": scope("hb", hb, "[read]", "")}))); got != "hb" {
		t.Errorf("full: %q", got)
	}
	// full with none: an empty set that is not nil, because an empty set is a change
	if got := proposed(bundle(w.f.B.Slug, "full", nil)); got == nil || len(got) != 0 {
		t.Errorf("all retired: %v", got)
	}
}
