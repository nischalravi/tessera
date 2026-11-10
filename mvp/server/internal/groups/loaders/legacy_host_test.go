package loaders_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/loaders"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// A loader stored before the ASCII-host rule (#944) can still be paused or renamed while its URL is unchanged; a changed
// URL, or enabling it, gets the full check (#953).
func TestUpdate_LegacyNonASCIIHost(t *testing.T) {
	const legacy = "https://fïles.example.org/y.csv"
	const other = "https://göod.example.org/y.csv"
	csv := func(u string) []byte {
		return []byte(fmt.Sprintf(`{"url":%q,"group":"g","subject_column":"id"}`, u))
	}
	cases := []struct {
		name     string
		disabled bool
		edit     func(s *loaders.Spec)
		refused  bool
	}{
		{"pause", false, func(s *loaders.Spec) { s.Status = store.LoaderDisabled }, false},
		{"rename enabled", false, func(s *loaders.Spec) { s.Name = "renamed" }, false},
		{"rename disabled", true, func(s *loaders.Spec) { s.Name = "renamed"; s.Status = store.LoaderDisabled }, false},
		{"enable", true, func(s *loaders.Spec) { s.Status = store.LoaderEnabled }, true},
		{"other non-ASCII host", false, func(s *loaders.Spec) { s.Config = csv(other) }, true},
		{"other non-ASCII host while pausing", false, func(s *loaders.Spec) { s.Config = csv(other); s.Status = store.LoaderDisabled }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			l := h.create(h.csvSpec("legacy", "people.csv", "g"), "")
			// the row as an earlier version stored it
			err := h.db.InTenant(context.Background(), tid, func(tx *store.TenantTx) error {
				l.Config = string(csv(legacy))
				if tc.disabled {
					l.Status = store.LoaderDisabled
				}
				return tx.UpdateGrpLoader(l)
			})
			if err != nil {
				t.Fatal(err)
			}
			spec, err := loaders.SpecOf(h.loader(l.ID))
			if err != nil {
				t.Fatal(err)
			}
			tc.edit(&spec)
			err = h.db.InTenant(context.Background(), tid, func(tx *store.TenantTx) error {
				_, err := loaders.Update(loaders.SaveEnv{Tx: tx, Now: h.now, Sealer: h.sealer}, l.ID, nil, spec, nil)
				return err
			})
			if tc.refused != (err != nil) || (err != nil && !strings.Contains(err.Error(), "must be ASCII")) {
				t.Fatalf("refused=%v, got %v", tc.refused, err)
			}
		})
	}
}
