package reviews_test

import (
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/reviews"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

func TestDecideIsFinal(t *testing.T) {
	tests := []struct {
		name      string
		decisions []string
		wantErr   []bool // a *DecidedError per decision
		wantFinal string
	}{
		{"keep then revoke", []string{"keep", "revoke"}, []bool{false, true}, "keep"},
		{"revoke then keep", []string{"revoke", "keep"}, []bool{false, true}, "revoke"},
		{"revoke twice", []string{"revoke", "revoke"}, []bool{false, false}, "revoke"},
		{"keep twice", []string{"keep", "keep"}, []bool{false, false}, "keep"},
		{"first refusal does not change a later same decision", []string{"keep", "revoke", "keep"}, []bool{false, true, false}, "keep"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db := testkit.Demo(t)
			var itemID int64
			testkit.Read(t, db, func(c *store.TenantTx) error {
				items, err := c.CampaignItems(1)
				if err == nil {
					itemID = items[0].ID
				}
				return err
			})
			now := testkit.Now
			for i, d := range tc.decisions {
				testkit.Write(t, db, func(c *store.TenantTx) error {
					it, err := reviews.Decide(c, now, itemID, d, store.UserRef{Display: "rev"}, nil)
					var de *reviews.DecidedError
					if got := errors.As(err, &de); got != tc.wantErr[i] {
						t.Errorf("decision %d (%s): DecidedError = %v (%v), want %v", i, d, got, err, tc.wantErr[i])
					}
					if err != nil && !tc.wantErr[i] {
						t.Fatalf("decision %d: %v", i, err)
					}
					if it == nil || it.Decision == nil || *it.Decision != tc.wantFinal {
						t.Errorf("decision %d: returned item %v, want decision %s", i, it, tc.wantFinal)
					}
					return nil
				})
			}
			testkit.Read(t, db, func(c *store.TenantTx) error {
				it, err := c.Item(itemID)
				if err != nil {
					return err
				}
				if it.Decision == nil || *it.Decision != tc.wantFinal {
					t.Errorf("stored decision = %v, want %s", it.Decision, tc.wantFinal)
				}
				_, err = c.EdgeBetween(it.EdgeSrc, it.EdgeDst)
				if live := err == nil; live != (tc.wantFinal == "keep") {
					t.Errorf("grant live = %v after final %s", live, tc.wantFinal)
				}
				return nil
			})
		})
	}
}

func TestDecideRejectsBadInput(t *testing.T) {
	db := testkit.Demo(t)
	testkit.Write(t, db, func(c *store.TenantTx) error {
		var e *reviews.Error
		if _, err := reviews.Decide(c, testkit.Now, 1, "maybe", store.UserRef{}, nil); !errors.As(err, &e) {
			t.Errorf("bad decision: %v", err)
		}
		if _, err := reviews.Decide(c, testkit.Now, 999999, "keep", store.UserRef{}, nil); !errors.As(err, &e) {
			t.Errorf("unknown item: %v", err)
		}
		return nil
	})
}
