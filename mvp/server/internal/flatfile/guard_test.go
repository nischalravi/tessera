package flatfile_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/deleteguard"
	"github.com/nischalravi/tessera/mvp/server/internal/flatfile"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// A re-upload that no longer lists most of an app's accounts disables only up to the accounts
// threshold; the rest stay active and are held for a second admin, who can release them.
func TestApply_DroppedAccountsOverTheThresholdAreHeld(t *testing.T) {
	e := newEnv(t)
	limit := 2
	e.tx(func(c *store.TenantTx) error {
		return deleteguard.Set(c, deleteguard.Policy{Category: deleteguard.CatAccounts, MaxCount: &limit, WindowMinutes: 60, Mode: deleteguard.ModeHoldExcess}, nil, e.now)
	})
	var v1, v2 strings.Builder
	v1.WriteString(accountsHead)
	v2.WriteString(accountsHead)
	for i := 0; i < 10; i++ {
		line := fmt.Sprintf("g%02d,login%02d,,,active\n", i, i)
		v1.WriteString(line)
		if i < 2 {
			v2.WriteString(line)
		}
	}
	e.mustApplied(e.accounts(v1.String()))
	e.mustApplied(e.accounts(v2.String()))
	active, off := 0, 0
	for i := 2; i < 10; i++ {
		if e.account(fmt.Sprintf("g%02d", i)).Status == "active" {
			active++
		} else {
			off++
		}
	}
	if off != 2 || active != 6 {
		t.Fatalf("%d of the 8 dropped accounts were disabled and %d kept, want 2 and 6", off, active)
	}
	e.tx(func(c *store.TenantTx) error {
		hs, err := c.DeletionHolds("held", deleteguard.CatAccounts, 10, 0)
		if err != nil || len(hs) != 1 || hs[0].ItemCount != 6 || hs[0].Source != "connector" || hs[0].SourceID != sys {
			t.Fatalf("holds %+v %v", hs, err)
		}
		res, err := deleteguard.Release(c, e.now, hs[0].ID, "approver", nil, deleteguard.Appliers{flatfile.ItemDropAccount: flatfile.ReleaseDrop})
		if err != nil || res.Released != 6 {
			t.Fatalf("release %+v %v", res, err)
		}
		return nil
	})
	for i := 2; i < 10; i++ {
		if st := e.account(fmt.Sprintf("g%02d", i)).Status; st != "disabled" {
			t.Errorf("g%02d is %s after the release", i, st)
		}
	}
}
