package flatfile_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/deleteguard"
	"github.com/nischalravi/tessera/mvp/server/internal/flatfile"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// A re-upload that drops a few accounts (15%, a plausible change) but more than the explicitly
// configured hold_excess threshold allows disables up to it and holds the rest.
func TestApply_DroppedAccountsOverTheThresholdAreHeld(t *testing.T) {
	e := newEnv(t)
	limit := 2
	e.tx(func(c *store.TenantTx) error {
		return deleteguard.Set(c, deleteguard.Policy{Category: deleteguard.CatAccounts, MaxCount: &limit, WindowMinutes: 60, Mode: deleteguard.ModeHoldExcess}, nil, e.now)
	})
	var v1, v2 strings.Builder
	v1.WriteString(accountsHead)
	v2.WriteString(accountsHead)
	for i := 0; i < 20; i++ {
		line := fmt.Sprintf("g%02d,login%02d,,,active\n", i, i)
		v1.WriteString(line)
		if i < 17 {
			v2.WriteString(line)
		}
	}
	e.mustApplied(e.accounts(v1.String()))
	e.mustApplied(e.accounts(v2.String()))
	active, off := 0, 0
	for i := 17; i < 20; i++ {
		if e.account(fmt.Sprintf("g%02d", i)).Status == "active" {
			active++
		} else {
			off++
		}
	}
	if off != 2 || active != 1 {
		t.Fatalf("%d of the 3 dropped accounts were disabled and %d kept, want 2 and 1", off, active)
	}
	e.tx(func(c *store.TenantTx) error {
		hs, err := c.DeletionHolds("held", deleteguard.CatAccounts, 10, 0)
		if err != nil || len(hs) != 1 || hs[0].ItemCount != 1 || hs[0].Source != "connector" || hs[0].SourceID != sys {
			t.Fatalf("holds %+v %v", hs, err)
		}
		res, err := deleteguard.Release(c, e.now, hs[0].ID, "approver", nil, deleteguard.Appliers{flatfile.ItemDropAccount: flatfile.ReleaseDrop})
		if err != nil || res.Released != 1 {
			t.Fatalf("release %+v %v", res, err)
		}
		return nil
	})
	for i := 17; i < 20; i++ {
		if st := e.account(fmt.Sprintf("g%02d", i)).Status; st != "disabled" {
			t.Errorf("g%02d is %s after the release", i, st)
		}
	}
}

// A truncated file (20 accounts, the next upload lists 2) is not trusted to say who is gone: all
// 18 removals are held and none applied, the same bad file again does not open another hold, and
// the release by another admin applies exactly the held set.
func TestApply_TruncatedFileHoldsEveryRemoval(t *testing.T) {
	e := newEnv(t)
	var v1, v2 strings.Builder
	v1.WriteString(accountsHead)
	v2.WriteString(accountsHead)
	for i := 0; i < 20; i++ {
		line := fmt.Sprintf("g%02d,login%02d,,,active\n", i, i)
		v1.WriteString(line)
		if i < 2 {
			v2.WriteString(line)
		}
	}
	e.mustApplied(e.accounts(v1.String()))
	e.mustApplied(e.accounts(v2.String()))
	for i := 2; i < 20; i++ {
		if st := e.account(fmt.Sprintf("g%02d", i)).Status; st != "active" {
			t.Fatalf("g%02d is %s: a truncated file disabled it", i, st)
		}
	}
	e.mustApplied(e.accounts(v2.String())) // the same bad file again
	e.tx(func(c *store.TenantTx) error {
		hs, err := c.DeletionHolds("held", deleteguard.CatAccounts, 10, 0)
		if err != nil || len(hs) != 1 || hs[0].ItemCount != 18 {
			t.Fatalf("holds %+v %v", hs, err)
		}
		if !strings.Contains(hs[0].Reason, "fewer than the last good run") {
			t.Errorf("reason %s", hs[0].Reason)
		}
		res, err := deleteguard.Release(c, e.now, hs[0].ID, "approver", nil, deleteguard.Appliers{flatfile.ItemDropAccount: flatfile.ReleaseDrop})
		if err != nil || res.Released != 18 {
			t.Fatalf("release %+v %v", res, err)
		}
		return nil
	})
	for i := 2; i < 20; i++ {
		if st := e.account(fmt.Sprintf("g%02d", i)).Status; st != "disabled" {
			t.Errorf("g%02d is %s after the release", i, st)
		}
	}
}
