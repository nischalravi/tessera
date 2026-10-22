package model_test

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/deleteguard"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func limit(t *testing.T, e model.Env, cat string, n int) {
	t.Helper()
	if err := deleteguard.Set(e.Tx, deleteguard.Policy{Category: cat, MaxCount: &n, WindowMinutes: 60, Mode: deleteguard.ModeHoldExcess}, nil, e.Now); err != nil {
		t.Fatal(err)
	}
}

func mkIdentities(t *testing.T, e model.Env, n int) []int64 {
	t.Helper()
	var out []int64
	for i := 0; i < n; i++ {
		id, err := e.Tx.InsertIdentity(&store.Identity{ExternalID: fmt.Sprintf("guard-u%d", i), Name: fmt.Sprintf("Guard %d", i),
			Type: "person", Status: "active", CreatedAt: e.Now})
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, id)
	}
	return out
}

func holdItems(t *testing.T, e model.Env, id string) []*store.DeletionHoldItem {
	t.Helper()
	items, err := e.Tx.DeletionHoldItems(id)
	if err != nil {
		t.Fatal(err)
	}
	return items
}

func TestGroupDeletesOverTheThresholdAreHeldAndReleased(t *testing.T) {
	f := storetest.TwoTenants(t)
	must(t, f, func(e model.Env) error {
		limit(t, e, deleteguard.CatGroups, 2)
		app := mkFolder(t, e, "", "app")
		var gs []*store.NativeGroup
		for i := 0; i < 5; i++ {
			gs = append(gs, mkGroup(t, e, app.ID, fmt.Sprintf("g%d", i)))
		}
		col := &deleteguard.Collector{}
		e.Held, e.Correlation = col, "req-1"
		e.By = new(string)
		*e.By = "alice"
		for _, g := range gs {
			if err := e.DeleteGroup(g.ID); err != nil {
				return err
			}
		}
		if col.Applied() != 2 || col.Held() != 3 {
			t.Fatalf("applied %d held %d", col.Applied(), col.Held())
		}
		deleted := 0
		for _, g := range gs {
			got, _ := e.Group(g.ID)
			if got.Status == store.GroupDeleted {
				deleted++
			}
		}
		if deleted != 2 {
			t.Errorf("%d groups were deleted, want 2", deleted)
		}
		res := col.Result()
		if res == nil || res.Held != 3 || res.HoldID == "" || res.Message == "" {
			t.Fatalf("result %+v", res)
		}
		h, err := e.Tx.DeletionHoldByID(res.HoldID)
		if err != nil {
			return err
		}
		if h.Actor != "alice" || h.Source != "user" || h.ItemCount != 3 {
			t.Errorf("hold %+v", h)
		}
		// the release re-checks each group, deletes it, and does not count against the window
		before, _ := e.Tx.DeletionsApplied(deleteguard.CatGroups, e.Now.Add(-1))
		for _, it := range holdItems(t, e, h.ID) {
			if out, note, err := e.ReleaseGroup(it); err != nil || out != deleteguard.ItemReleased {
				t.Errorf("release %s = %s %q %v", it.Label, out, note, err)
			}
		}
		if after, _ := e.Tx.DeletionsApplied(deleteguard.CatGroups, e.Now.Add(-1)); after != before {
			t.Errorf("the window grew from %d to %d on a release", before, after)
		}
		for _, g := range gs {
			if got, _ := e.Group(g.ID); got.Status != store.GroupDeleted {
				t.Errorf("%s is %s after the release", g.Name, got.Status)
			}
		}
		// a second release of a deleted group finds nothing left to do
		it := holdItems(t, e, h.ID)[0]
		if out, _, err := e.ReleaseGroup(it); err != nil || out != deleteguard.ItemGone {
			t.Errorf("release of a deleted group = %s %v", out, err)
		}
		return nil
	})
}

func TestPurgeAndFolderDeleteAreGuarded(t *testing.T) {
	f := storetest.TwoTenants(t)
	must(t, f, func(e model.Env) error {
		limit(t, e, deleteguard.CatGroups, 100)
		limit(t, e, deleteguard.CatFolders, 1)
		app := mkFolder(t, e, "", "app")
		g := mkGroup(t, e, app.ID, "g")
		if err := e.DeleteGroup(g.ID); err != nil {
			return err
		}
		limit(t, e, deleteguard.CatGroups, 1) // the soft delete used the one
		col := &deleteguard.Collector{}
		e.Held = col
		if err := e.PurgeGroup(g.ID); err != nil {
			return err
		}
		if col.Held() != 1 {
			t.Fatalf("purge held %d", col.Held())
		}
		if _, err := e.Group(g.ID); err != nil {
			t.Errorf("the group was purged although the purge was held: %v", err)
		}
		it := holdItems(t, e, col.Result().HoldID)[0]
		if it.Kind != model.ItemGroupPurge {
			t.Fatalf("kind %s", it.Kind)
		}
		if out, _, err := e.ReleaseGroup(it); err != nil || out != deleteguard.ItemReleased {
			t.Errorf("release purge = %s %v", out, err)
		}
		if _, err := e.Group(g.ID); err == nil {
			t.Errorf("the group is still there after the release")
		}
		// folders: one allowed per window, the second is held
		a, b := mkFolder(t, e, "", "fa"), mkFolder(t, e, "", "fb")
		col = &deleteguard.Collector{}
		e.Held = col
		if err := e.DeleteFolder(a.ID); err != nil {
			return err
		}
		if err := e.DeleteFolder(b.ID); err != nil {
			return err
		}
		if col.Applied() != 1 || col.Held() != 1 {
			t.Errorf("folders applied %d held %d", col.Applied(), col.Held())
		}
		if _, err := e.Folder(b.ID); err != nil {
			t.Errorf("the held folder is gone: %v", err)
		}
		return nil
	})
}

func TestRecursiveFolderDeleteAppliesUpToTheThreshold(t *testing.T) {
	f := storetest.TwoTenants(t)
	must(t, f, func(e model.Env) error {
		limit(t, e, deleteguard.CatGroups, 3)
		app := mkFolder(t, e, "", "app")
		for i := 0; i < 6; i++ {
			mkGroup(t, e, app.ID, fmt.Sprintf("g%d", i))
		}
		col := &deleteguard.Collector{}
		e.Held = col
		_, res, err := e.DeleteFolderRecursive(app.ID)
		if err != nil {
			return err
		}
		if res.Groups != 3 || res.Held != 3 || res.Folders != 0 {
			t.Errorf("result %+v", res)
		}
		if _, err := e.Folder(app.ID); err != nil {
			t.Errorf("the folder was removed although groups were held: %v", err)
		}
		hold := col.Result()
		if hold == nil || hold.Held != 3 {
			t.Fatalf("hold %+v", hold)
		}
		// the held groups are the last three of the plan, deterministically
		items := holdItems(t, e, hold.HoldID)
		if len(items) != 3 || items[0].Kind != model.ItemGroupTree {
			t.Fatalf("items %+v", items)
		}
		for _, it := range items {
			if out, note, err := e.ReleaseGroup(it); err != nil || out != deleteguard.ItemReleased {
				t.Errorf("release %s = %s %q %v", it.Label, out, note, err)
			}
		}
		// the tree is empty now, so a second delete takes the folder (the folders category has room)
		e.Held = nil
		if _, res, err = e.DeleteFolderRecursive(app.ID); err != nil || res.Folders != 1 || res.Held != 0 {
			t.Errorf("second delete = %+v %v", res, err)
		}
		return nil
	})
}

func TestMemberRemovalsOverTheThresholdAreHeld(t *testing.T) {
	f := storetest.TwoTenants(t)
	must(t, f, func(e model.Env) error {
		limit(t, e, deleteguard.CatMembers, 2)
		app := mkFolder(t, e, "", "app")
		g := mkGroup(t, e, app.ID, "g")
		ids := mkIdentities(t, e, 5)
		for _, id := range ids {
			if _, err := e.AddMember(g.ID, model.MemberInput{Identity: &id}); err != nil {
				return err
			}
		}
		col := &deleteguard.Collector{}
		e.Held, e.Correlation = col, "req-2"
		held := 0
		for _, id := range ids {
			out, err := e.RemoveMember(g.ID, strconv.FormatInt(id, 10))
			if err != nil {
				return err
			}
			if out.Held {
				held++
			}
		}
		if held != 3 || col.Applied() != 2 {
			t.Fatalf("held %d applied %d", held, col.Applied())
		}
		n, err := e.Tx.GrpDirectCount(store.GrpDirectFilter{Group: g.ID})
		if err != nil || n != 3 {
			t.Errorf("%d memberships left (%v), want the 3 held", n, err)
		}
		// release: each membership is re-checked; one that is gone meanwhile is "gone"
		hold := col.Last()
		items := holdItems(t, e, hold.HoldID)
		if len(items) != 3 || items[0].Kind != model.ItemMember {
			t.Fatalf("items %+v", items)
		}
		ov := e
		ov.Override = true // an admin removes one of them by hand meanwhile
		if _, err := ov.RemoveMember(g.ID, strings.Split(items[0].Ref, "|")[2]); err != nil {
			return err
		}
		outs := map[string]int{}
		for _, it := range items {
			out, _, err := e.ReleaseMember(it)
			if err != nil {
				return err
			}
			outs[out]++
		}
		if outs[deleteguard.ItemReleased] != 2 || outs[deleteguard.ItemGone] != 1 {
			t.Errorf("outcomes %v", outs)
		}
		if n, _ := e.Tx.GrpDirectCount(store.GrpDirectFilter{Group: g.ID}); n != 0 {
			t.Errorf("%d memberships left after the release", n)
		}
		return nil
	})
}

func TestHoldAllHoldsALoaderGroupsWholeRemoval(t *testing.T) {
	f := storetest.TwoTenants(t)
	must(t, f, func(e model.Env) error {
		n := 2
		if err := deleteguard.Set(e.Tx, deleteguard.Policy{Category: deleteguard.CatMembers, MaxCount: &n, WindowMinutes: 60,
			Mode: deleteguard.ModeHoldAll}, nil, e.Now); err != nil {
			return err
		}
		app := mkFolder(t, e, "", "app")
		e.Cause, e.CauseRef = store.CauseLoader, "ldr-1"
		g, err := e.CreateLoaderGroup(model.LoaderGroupInput{Folder: app.ID, Extension: "lg", LoaderID: "ldr-1"})
		if err != nil {
			return err
		}
		ids := mkIdentities(t, e, 4)
		if _, err := e.LoaderSync(g, "ldr-1", ids, nil); err != nil {
			return err
		}
		res, err := e.LoaderSync(g, "ldr-1", nil, ids)
		if err != nil {
			return err
		}
		if res.Removed != 0 || res.Held != 4 {
			t.Errorf("hold_all: removed %d held %d", res.Removed, res.Held)
		}
		// within the threshold the same removal goes through
		res, err = e.LoaderSync(g, "ldr-1", nil, ids[:2])
		if err != nil {
			return err
		}
		if res.Removed != 2 || res.Held != 0 {
			t.Errorf("a batch under the threshold: removed %d held %d", res.Removed, res.Held)
		}
		hs, err := e.Tx.DeletionHolds("held", deleteguard.CatMembers, 10, 0)
		if err != nil || len(hs) != 1 || hs[0].Source != "loader" || hs[0].SourceID != "ldr-1" || hs[0].Mode != "hold_all" {
			t.Errorf("holds %+v %v", hs, err)
		}
		return nil
	})
}
