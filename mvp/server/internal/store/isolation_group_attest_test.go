package store_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Group attestation, deprovisioning, the Inbox and reports (issue #57, GR-14):
// every row is its tenant's. Another tenant's ids look nonexistent, writes find
// nothing to change, and the guard triggers refuse a row that names another
// tenant's group, folder, identity, user or campaign.

type attestIDs struct {
	g      store.GroupID
	folder store.FolderID
	ident  int64
	user   string
	task   string
	camp   string
	item   string
	review int64
	deprov string
	report string
	run    string
}

func seedAttest(t *testing.T, f *storetest.Fixture) map[string]attestIDs {
	t.Helper()
	base := seedEngine(t, f)
	out := map[string]attestIDs{}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		ids := attestIDs{g: base[tn.Slug].g1, ident: base[tn.Slug].ident}
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			fo, err := c.GrpFolderByName("app")
			if err != nil {
				return err
			}
			ids.folder = fo.ID
			u := &store.PlatformUser{DisplayName: "U " + tn.Slug, CreatedAt: storetest.Now}
			if err := c.InsertPlatformUser(u); err != nil {
				return err
			}
			ids.user = u.ID.String()
			key := "k-" + tn.Slug
			task := &store.GrpTask{Kind: store.TaskRule, Title: "t", ObjectType: "group", ObjectID: string(ids.g), Subject: &ids.ident,
				DedupeKey: &key, CreatedAt: storetest.Now}
			if err := c.InsertGrpTask(task); err != nil {
				return err
			}
			ids.task = task.ID
			if err := c.SetGrpAttestSettings(&store.GrpAttestSettings{OwnerType: "group", OwnerID: string(ids.g), IntervalDays: 30, WindowDays: 14,
				ReviewerType: "admins", ReminderDays: "[]", OverdueAction: "none", Enabled: true, UpdatedBy: ids.user, UpdatedAt: storetest.Now}); err != nil {
				return err
			}
			rc, err := c.InsertCampaign(&store.ReviewCampaign{Name: "x", CreatedAt: storetest.Now, Status: "open", UnusedDays: 90})
			if err != nil {
				return err
			}
			if err := c.InsertReviewItem(&store.ReviewItem{CampaignID: rc, IdentityID: ids.ident, EdgeSrc: "native-group:x", EdgeDst: fmt.Sprintf("identity:%d", ids.ident),
				GrantLabel: "l", Reasons: []string{}, Context: []byte("{}")}); err != nil {
				return err
			}
			ris, err := c.CampaignItems(rc)
			if err != nil {
				return err
			}
			ids.review = ris[0].ID
			camp := &store.GrpAttestCampaign{GroupID: ids.g, Kind: "periodic", ReviewCampaign: &rc, StartedAt: storetest.Now,
				DueAt: storetest.Now.Add(24 * time.Hour), OverdueAction: "none", ReviewerType: "admins", ReminderDays: "[]", ActsAs: ids.user,
				PopulationCount: 1, PopulationHash: "h"}
			if err := c.InsertGrpAttestCampaign(camp); err != nil {
				return err
			}
			ids.camp = camp.ID
			item := &store.GrpAttestItem{CampaignID: camp.ID, GroupID: ids.g, Identity: ids.ident, How: "direct", ReviewItem: &ris[0].ID}
			if err := c.InsertGrpAttestItem(item); err != nil {
				return err
			}
			ids.item = item.ID
			if err := c.SetGrpDeprovSettings(&store.GrpDeprovSettings{Affiliations: "[]", VetoEnabled: true, UpdatedAt: storetest.Now}); err != nil {
				return err
			}
			if err := c.SetGrpDeprovFolder(&store.GrpDeprovFolder{FolderID: ids.folder, Mode: "notify", UpdatedBy: ids.user, UpdatedAt: storetest.Now}); err != nil {
				return err
			}
			if err := c.SetGrpDeprovMark(store.GrpDeprovMark{Identity: ids.ident, Since: storetest.Now, Reason: "leaver"}); err != nil {
				return err
			}
			d := &store.GrpDeprovItem{Identity: ids.ident, FolderID: ids.folder, TaskID: &ids.task, Mode: "notify", OpenedAt: storetest.Now}
			if err := c.InsertGrpDeprovItem(d); err != nil {
				return err
			}
			ids.deprov = d.ID
			next := storetest.Now.Add(time.Hour)
			r := &store.GrpReport{Name: "r", Kind: "group_members", Params: "{}", Format: "csv", Schedule: "daily", Delivery: "store", NextRunAt: &next,
				CreatedBy: ids.user, CreatedAt: storetest.Now, UpdatedAt: storetest.Now}
			if err := c.InsertGrpReport(r); err != nil {
				return err
			}
			ids.report = r.ID
			run := &store.GrpReportRun{ReportID: r.ID, RanAt: storetest.Now, RanBy: ids.user, Trigger: "manual", Status: "ok", Format: "csv"}
			if err := c.InsertGrpReportRun(run); err != nil {
				return err
			}
			ids.run = run.ID
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		out[tn.Slug] = ids
	}
	return out
}

func TestIsolation_GroupAttestationTables(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedAttest(t, f)
	a, b := ids[f.A.Slug], ids[f.B.Slug]
	nf := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s = %v, want ErrNotFound", what, err)
		}
	}
	inB(t, f, func(c *store.TenantTx) error {
		_, err := c.GrpTask(a.task)
		nf("GrpTask(A's)", err)
		_, err = c.GrpOpenTaskByKey("k-" + f.A.Slug)
		nf("GrpOpenTaskByKey(A's)", err)
		if _, err := c.GrpOpenTaskByKey("k-" + f.B.Slug); err != nil {
			t.Errorf("GrpOpenTaskByKey(B's) = %v", err)
		}
		if rows, err := c.GrpTasks(store.GrpTaskFilter{}); err != nil || len(rows) != 1 || rows[0].ID != b.task {
			t.Errorf("GrpTasks = %v, %v; want B's one", rows, err)
		}
		nf("CloseGrpTask(A's)", c.CloseGrpTask(a.task, "done", storetest.Now, ""))
		_, err = c.GrpAttestSettingsOf("group", string(a.g))
		nf("GrpAttestSettingsOf(A's)", err)
		if rows, err := c.GrpAttestSettingsEnabled(); err != nil || len(rows) != 1 {
			t.Errorf("GrpAttestSettingsEnabled = %d, %v; want B's 1", len(rows), err)
		}
		if had, err := c.DeleteGrpAttestSettings("group", string(a.g)); err != nil || had {
			t.Errorf("DeleteGrpAttestSettings(A's) = %v, %v", had, err)
		}
		_, err = c.GrpAttestCampaign(a.camp)
		nf("GrpAttestCampaign(A's)", err)
		if rows, err := c.GrpAttestCampaigns(store.GrpAttestFilter{Group: a.g}); err != nil || len(rows) != 0 {
			t.Errorf("GrpAttestCampaigns(A's group) = %d, %v", len(rows), err)
		}
		if rows, err := c.GrpAttestCampaigns(store.GrpAttestFilter{}); err != nil || len(rows) != 1 {
			t.Errorf("GrpAttestCampaigns = %d, %v; want B's 1", len(rows), err)
		}
		nf("SaveGrpAttestCampaign(A's)", c.SaveGrpAttestCampaign(&store.GrpAttestCampaign{ID: a.camp, Status: "open"}))
		_, err = c.GrpAttestItem(a.item)
		nf("GrpAttestItem(A's)", err)
		_, err = c.GrpAttestItemByReview(a.review)
		nf("GrpAttestItemByReview(A's)", err)
		if rows, err := c.GrpAttestItems(a.camp); err != nil || len(rows) != 0 {
			t.Errorf("GrpAttestItems(A's) = %d, %v", len(rows), err)
		}
		nf("SetGrpAttestItemApplied(A's)", c.SetGrpAttestItemApplied(a.item, "applied", "", storetest.Now))
		if _, err := c.GrpDeprovSettings(); err != nil {
			t.Errorf("GrpDeprovSettings = %v", err)
		}
		_, err = c.GrpDeprovFolder(a.folder)
		nf("GrpDeprovFolder(A's)", err)
		if had, err := c.DeleteGrpDeprovFolder(a.folder); err != nil || had {
			t.Errorf("DeleteGrpDeprovFolder(A's) = %v, %v", had, err)
		}
		_, err = c.GrpDeprovMark(a.ident)
		nf("GrpDeprovMark(A's)", err)
		if had, err := c.ClearGrpDeprovMark(a.ident); err != nil || had {
			t.Errorf("ClearGrpDeprovMark(A's) = %v, %v", had, err)
		}
		_, err = c.GrpDeprovItem(a.deprov)
		nf("GrpDeprovItem(A's)", err)
		if rows, err := c.GrpDeprovItems(store.GrpDeprovFilter{}); err != nil || len(rows) != 1 || rows[0].ID != b.deprov {
			t.Errorf("GrpDeprovItems = %v, %v; want B's one", rows, err)
		}
		nf("ResolveGrpDeprovItem(A's)", c.ResolveGrpDeprovItem(a.deprov, "removed", "", "", storetest.Now))
		if ids, err := c.GrpInactiveHolders(); err != nil || len(ids) != 0 {
			t.Errorf("GrpInactiveHolders = %v, %v", ids, err)
		}
		_, err = c.GrpReport(a.report)
		nf("GrpReport(A's)", err)
		if rows, err := c.GrpReports(""); err != nil || len(rows) != 1 || rows[0].ID != b.report {
			t.Errorf("GrpReports = %v, %v; want B's one", rows, err)
		}
		if rows, err := c.GrpReportsDue(storetest.Now.Add(48*time.Hour), 100); err != nil || len(rows) != 1 {
			t.Errorf("GrpReportsDue = %d, %v; want B's 1", len(rows), err)
		}
		nf("SaveGrpReport(A's)", c.SaveGrpReport(&store.GrpReport{ID: a.report, Name: "z", Params: "{}", Format: "csv", Schedule: "none", Delivery: "store",
			UpdatedAt: storetest.Now}))
		_, err = c.GrpReportRun(a.run)
		nf("GrpReportRun(A's)", err)
		if rows, err := c.GrpReportRuns(a.report, 10); err != nil || len(rows) != 0 {
			t.Errorf("GrpReportRuns(A's) = %d, %v", len(rows), err)
		}
		if n, err := c.PruneGrpReportRuns(a.report, 0); err != nil || n != 0 {
			t.Errorf("PruneGrpReportRuns(A's) = %d, %v", n, err)
		}
		nf("DeleteGrpReport(A's)", c.DeleteGrpReport(a.report))
		return nil
	})
	// everything of A's is still there
	err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		if tk, err := c.GrpTask(a.task); err != nil || tk.Status != "open" {
			t.Errorf("A's task = %+v, %v", tk, err)
		}
		if _, err := c.GrpReport(a.report); err != nil {
			t.Errorf("A's report: %v", err)
		}
		if rows, err := c.GrpReportRuns(a.report, 10); err != nil || len(rows) != 1 {
			t.Errorf("A's runs = %d, %v", len(rows), err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestIsolation_GroupAttestationCrossTenantReferences(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedAttest(t, f)
	a, b := ids[f.A.Slug], ids[f.B.Slug]
	run := func(fn func(c *store.TenantTx) error) error { return f.DB.InTenant(context.Background(), f.B.ID, fn) }
	camp := func(c *store.TenantTx) *store.GrpAttestCampaign {
		return &store.GrpAttestCampaign{GroupID: b.g, Kind: "micro", StartedAt: storetest.Now, DueAt: storetest.Now, OverdueAction: "none",
			ReviewerType: "admins", ReminderDays: "[]", ActsAs: b.user, PopulationCount: 0, PopulationHash: "h"}
	}
	for name, fn := range map[string]func(c *store.TenantTx) error{
		"a task about A's group": func(c *store.TenantTx) error {
			return c.InsertGrpTask(&store.GrpTask{Kind: "rule", Title: "t", ObjectType: "group", ObjectID: string(a.g), CreatedAt: storetest.Now})
		},
		"a task about A's folder": func(c *store.TenantTx) error {
			return c.InsertGrpTask(&store.GrpTask{Kind: "rule", Title: "t", ObjectType: "folder", ObjectID: string(a.folder), CreatedAt: storetest.Now})
		},
		"a task about A's identity": func(c *store.TenantTx) error {
			return c.InsertGrpTask(&store.GrpTask{Kind: "rule", Title: "t", ObjectType: "group", ObjectID: string(b.g), Subject: &a.ident, CreatedAt: storetest.Now})
		},
		"settings of A's group": func(c *store.TenantTx) error {
			return c.SetGrpAttestSettings(&store.GrpAttestSettings{OwnerType: "group", OwnerID: string(a.g), IntervalDays: 1, WindowDays: 1,
				ReviewerType: "admins", ReminderDays: "[]", OverdueAction: "none", UpdatedBy: b.user, UpdatedAt: storetest.Now})
		},
		"settings saved by A's user": func(c *store.TenantTx) error {
			return c.SetGrpAttestSettings(&store.GrpAttestSettings{OwnerType: "folder", OwnerID: string(b.folder), IntervalDays: 1, WindowDays: 1,
				ReviewerType: "admins", ReminderDays: "[]", OverdueAction: "none", UpdatedBy: a.user, UpdatedAt: storetest.Now})
		},
		"a campaign on A's group": func(c *store.TenantTx) error {
			x := camp(c)
			x.GroupID = a.g
			return c.InsertGrpAttestCampaign(x)
		},
		"a campaign acting as A's user": func(c *store.TenantTx) error {
			x := camp(c)
			x.ActsAs = a.user
			return c.InsertGrpAttestCampaign(x)
		},
		"an item of A's campaign": func(c *store.TenantTx) error {
			return c.InsertGrpAttestItem(&store.GrpAttestItem{CampaignID: a.camp, GroupID: b.g, Identity: b.ident, How: "direct"})
		},
		"an item for A's identity": func(c *store.TenantTx) error {
			return c.InsertGrpAttestItem(&store.GrpAttestItem{CampaignID: b.camp, GroupID: b.g, Identity: a.ident, How: "nested"})
		},
		"a deprovisioning folder of A's": func(c *store.TenantTx) error {
			return c.SetGrpDeprovFolder(&store.GrpDeprovFolder{FolderID: a.folder, Mode: "notify", UpdatedBy: b.user, UpdatedAt: storetest.Now})
		},
		"a deprovisioned mark for A's identity": func(c *store.TenantTx) error {
			return c.SetGrpDeprovMark(store.GrpDeprovMark{Identity: a.ident, Since: storetest.Now, Reason: "leaver"})
		},
		"a deprovisioning item in A's folder": func(c *store.TenantTx) error {
			return c.InsertGrpDeprovItem(&store.GrpDeprovItem{Identity: b.ident, FolderID: a.folder, Mode: "notify", OpenedAt: storetest.Now})
		},
		"a report by A's user": func(c *store.TenantTx) error {
			return c.InsertGrpReport(&store.GrpReport{Name: "r", Kind: "k", Params: "{}", Format: "csv", Schedule: "none", Delivery: "store",
				CreatedBy: a.user, CreatedAt: storetest.Now, UpdatedAt: storetest.Now})
		},
		"a run of A's report": func(c *store.TenantTx) error {
			return c.InsertGrpReportRun(&store.GrpReportRun{ReportID: a.report, RanAt: storetest.Now, RanBy: b.user, Trigger: "manual", Status: "ok", Format: "csv"})
		},
		"a row stamped with A": func(c *store.TenantTx) error {
			return c.InsertGrpTask(&store.GrpTask{TenantID: f.A.ID, Kind: "rule", Title: "t", ObjectType: "group", ObjectID: string(b.g), CreatedAt: storetest.Now})
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := run(fn); !errors.Is(err, store.ErrCrossTenant) {
				t.Fatalf("err = %v, want ErrCrossTenant", err)
			}
		})
	}
}

// groupAttestCovered lists the repository methods of GR-14 that
// TestIsolation_GroupAttestationTables exercises.
func groupAttestCovered() map[string]bool {
	m := map[string]bool{}
	for _, name := range []string{"InsertGrpTask", "GrpTask", "GrpOpenTaskByKey", "GrpTasks", "CloseGrpTask", "GrpAttestSettingsOf",
		"GrpAttestSettingsEnabled", "SetGrpAttestSettings", "DeleteGrpAttestSettings", "InsertGrpAttestCampaign", "GrpAttestCampaign",
		"GrpAttestCampaigns", "SaveGrpAttestCampaign", "InsertGrpAttestItem", "GrpAttestItem", "GrpAttestItemByReview", "GrpAttestItems",
		"SetGrpAttestItemApplied", "GrpDeprovSettings", "SetGrpDeprovSettings", "GrpDeprovFolder", "SetGrpDeprovFolder",
		"DeleteGrpDeprovFolder", "GrpDeprovMark", "SetGrpDeprovMark", "ClearGrpDeprovMark", "InsertGrpDeprovItem", "GrpDeprovItem",
		"GrpDeprovItems", "ResolveGrpDeprovItem", "GrpInactiveHolders", "InsertGrpReport", "GrpReport", "GrpReports", "GrpReportsDue",
		"SaveGrpReport", "DeleteGrpReport", "InsertGrpReportRun", "GrpReportRun", "GrpReportRuns", "PruneGrpReportRuns"} {
		m[name] = true
	}
	return m
}
