package gov_test

import (
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/attest"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/deprov"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/gov"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/inbox"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/reports"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/rules"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/viz"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Attestation, deprovisioning, the Inbox, reports and the Groups lens (issue
// #57, GR-14; design §10.4, §10.5, §10.7), through the packages, with the
// rules that feed them.

var update = flag.Bool("update", false, "rewrite the report golden files")

type world struct {
	t  *testing.T
	f  *storetest.Fixture
	rt *rules.Runtime

	app, other                    store.FolderID
	gA, gB, gC, aff, gOther       store.GroupID
	alice, bob, carol, dave, ivan int64
	admin, author                 uuid.UUID
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{t: t, f: storetest.TwoTenants(t), rt: &rules.Runtime{}}
	w.in(func(c *store.TenantTx) {
		e := model.Env{Tx: c, Now: storetest.Now, TenantAdmin: true}
		folder := func(parent store.FolderID, ext string) store.FolderID {
			f, err := e.CreateFolder(model.CreateFolderInput{Parent: parent, Extension: ext})
			if err != nil {
				t.Fatal(err)
			}
			return f.ID
		}
		group := func(folder store.FolderID, ext string) store.GroupID {
			g, err := e.CreateGroup(model.CreateGroupInput{Folder: folder, Extension: ext})
			if err != nil {
				t.Fatal(err)
			}
			return g.ID
		}
		w.app, w.other = folder("", "app"), folder("", "other")
		w.gA, w.gB, w.gC, w.aff = group(w.app, "a"), group(w.app, "b"), group(w.app, "c"), group(w.app, "aff")
		w.gOther = group(w.other, "x")
		ident := func(name, dept string) int64 {
			email := strings.ToLower(name) + "@b.example"
			id, err := c.InsertIdentity(&store.Identity{ExternalID: name, Name: name, Type: "person", Status: "active", Email: &email,
				Department: &dept, CreatedAt: storetest.Now})
			if err != nil {
				t.Fatal(err)
			}
			return id
		}
		w.alice, w.bob, w.carol, w.dave, w.ivan = ident("Alice", "Eng"), ident("Bob", "Sales"), ident("Carol", "Eng"), ident("Dave", "Ops"),
			ident("Ivan", "Eng")
		user := func(name string, ident *int64) uuid.UUID {
			u := &store.PlatformUser{DisplayName: name, IdentityID: ident, CreatedAt: storetest.Now}
			if err := c.InsertPlatformUser(u); err != nil {
				t.Fatal(err)
			}
			return u.ID
		}
		w.admin, w.author = user("admin", nil), user("author", &w.ivan)
		if err := c.InsertRoleAssignment(&store.RoleAssignment{UserID: w.admin, Role: "tenant_admin", Source: "bootstrap", CreatedAt: storetest.Now}); err != nil {
			t.Fatal(err)
		}
	})
	return w
}

func (w *world) in(fn func(c *store.TenantTx)) {
	w.t.Helper()
	if err := w.f.DB.InTenant(context.Background(), w.f.B.ID, func(c *store.TenantTx) error { fn(c); return nil }); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) inErr(fn func(c *store.TenantTx) error) error {
	return w.f.DB.InTenant(context.Background(), w.f.B.ID, fn)
}

var adminSubject = privs.Subject{TenantAdmin: true}

// renv is a report environment with the run as a method.
type renv reports.Env

func (e renv) Run2(kind string, p reports.Params) (*reports.Result, error) {
	return reports.Run(reports.Env(e), kind, p)
}

func (w *world) checker(c *store.TenantTx, now time.Time, s privs.Subject) *privs.Checker {
	return privs.NewChecker(c, now, nil, s)
}

func (w *world) model(c *store.TenantTx, now time.Time) model.Env {
	return model.Env{Tx: c, Now: now, TenantAdmin: true, Guard: w.rt.Guard()}
}

func (w *world) add(c *store.TenantTx, now time.Time, g store.GroupID, id int64) {
	w.t.Helper()
	if _, err := w.model(c, now).AddMember(g, model.MemberInput{Identity: &id}); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) remove(c *store.TenantTx, now time.Time, g store.GroupID, id int64) {
	w.t.Helper()
	if _, err := w.model(c, now).RemoveMember(g, strconv.FormatInt(id, 10)); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) attestEnv(c *store.TenantTx, now time.Time) attest.Env {
	return attest.Env{Tx: c, Now: now, By: w.admin.String(), TenantAdmin: true, Checker: w.checker(c, now, adminSubject)}
}

func members(t *testing.T, c *store.TenantTx, now time.Time, g store.GroupID, who ...int64) map[int64]bool {
	t.Helper()
	out := map[int64]bool{}
	for _, id := range who {
		in, err := model.Env{Tx: c, Now: now}.IsMember(g, id)
		if err != nil {
			t.Fatal(err)
		}
		out[id] = in
	}
	return out
}

func detail(t *testing.T, c *store.TenantTx, camp string) (*attest.CampaignView, map[int64]attest.ItemView) {
	t.Helper()
	v, items, err := attest.Detail(c, camp)
	if err != nil {
		t.Fatal(err)
	}
	by := map[int64]attest.ItemView{}
	for _, it := range items {
		by[it.Identity] = it
	}
	return v, by
}

func TestAttestation_FrozenPopulation(t *testing.T) {
	w := newWorld(t)
	var camp string
	w.in(func(c *store.TenantTx) {
		for _, id := range []int64{w.alice, w.bob, w.carol} {
			w.add(c, storetest.Now, w.gA, id)
		}
		camp0, created, err := attest.Start(w.attestEnv(c, storetest.Now), w.gA, attest.StartInput{})
		if err != nil || !created {
			t.Fatalf("Start = %v, %v", camp0, err)
		}
		camp = camp0.ID
		if camp0.PopulationCount != 3 {
			t.Errorf("population = %d, want 3", camp0.PopulationCount)
		}
		// a second open campaign of the group is refused
		if _, _, err := attest.Start(w.attestEnv(c, storetest.Now), w.gA, attest.StartInput{}); err == nil || !strings.Contains(err.Error(), "attestation_open") {
			t.Errorf("second Start = %v, want attestation_open", err)
		}
	})
	w.in(func(c *store.TenantTx) {
		later := storetest.Now.Add(time.Hour)
		// the group changes while the campaign is open: the population does not
		w.add(c, later, w.gA, w.dave)
		w.remove(c, later, w.gA, w.alice)
		v, items := detail(t, c, camp)
		if len(items) != 3 || items[w.alice].Identity == 0 || items[w.dave].Identity != 0 {
			t.Errorf("items after the change = %v", items)
		}
		if ok, err := attest.Verify(c, camp); err != nil || !ok {
			t.Errorf("Verify = %v, %v; want the frozen population intact", ok, err)
		}
		if v.Counts.Total != 3 || v.Counts.Pending != 3 {
			t.Errorf("counts = %+v", v.Counts)
		}
		// each item carries how the membership was granted and the usage context
		if ctx := string(items[w.bob].Context); !strings.Contains(ctx, `"how":"direct"`) || !strings.Contains(ctx, "usage_scope") {
			t.Errorf("context = %s", ctx)
		}
		// a revoke is applied through the engine and read back; a keep leaves the member
		ur := store.UserRef{ID: w.admin, Display: "admin"}
		e := w.attestEnv(c, later)
		if _, err := attest.Decide(e, ur, camp, items[w.carol].ID, "revoke", nil); err != nil {
			t.Fatal(err)
		}
		if _, err := attest.Decide(e, ur, camp, items[w.bob].ID, "keep", nil); err != nil {
			t.Fatal(err)
		}
		in := members(t, c, later, w.gA, w.bob, w.carol, w.dave)
		if !in[w.bob] || in[w.carol] || !in[w.dave] {
			t.Errorf("members after the decisions = %v", in)
		}
		_, items = detail(t, c, camp)
		if items[w.carol].ApplyState != store.ApplyApplied || items[w.bob].ApplyState != store.ApplySkipped {
			t.Errorf("apply states = %s, %s", items[w.carol].ApplyState, items[w.bob].ApplyState)
		}
		// deciding twice is refused
		if _, err := attest.Decide(e, ur, camp, items[w.carol].ID, "keep", nil); err == nil {
			t.Error("a second decision on one item was accepted")
		}
	})
}

func TestAttestation_OverdueRemovesAndVerifies(t *testing.T) {
	w := newWorld(t)
	var camp string
	w.in(func(c *store.TenantTx) {
		for _, id := range []int64{w.alice, w.bob, w.carol} {
			w.add(c, storetest.Now, w.gA, id)
		}
		e := w.attestEnv(c, storetest.Now)
		if _, err := attest.Put(e, "group", string(w.gA), attest.Settings{IntervalDays: 90, WindowDays: 7, Reviewers: "admins",
			ReminderDays: []int{1, 3}, OverdueAction: "remove_unattested", Enabled: true}); err != nil {
			t.Fatal(err)
		}
		c0, _, err := attest.Start(e, w.gA, attest.StartInput{})
		if err != nil {
			t.Fatal(err)
		}
		camp = c0.ID
		_, items := detail(t, c, camp)
		if _, err := attest.Decide(e, store.UserRef{ID: w.admin}, camp, items[w.bob].ID, "keep", nil); err != nil {
			t.Fatal(err)
		}
	})
	w.in(func(c *store.TenantTx) {
		// before the due date: a reminder, no removal
		sum, err := attest.Sweep(c, storetest.Now.Add(5*24*time.Hour), nil, nil)
		if err != nil || sum.Reminded != 1 || sum.Overdue != 0 {
			t.Fatalf("early Sweep = %+v, %v", sum, err)
		}
		if in := members(t, c, storetest.Now.Add(5*24*time.Hour), w.gA, w.alice, w.carol); !in[w.alice] || !in[w.carol] {
			t.Errorf("members removed before the due date: %v", in)
		}
	})
	late := storetest.Now.Add(8 * 24 * time.Hour)
	w.in(func(c *store.TenantTx) {
		sum, err := attest.Sweep(c, late, nil, nil)
		if err != nil || sum.Overdue != 1 {
			t.Fatalf("Sweep = %+v, %v", sum, err)
		}
		in := members(t, c, late, w.gA, w.alice, w.bob, w.carol)
		if in[w.alice] || !in[w.bob] || in[w.carol] {
			t.Errorf("members after the overdue action = %v; want only bob", in)
		}
		v, items := detail(t, c, camp)
		if v.Status != store.AttestOverdueApplied {
			t.Errorf("status = %s", v.Status)
		}
		for _, id := range []int64{w.alice, w.carol} {
			it := items[id]
			// removed, read back, and recorded as the revoke it is
			if it.ApplyState != store.ApplyApplied || it.Decision == nil || *it.Decision != "revoke" {
				t.Errorf("item of %d = %+v", id, it)
			}
		}
		// the removals are events like any other, and so is the action
		evs, err := c.GrpEventsAfter(0, 1<<40, 1000)
		if err != nil {
			t.Fatal(err)
		}
		var overdue, removed int
		for _, ev := range evs {
			switch ev.Type {
			case events.AttestationOverdueAction:
				overdue++
			case events.MembershipDirectRemoved:
				removed++
			}
		}
		if overdue != 1 || removed != 2 {
			t.Errorf("events: %d overdue actions, %d direct removals; want 1 and 2", overdue, removed)
		}
		// a second pass does nothing more
		if sum, err := attest.Sweep(c, late, nil, nil); err != nil || sum.Overdue != 0 {
			t.Errorf("second Sweep = %+v, %v", sum, err)
		}
	})
}

// An overdue action acts as the user who saved the settings; when that user no
// longer holds the privilege, nothing is removed and the admins are asked.
func TestAttestation_OverdueFailsClosedWithoutAuthority(t *testing.T) {
	w := newWorld(t)
	w.in(func(c *store.TenantTx) {
		w.add(c, storetest.Now, w.gA, w.alice)
		// the settings were saved by a user who holds nothing on the group
		if err := c.SetGrpAttestSettings(&store.GrpAttestSettings{OwnerType: "group", OwnerID: string(w.gA), IntervalDays: 90, WindowDays: 7,
			ReviewerType: "admins", ReminderDays: "[]", OverdueAction: "remove_unattested", Enabled: true, UpdatedBy: w.author.String(),
			UpdatedAt: storetest.Now}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := attest.Start(w.attestEnv(c, storetest.Now), w.gA, attest.StartInput{}); err != nil {
			t.Fatal(err)
		}
		late := storetest.Now.Add(8 * 24 * time.Hour)
		if _, err := attest.Sweep(c, late, nil, nil); err != nil {
			t.Fatal(err)
		}
		if in := members(t, c, late, w.gA, w.alice); !in[w.alice] {
			t.Error("a member was removed by an action whose author lacks the privilege")
		}
		tasks, err := c.GrpTasks(store.GrpTaskFilter{Kind: store.TaskAttestationOverdue})
		if err != nil || len(tasks) != 1 || !strings.Contains(tasks[0].Detail, "privilege_required") {
			t.Errorf("tasks = %v, %v", tasks, err)
		}
	})
}

func TestAttestation_ScheduleStartsWhenDue(t *testing.T) {
	w := newWorld(t)
	w.in(func(c *store.TenantTx) {
		w.add(c, storetest.Now, w.gA, w.alice)
		if _, err := attest.Put(w.attestEnv(c, storetest.Now), "folder", string(w.app), attest.Settings{IntervalDays: 30, WindowDays: 7,
			Reviewers: "admins", ReminderDays: []int{}, OverdueAction: "none", Enabled: true}); err != nil {
			t.Fatal(err)
		}
		if n, err := attest.StartDue(c, storetest.Now.Add(24*time.Hour), nil); err != nil || n != 0 {
			t.Fatalf("StartDue too early = %d, %v", n, err)
		}
		n, err := attest.StartDue(c, storetest.Now.Add(31*24*time.Hour), nil)
		if err != nil || n != 4 { // the four groups of the folder
			t.Fatalf("StartDue = %d, %v; want a campaign for each group of the folder", n, err)
		}
		// a group takes its folder's settings
		v, err := attest.Get(c, "group", string(w.gA))
		if err != nil || !v.Inherited || v.IntervalDays != 30 {
			t.Errorf("inherited settings = %+v, %v", v, err)
		}
		if n, err := attest.StartDue(c, storetest.Now.Add(32*24*time.Hour), nil); err != nil || n != 0 {
			t.Errorf("StartDue again = %d, %v", n, err)
		}
	})
}

func TestDeprov_AffiliationLossCreatesTasks(t *testing.T) {
	w := newWorld(t)
	de := func(c *store.TenantTx, now time.Time) deprov.Env {
		return deprov.Env{Tx: c, Now: now, By: w.admin.String(), TenantAdmin: true, Checker: w.checker(c, now, adminSubject)}
	}
	now := storetest.Now
	w.in(func(c *store.TenantTx) {
		if _, err := deprov.SaveSettings(de(c, now), deprov.Settings{Affiliations: []string{string(w.aff)}, VetoEnabled: true}); err != nil {
			t.Fatal(err)
		}
		for _, id := range []int64{w.alice, w.bob} {
			w.add(c, now, w.aff, id)
			w.add(c, now, w.gA, id)
		}
		w.add(c, now, w.gOther, w.alice)
		// bob is left on notify; alice's folder "other" removes at once
		if _, err := deprov.SetFolder(de(c, now), w.other, store.DeprovAutoNow, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := deprov.Process(de(c, now), 1000); err != nil { // the adds are not losses
			t.Fatal(err)
		}
		if items, _ := c.GrpDeprovItems(store.GrpDeprovFilter{}); len(items) != 0 {
			t.Fatalf("items before any loss = %d", len(items))
		}
		w.remove(c, now, w.aff, w.alice)
		w.remove(c, now, w.aff, w.bob)
		if _, err := deprov.Process(de(c, now), 1000); err != nil {
			t.Fatal(err)
		}
		items, err := c.GrpDeprovItems(store.GrpDeprovFilter{Status: store.DeprovOpen})
		if err != nil {
			t.Fatal(err)
		}
		// alice: folder app (notify) is open; folder other was removed at once (and is resolved)
		byFolder := map[store.FolderID]int{}
		for _, it := range items {
			byFolder[it.FolderID]++
		}
		if len(items) != 2 || byFolder[w.app] != 2 {
			t.Errorf("open items = %d (%v); want alice and bob in app", len(items), byFolder)
		}
		if in := members(t, c, now, w.gOther, w.alice); in[w.alice] {
			t.Error("auto_now left alice in the folder that removes at once")
		}
		done, _ := c.GrpDeprovItems(store.GrpDeprovFilter{Status: store.DeprovRemoved})
		if len(done) != 1 || done[0].FolderID != w.other {
			t.Errorf("removed items = %v", done)
		}
		// an Inbox task per open item, seen by the folder's administrators and not by others
		tasks, err := c.GrpTasks(store.GrpTaskFilter{Status: store.TaskOpen, Kind: store.TaskDeprovisioning})
		if err != nil || len(tasks) != 2 {
			t.Fatalf("tasks = %d, %v", len(tasks), err)
		}
		mine, err := inbox.List(c, w.checker(c, now, adminSubject), store.GrpTaskFilter{Status: store.TaskOpen}, 10, 0)
		if err != nil || len(mine) != 2 {
			t.Errorf("admin's inbox = %d, %v", len(mine), err)
		}
		other, err := inbox.List(c, w.checker(c, now, privs.Subject{Identity: &w.dave}), store.GrpTaskFilter{Status: store.TaskOpen}, 10, 0)
		if err != nil || len(other) != 0 {
			t.Errorf("a stranger's inbox = %d, %v", len(other), err)
		}
		if err := func() error {
			_, err := inbox.Close(c, w.checker(c, now, privs.Subject{Identity: &w.dave}), now, tasks[0].ID, "done", "")
			return err
		}(); err == nil {
			t.Error("a stranger closed the task")
		}

		// the veto rule: no new direct membership for a deprovisioned identity, unless overridden with a reason
		_, err = w.model(c, now).AddMember(w.gB, model.MemberInput{Identity: &w.alice})
		var me *model.Error
		if !errors.As(err, &me) || me.Code != "vetoed" {
			t.Errorf("add of a deprovisioned identity = %v, want vetoed", err)
		}
		over := w.model(c, now)
		over.VetoOverride = "returning contractor, approved by HR"
		if _, err := over.AddMember(w.gB, model.MemberInput{Identity: &w.alice}); err != nil {
			t.Errorf("overridden add = %v", err)
		}
		// regaining an affiliation lifts the veto
		w.add(c, now, w.aff, w.bob)
		if _, err := deprov.Process(de(c, now), 1000); err != nil {
			t.Fatal(err)
		}
		if _, err := w.model(c, now).AddMember(w.gB, model.MemberInput{Identity: &w.bob}); err != nil {
			t.Errorf("add after the affiliation came back = %v", err)
		}
	})
}

func TestDeprov_AutoAfterAndManualResolve(t *testing.T) {
	w := newWorld(t)
	de := func(c *store.TenantTx, now time.Time) deprov.Env {
		return deprov.Env{Tx: c, Now: now, By: w.admin.String(), TenantAdmin: true, Checker: w.checker(c, now, adminSubject)}
	}
	now := storetest.Now
	w.in(func(c *store.TenantTx) {
		if _, err := deprov.SaveSettings(de(c, now), deprov.Settings{Affiliations: []string{string(w.aff)}, VetoEnabled: true}); err != nil {
			t.Fatal(err)
		}
		if _, err := deprov.SetFolder(de(c, now), w.app, store.DeprovAutoAfter, 10); err != nil {
			t.Fatal(err)
		}
		for _, id := range []int64{w.alice, w.carol} {
			w.add(c, now, w.aff, id)
			w.add(c, now, w.gA, id)
			w.remove(c, now, w.aff, id)
		}
		if _, err := deprov.Process(de(c, now), 1000); err != nil {
			t.Fatal(err)
		}
		if n, err := deprov.Sweep(de(c, now.Add(9*24*time.Hour))); err != nil || n != 0 {
			t.Errorf("Sweep before the delay = %d, %v", n, err)
		}
		// carol's item is dismissed by hand, with a reason; she keeps her membership
		items, _ := c.GrpDeprovItems(store.GrpDeprovFilter{Status: store.DeprovOpen, Identity: w.carol})
		if _, err := deprov.Resolve(de(c, now), items[0].ID, "dismiss", ""); err == nil {
			t.Error("dismissed without a reason")
		}
		if _, err := deprov.Resolve(de(c, now), items[0].ID, "dismiss", "on leave, returns in May"); err != nil {
			t.Fatal(err)
		}
		late := now.Add(11 * 24 * time.Hour)
		if _, err := deprov.Sweep(de(c, late)); err != nil {
			t.Fatal(err)
		}
		in := members(t, c, late, w.gA, w.alice, w.carol)
		if in[w.alice] || !in[w.carol] {
			t.Errorf("members after the delay = %v; want carol only", in)
		}
	})
}

// A rule can open an Inbox task and start a micro-certification (GR-13 left
// both as action_unavailable).
func TestRules_InboxAndMicroCertification(t *testing.T) {
	w := newWorld(t)
	renv := func(c *store.TenantTx) rules.Env {
		return rules.Env{Tx: c, Now: storetest.Now, By: w.admin.String(), Checker: w.checker(c, storetest.Now, adminSubject), RT: w.rt}
	}
	w.in(func(c *store.TenantTx) {
		for _, spec := range []rules.Spec{
			{OwnerType: "group", OwnerID: string(w.gA), Trigger: rules.TrigDirectAdded, Action: rules.ActOpenInboxTask, Enabled: true,
				Params: rules.Params{Subject: "Check the new member", Message: "see the ticket"}},
			{OwnerType: "group", OwnerID: string(w.gA), Trigger: rules.TrigDirectAdded, Action: rules.ActMicroCertifyNew, Enabled: true,
				Params: rules.Params{Days: 5}},
		} {
			if _, _, err := rules.Create(renv(c), spec); err != nil {
				t.Fatal(err)
			}
		}
		w.add(c, storetest.Now, w.gA, w.bob)
		if n, err := w.rt.Process(c, storetest.Now, 500); err != nil || n == 0 {
			t.Fatalf("Process = %d, %v", n, err)
		}
		tasks, err := c.GrpTasks(store.GrpTaskFilter{Status: store.TaskOpen})
		if err != nil {
			t.Fatal(err)
		}
		kinds := map[string]int{}
		for _, tk := range tasks {
			kinds[tk.Kind]++
		}
		if kinds[store.TaskRule] != 1 || kinds[store.TaskMicroCertification] != 1 {
			t.Errorf("tasks by kind = %v", kinds)
		}
		camps, err := c.GrpAttestCampaigns(store.GrpAttestFilter{Group: w.gA})
		if err != nil || len(camps) != 1 || camps[0].Kind != store.AttestMicro || camps[0].PopulationCount != 1 {
			t.Fatalf("campaigns = %v, %v", camps, err)
		}
		if got := camps[0].DueAt.Sub(camps[0].StartedAt); got != 5*24*time.Hour {
			t.Errorf("micro-certification window = %v, want 5 days", got)
		}
		// firing again for the same event finds the work already open
		if _, _, err := attest.Start(w.attestEnv(c, storetest.Now), w.gA, attest.StartInput{Kind: store.AttestMicro, Identity: w.bob}); err != nil {
			t.Errorf("repeat micro Start = %v", err)
		}
		if camps, _ := c.GrpAttestCampaigns(store.GrpAttestFilter{Group: w.gA}); len(camps) != 1 {
			t.Errorf("campaigns after a repeat = %d, want 1", len(camps))
		}
	})
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "reports", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path) // #nosec G304 -- a fixed test path
	if err != nil {
		t.Fatalf("%v (run with -update to write the golden files)", err)
	}
	if string(want) != got {
		t.Errorf("%s differs from its golden file:\n--- got\n%s--- want\n%s", name, got, want)
	}
}

func TestReports_Golden(t *testing.T) {
	w := newWorld(t)
	now := storetest.Now
	w.in(func(c *store.TenantTx) {
		w.add(c, now, w.gA, w.alice)
		w.add(c, now, w.gA, w.bob)
		if _, err := w.model(c, now).AddMember(w.gB, model.MemberInput{Group: w.gA}); err != nil {
			t.Fatal(err)
		}
		w.add(c, now, w.gB, w.carol)
		pe := privs.Env{Tx: c, Now: now, TenantAdmin: true}
		if _, _, err := privs.Grant(pe, privs.GrantInput{Object: privs.GroupObject(w.gA), Privilege: privs.Admin, Holder: privs.IdentityHolder(w.ivan)}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := privs.Grant(pe, privs.GrantInput{Object: privs.FolderObject(w.app), Privilege: privs.StemView, Holder: privs.Everyone()}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := attest.Start(w.attestEnv(c, now), w.gA, attest.StartInput{}); err != nil {
			t.Fatal(err)
		}
		// a policy group with direct members, made at the store level (policy groups are GR-9)
		ref := `{"path":"policies/test.cedar"}`
		pg := &store.NativeGroup{FolderID: w.app, Extension: "pol", DisplayExtension: "pol", Name: "app:pol", DisplayName: "app:pol",
			Definition: store.DefinitionPolicy, PolicyRef: &ref, CreatedAt: now}
		if err := c.InsertGrpGroup(pg); err != nil {
			t.Fatal(err)
		}
		list := store.MembersListID(c.Tenant())
		for _, id := range []int64{w.alice, w.bob, w.carol} {
			id := id
			if err := c.InsertGrpDirect(&store.DirectMembership{GroupID: pg.ID, ListID: list, MemberType: store.MemberIdentity,
				MemberIdentity: &id, Source: "test", CreatedAt: now}); err != nil {
				t.Fatal(err)
			}
		}
		de := deprov.Env{Tx: c, Now: now, By: w.admin.String(), Checker: w.checker(c, now, adminSubject)}
		if _, err := deprov.SaveSettings(de, deprov.Settings{Affiliations: []string{string(w.aff)}, VetoEnabled: true}); err != nil {
			t.Fatal(err)
		}
		w.add(c, now, w.aff, w.dave)
		w.add(c, now, w.gOther, w.dave)
		w.remove(c, now, w.aff, w.dave)
		if _, err := deprov.Process(de, 1000); err != nil {
			t.Fatal(err)
		}

		env := renv{Tx: c, Now: now.Add(48 * time.Hour), Checker: w.checker(c, now, adminSubject)}
		cases := []struct {
			name, kind string
			p          reports.Params
		}{
			{"group_members_effective", reports.GroupMembers, reports.Params{Group: string(w.gB)}},
			{"group_members_direct", reports.GroupMembers, reports.Params{Group: string(w.gA), Filter: "direct"}},
			{"groups_of_person", reports.GroupsOfPerson, reports.Params{Identity: w.alice}},
			{"folder_privileges", reports.FolderPrivileges, reports.Params{Folder: string(w.app)}},
			{"groups_without_owners", reports.GroupsWithoutOwners, reports.Params{}},
			{"policy_direct_exceptions", reports.PolicyDirectMembers, reports.Params{Limit: 2}},
			{"attestation_status", reports.AttestationStatus, reports.Params{}},
			{"deprovisioning_backlog", reports.DeprovisioningBlog, reports.Params{}},
		}
		for _, tc := range cases {
			res, err := env.Run2(tc.kind, tc.p)
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			csv, err := res.CSV()
			if err != nil {
				t.Fatal(err)
			}
			golden(t, tc.name+".csv", csv)
			js, err := res.JSON(env.Now)
			if err != nil {
				t.Fatal(err)
			}
			golden(t, tc.name+".json", js)
		}
	})
}

func TestReports_NeverShowMoreThanTheSubjectMaySee(t *testing.T) {
	w := newWorld(t)
	now := storetest.Now
	w.in(func(c *store.TenantTx) {
		w.add(c, now, w.gA, w.alice)
		w.add(c, now, w.gOther, w.alice)
		pe := privs.Env{Tx: c, Now: now, TenantAdmin: true}
		// bob may view and read group a, and nothing else
		for _, p := range []privs.Privilege{privs.View, privs.Read} {
			if _, _, err := privs.Grant(pe, privs.GrantInput{Object: privs.GroupObject(w.gA), Privilege: p, Holder: privs.IdentityHolder(w.bob)}); err != nil {
				t.Fatal(err)
			}
		}
		bob := w.checker(c, now, privs.Subject{Identity: &w.bob})
		env := renv{Tx: c, Now: now, Checker: bob}
		res, err := env.Run2(reports.GroupsOfPerson, reports.Params{Identity: w.alice})
		if err != nil || len(res.Rows) != 1 || res.Rows[0][0] != "app:a" {
			t.Errorf("groups of alice for bob = %v, %v; want app:a only", res, err)
		}
		if _, err := env.Run2(reports.GroupMembers, reports.Params{Group: string(w.gOther)}); err == nil {
			t.Error("members of a group bob may not read were reported")
		}
		if _, err := env.Run2(reports.FolderPrivileges, reports.Params{Folder: string(w.app)}); err == nil {
			t.Error("a folder's privileges were reported to someone without stem_admin")
		}
		if res, err := env.Run2(reports.GroupsWithoutOwners, reports.Params{}); err != nil || len(res.Rows) != 1 {
			t.Errorf("groups without owners for bob = %v, %v; want the one group he can view", res, err)
		}
		if _, err := env.Run2(reports.LoaderFailsafeLog, reports.Params{}); err == nil {
			t.Error("a report whose data does not exist yet ran")
		}
		if _, err := env.Run2(reports.GroupMembers, reports.Params{Group: string(w.gA), Identity: 3}); err == nil {
			t.Error("a parameter the report does not take was accepted")
		}

		// a saved report runs with the privileges its owner holds when it runs
		own := reports.SaveEnv{Tx: c, Now: now, By: w.author.String(), Checker: w.checker(c, now, privs.Subject{Identity: &w.ivan})}
		if _, err := reports.Save(own, reports.SaveInput{Name: "x", Kind: reports.GroupMembers, Params: reports.Params{Group: string(w.gA)}}); err == nil {
			t.Error("a report was saved by someone who may not run it")
		}
		admin := reports.SaveEnv{Tx: c, Now: now, By: w.admin.String(), Checker: w.checker(c, now, adminSubject)}
		rep, err := reports.Save(admin, reports.SaveInput{Name: "daily", Kind: reports.GroupMembers, Params: reports.Params{Group: string(w.gA)},
			Schedule: "daily"})
		if err != nil {
			t.Fatal(err)
		}
		n, err := reports.RunDue(c, now.Add(25*time.Hour), nil, nil, nil)
		if err != nil || n != 1 {
			t.Fatalf("RunDue = %d, %v", n, err)
		}
		runs, _ := c.GrpReportRuns(rep.ID, 10)
		if len(runs) != 1 || runs[0].Status != "ok" || runs[0].RowCount != 1 {
			t.Fatalf("runs = %+v", runs)
		}
		// only the user the run was made for, or a tenant admin, reads it back
		if _, _, err := reports.ReadRun(c, runs[0].ID, w.author.String(), false); err == nil {
			t.Error("another user read a run")
		}
		if _, _, err := reports.ReadRun(c, runs[0].ID, w.admin.String(), false); err != nil {
			t.Errorf("the owner could not read the run: %v", err)
		}
		// the owner loses their account: the next run fails and carries no data
		if err := c.DisableUser(w.admin, "left", now); err != nil {
			t.Fatal(err)
		}
		if _, err := reports.RunDue(c, now.Add(60*time.Hour), nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		runs, _ = c.GrpReportRuns(rep.ID, 10)
		if runs[0].Status != "failed" || runs[0].Content != "" {
			t.Errorf("run of a disabled owner = %+v", runs[0])
		}
	})
}

func TestReports_CSVDefusesFormulas(t *testing.T) {
	r := &reports.Result{Kind: "x", Columns: []string{"a", "b"}, Rows: [][]string{{"=1+1", "ok"}, {"@SUM(A1)", "-5"}, {"plain", "a,b"}}}
	got, err := r.CSV()
	if err != nil {
		t.Fatal(err)
	}
	want := "a,b\n'=1+1,ok\n'@SUM(A1),'-5\nplain,\"a,b\"\n"
	if got != want {
		t.Errorf("CSV = %q, want %q", got, want)
	}
}

func TestVisualization_RespectsView(t *testing.T) {
	w := newWorld(t)
	now := storetest.Now
	w.in(func(c *store.TenantTx) {
		// a contains b contains c; bob may view a and c, not b
		if _, err := w.model(c, now).AddMember(w.gA, model.MemberInput{Group: w.gB}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.model(c, now).AddMember(w.gB, model.MemberInput{Group: w.gC}); err != nil {
			t.Fatal(err)
		}
		w.add(c, now, w.gC, w.alice)
		pe := privs.Env{Tx: c, Now: now, TenantAdmin: true}
		for _, g := range []store.GroupID{w.gA, w.gC} {
			if _, _, err := privs.Grant(pe, privs.GrantInput{Object: privs.GroupObject(g), Privilege: privs.View, Holder: privs.IdentityHolder(w.bob)}); err != nil {
				t.Fatal(err)
			}
		}
		names := func(g *viz.Graph) []string {
			var out []string
			for _, n := range g.Nodes {
				out = append(out, n.Name)
			}
			return out
		}
		full, err := viz.GroupGraph(c, w.checker(c, now, adminSubject), w.gA, 0, 3)
		if err != nil || len(full.Nodes) != 3 || len(full.Edges) != 2 {
			t.Fatalf("admin's graph = %v, %v", full, err)
		}
		bob := w.checker(c, now, privs.Subject{Identity: &w.bob})
		g, err := viz.GroupGraph(c, bob, w.gA, 0, 3)
		if err != nil {
			t.Fatal(err)
		}
		// b is hidden, and nothing is walked through it: c does not appear either
		if got := names(g); len(got) != 1 || got[0] != "app:a" || len(g.Edges) != 0 {
			t.Errorf("bob's graph = %v with %d edges; want app:a alone", got, len(g.Edges))
		}
		up, err := viz.GroupGraph(c, bob, w.gC, 3, 0)
		if err != nil || len(up.Nodes) != 1 || up.Nodes[0].Name != "app:c" {
			t.Errorf("bob's view upward from c = %v, %v", up, err)
		}
		// a group the subject may not view is not disclosed at all
		if _, err := viz.GroupGraph(c, bob, w.gB, 1, 1); err == nil {
			t.Error("the graph of a group bob cannot view was returned")
		}
		var ge *gov.Error
		if _, err := viz.GroupGraph(c, bob, w.gA, 11, 0); !errors.As(err, &ge) {
			t.Errorf("too many levels = %v", err)
		}
		// the person graph shows only the groups the viewer may see
		pg, err := viz.PersonGraph(c, bob, w.alice, 3, now)
		if err != nil {
			t.Fatal(err)
		}
		if got := names(pg); len(got) != 2 { // alice and app:c
			t.Errorf("alice's graph for bob = %v", got)
		}
		pa, err := viz.PersonGraph(c, w.checker(c, now, adminSubject), w.alice, 3, now)
		if err != nil || len(pa.Nodes) != 4 { // alice, c, b, a
			t.Errorf("alice's graph for admin = %v, %v", pa, err)
		}
	})
}
