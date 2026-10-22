package deleteguard_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/deleteguard"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func setSource(t *testing.T, f *storetest.Fixture, tn storetest.Tenant, p deleteguard.SourcePolicy) {
	t.Helper()
	in(t, f, tn, func(tx *store.TenantTx) error { return deleteguard.SetSource(tx, p, nil, now) })
}

func fp(v float64) *float64 { return &v }
func bp(v bool) *bool       { return &v }

func loaderReq(id string, n int) deleteguard.Request {
	return deleteguard.Request{Category: deleteguard.CatMembers, Items: items(n, "m"), Source: deleteguard.SourceLoader, SourceID: id,
		Correlation: "run:" + id}
}

func TestSourceOverrideReplacesTheCategoryThresholdForThatSourceOnly(t *testing.T) {
	f := storetest.TwoTenants(t)
	// members default to 500 or 10% an hour; loader L1 is held to 3, loader L2 is loosened to 1000
	setSource(t, f, f.A, deleteguard.SourcePolicy{Kind: "loader", SourceID: "L1", Category: deleteguard.CatMembers, Mode: deleteguard.ModeHoldExcess,
		MaxCount: ten(3), WindowMinutes: 60})
	setSource(t, f, f.A, deleteguard.SourcePolicy{Kind: "loader", SourceID: "L2", Category: deleteguard.CatMembers, Mode: deleteguard.ModeHoldExcess,
		MaxCount: ten(1000), WindowMinutes: 60})
	in(t, f, f.A, func(tx *store.TenantTx) error {
		d, err := deleteguard.Admit(tx, now, loaderReq("L1", 7))
		if err != nil {
			return err
		}
		if d.NApplied() != 3 || d.NHeld() != 4 || *d.Limit != 3 {
			t.Errorf("L1: applied %d held %d limit %v", d.NApplied(), d.NHeld(), d.Limit)
		}
		// the source's own window is used up: a second run of L1 applies none
		d, err = deleteguard.Admit(tx, now.Add(time.Minute), loaderReq("L1", 2))
		if err != nil {
			return err
		}
		if d.NApplied() != 0 || d.NHeld() != 2 {
			t.Errorf("L1 again: applied %d held %d", d.NApplied(), d.NHeld())
		}
		// L2 is not held back by L1's window, and may exceed the category's threshold
		d, err = deleteguard.Admit(tx, now, loaderReq("L2", 700))
		if err != nil {
			return err
		}
		if d.NApplied() != 700 || d.NHeld() != 0 {
			t.Errorf("L2: applied %d held %d", d.NApplied(), d.NHeld())
		}
		// a loader with no override is under the category's setting (min of 500 and the percent floor)
		d, err = deleteguard.Admit(tx, now, loaderReq("L3", 600))
		if err != nil {
			return err
		}
		if d.NApplied() == 600 || d.NHeld() == 0 {
			t.Errorf("L3 (no override): applied %d held %d", d.NApplied(), d.NHeld())
		}
		// the hold says which source's setting was in force
		h, err := deleteguard.Load(tx, now, d.HoldID)
		if err != nil {
			return err
		}
		if strings.Contains(h.Reason, `"source_override":true`) {
			t.Errorf("L3's hold claims an override: %s", h.Reason)
		}
		return nil
	})
	in(t, f, f.A, func(tx *store.TenantTx) error {
		// the tenant ledger counts what the sources applied too
		u, err := deleteguard.UsageOf(tx, now.Add(2*time.Minute))
		if err != nil {
			return err
		}
		for _, x := range u {
			if x.Category == deleteguard.CatMembers && x.Used < 703 {
				t.Errorf("tenant window used %d, want at least 703", x.Used)
			}
		}
		return nil
	})
	// tenant B has no such override
	in(t, f, f.B, func(tx *store.TenantTx) error {
		d, err := deleteguard.Admit(tx, now, loaderReq("L1", 5))
		if err != nil {
			return err
		}
		if d.NApplied() != 5 {
			t.Errorf("tenant B's L1 applied %d, want 5: A's override leaked", d.NApplied())
		}
		return nil
	})
}

func TestSourceDrivenDefaultIsHoldAllUnlessTheSourceSetsAMode(t *testing.T) {
	f := storetest.TwoTenants(t)
	setSource(t, f, f.A, deleteguard.SourcePolicy{Kind: "connection", SourceID: "c-explicit", Category: deleteguard.CatAccounts,
		Mode: deleteguard.ModeHoldExcess, MaxCount: ten(2), WindowMinutes: 60})
	in(t, f, f.A, func(tx *store.TenantTx) error {
		req := func(id string) deleteguard.Request {
			return deleteguard.Request{Category: deleteguard.CatAccounts, Items: items(5, "a"), Source: deleteguard.SourceConnector, SourceID: id,
				SourceDriven: true, Correlation: "sync:" + id}
		}
		// the default limit is 200, so 5 pass; shrink the tenant's to see hold_all
		if err := deleteguard.Set(tx, deleteguard.Policy{Category: deleteguard.CatAccounts, MaxCount: ten(3), WindowMinutes: 60, Mode: deleteguard.ModeHoldExcess}, nil, now); err != nil {
			return err
		}
		// a tenant-set mode is explicit: hold_excess applies the part that fits
		d, err := deleteguard.Admit(tx, now, req("c-plain"))
		if err != nil {
			return err
		}
		if d.NApplied() != 3 || d.NHeld() != 2 {
			t.Errorf("tenant-set hold_excess: applied %d held %d", d.NApplied(), d.NHeld())
		}
		d, err = deleteguard.Admit(tx, now, req("c-explicit"))
		if err != nil {
			return err
		}
		if d.NApplied() != 2 || d.NHeld() != 3 || d.Mode != deleteguard.ModeHoldExcess {
			t.Errorf("explicit source override: applied %d held %d mode %s", d.NApplied(), d.NHeld(), d.Mode)
		}
		return nil
	})
}

func TestFeedChecksPerSource(t *testing.T) {
	f := storetest.TwoTenants(t)
	setSource(t, f, f.A, deleteguard.SourcePolicy{Kind: "connection", SourceID: "loose", Category: deleteguard.CatIdentities, FeedDropPercent: fp(60)})
	setSource(t, f, f.A, deleteguard.SourcePolicy{Kind: "connection", SourceID: "noempty", Category: deleteguard.CatIdentities,
		FeedDropPercent: fp(100), FeedEmptyCheck: bp(false)})
	setSource(t, f, f.A, deleteguard.SourcePolicy{Kind: "connection", SourceID: "strict", Category: deleteguard.CatIdentities, FeedDropPercent: fp(5)})
	cases := []struct {
		name      string
		ref       deleteguard.SourceRef
		cat       string
		prev, now int
		partial   string
		flagged   bool
	}{
		{"default 20: a 30% drop is flagged", deleteguard.SourceRef{Kind: "connection", ID: "plain"}, deleteguard.CatIdentities, 100, 70, "", true},
		{"default 20: a 15% drop passes", deleteguard.SourceRef{Kind: "connection", ID: "plain"}, deleteguard.CatIdentities, 100, 85, "", false},
		{"no source: defaults", deleteguard.SourceRef{}, deleteguard.CatIdentities, 100, 70, "", true},
		{"limit 60: the 30% drop passes", deleteguard.SourceRef{Kind: "connection", ID: "loose"}, deleteguard.CatIdentities, 100, 70, "", false},
		{"limit 60: a 70% drop is flagged", deleteguard.SourceRef{Kind: "connection", ID: "loose"}, deleteguard.CatIdentities, 100, 30, "", true},
		{"limit 5: a 10% drop is flagged", deleteguard.SourceRef{Kind: "connection", ID: "strict"}, deleteguard.CatIdentities, 100, 90, "", true},
		{"empty feed is flagged by default", deleteguard.SourceRef{Kind: "connection", ID: "plain"}, deleteguard.CatIdentities, 10, 0, "", true},
		{"empty feed passes with the check off and drop 100", deleteguard.SourceRef{Kind: "connection", ID: "noempty"}, deleteguard.CatIdentities, 10, 0, "", false},
		{"empty feed with the check off is judged by the percent", deleteguard.SourceRef{Kind: "connection", ID: "strict"}, deleteguard.CatIdentities, 10, 0, "", true},
		{"a partial read is flagged whatever the settings", deleteguard.SourceRef{Kind: "connection", ID: "noempty"}, deleteguard.CatIdentities, 10, 10, "timeout", true},
		{"the setting is per category", deleteguard.SourceRef{Kind: "connection", ID: "loose"}, deleteguard.CatAccounts, 100, 70, "", true},
		{"no history, nothing to compare", deleteguard.SourceRef{Kind: "connection", ID: "plain"}, deleteguard.CatIdentities, 0, 0, "", false},
	}
	in(t, f, f.A, func(tx *store.TenantTx) error {
		for _, c := range cases {
			got, err := deleteguard.CheckFeed(tx, c.ref, c.cat, c.prev, c.now, c.partial)
			if err != nil {
				return err
			}
			if (len(got) > 0) != c.flagged {
				t.Errorf("%s: sanity %v", c.name, got)
			}
		}
		return nil
	})
	// another tenant's source of the same id is on the defaults
	in(t, f, f.B, func(tx *store.TenantTx) error {
		got, err := deleteguard.CheckFeed(tx, deleteguard.SourceRef{Kind: "connection", ID: "loose"}, deleteguard.CatIdentities, 100, 70, "")
		if err != nil || len(got) == 0 {
			t.Errorf("tenant B sees A's feed setting: %v %v", got, err)
		}
		return nil
	})
}

func TestFeedSettingsDecideTheHold(t *testing.T) {
	f := storetest.TwoTenants(t)
	setSource(t, f, f.A, deleteguard.SourcePolicy{Kind: "connection", SourceID: "c1", Category: deleteguard.CatIdentities, FeedDropPercent: fp(50)})
	in(t, f, f.A, func(tx *store.TenantTx) error {
		for _, tc := range []struct {
			id   string
			now  int
			held bool
		}{{"c1", 70, false}, {"c2", 70, true}} {
			ref := deleteguard.SourceRef{Kind: "connection", ID: tc.id}
			sanity, err := deleteguard.CheckFeed(tx, ref, deleteguard.CatIdentities, 100, tc.now, "")
			if err != nil {
				return err
			}
			d, err := deleteguard.AdmitWith(tx, now, deleteguard.Request{Category: deleteguard.CatIdentities, Items: items(2, tc.id),
				Source: deleteguard.SourceConnector, SourceID: tc.id, SourceDriven: true, Sanity: sanity, Correlation: "sync:" + tc.id})
			if err != nil {
				return err
			}
			if (d.NHeld() > 0) != tc.held {
				t.Errorf("%s: held %d, want held=%v", tc.id, d.NHeld(), tc.held)
			}
		}
		return nil
	})
}

func TestPreviousCountIsPerSource(t *testing.T) {
	f := storetest.TwoTenants(t)
	a, b := deleteguard.SourceRef{Kind: "connection", ID: "A"}, deleteguard.SourceRef{Kind: "connection", ID: "B"}
	in(t, f, f.A, func(tx *store.TenantTx) error {
		if n, err := deleteguard.PreviousCount(tx, a, deleteguard.CatIdentities, 999); err != nil || n != 999 {
			t.Errorf("no history: %d %v, want the fallback", n, err)
		}
		if err := deleteguard.RecordGoodRun(tx, now, a, deleteguard.CatIdentities, 40); err != nil {
			return err
		}
		if err := deleteguard.RecordGoodRun(tx, now, b, deleteguard.CatIdentities, 900); err != nil {
			return err
		}
		if err := deleteguard.RecordGoodRun(tx, now.Add(time.Hour), a, deleteguard.CatIdentities, 42); err != nil {
			return err
		}
		for ref, want := range map[deleteguard.SourceRef]int{a: 42, b: 900} {
			if n, err := deleteguard.PreviousCount(tx, ref, deleteguard.CatIdentities, 999); err != nil || n != want {
				t.Errorf("%v: %d %v, want %d", ref, n, err, want)
			}
		}
		// another category of the same source has no history
		if n, _ := deleteguard.PreviousCount(tx, a, deleteguard.CatAccounts, 7); n != 7 {
			t.Errorf("accounts basis = %d, want the fallback", n)
		}
		// a request with no source names none to keep
		if err := deleteguard.RecordGoodRun(tx, now, deleteguard.SourceRef{}, deleteguard.CatIdentities, 5); err != nil {
			t.Errorf("RecordGoodRun with no source: %v", err)
		}
		return nil
	})
}

func TestScopedSourceUsesItsOwnSettings(t *testing.T) {
	f := storetest.TwoTenants(t)
	setSource(t, f, f.A, deleteguard.SourcePolicy{Kind: "vms_source", SourceID: "V1", Category: deleteguard.CatIdentities,
		Mode: deleteguard.ModeHoldExcess, MaxCount: ten(2), WindowMinutes: 60})
	in(t, f, f.A, func(tx *store.TenantTx) error {
		leaver := func(n int) *deleteguard.Decision {
			d, err := deleteguard.AdmitWith(tx, now, deleteguard.Request{Category: deleteguard.CatIdentities, Items: items(n, fmt.Sprint(n)),
				Source: deleteguard.SourceLifecycle, SourceID: "leaver", SourceDriven: true, Correlation: "leavers"})
			if err != nil {
				t.Fatal(err)
			}
			return d
		}
		if d := leaver(4); d.NApplied() != 4 {
			t.Errorf("unscoped: applied %d, want 4 (the tenant default is 50)", d.NApplied())
		}
		restore := deleteguard.ScopeSource(tx, deleteguard.SourceRef{Kind: "vms_source", ID: "V1"})
		if d := leaver(5); d.NApplied() != 2 || d.NHeld() != 3 {
			t.Errorf("scoped to V1: applied %d held %d, want 2 and 3", d.NApplied(), d.NHeld())
		}
		restore()
		if deleteguard.ScopeOf(tx).Valid() {
			t.Error("the scope outlived restore")
		}
		return nil
	})
}

func TestSourceLoosening(t *testing.T) {
	tenant := deleteguard.Defaults()[deleteguard.CatMembers]
	ov := func(mode string, count int, window int) *deleteguard.SourcePolicy {
		return &deleteguard.SourcePolicy{Kind: "loader", SourceID: "L", Category: deleteguard.CatMembers, Mode: mode, MaxCount: ten(count), WindowMinutes: window}
	}
	res := func(o *deleteguard.SourcePolicy) deleteguard.Resolved { return deleteguard.Resolve(tenant, o, true) }
	feed := func(drop float64, empty bool) *deleteguard.SourcePolicy {
		return &deleteguard.SourcePolicy{Kind: "loader", SourceID: "L", Category: deleteguard.CatMembers, FeedDropPercent: fp(drop), FeedEmptyCheck: bp(empty)}
	}
	cases := []struct {
		name     string
		cur, nxt *deleteguard.SourcePolicy
		loosens  bool
	}{
		{"none to a lower limit with hold_all tightens", nil, ov("hold_all", 5, 60), false},
		{"none to hold_excess above the category's limit loosens (a source-driven default is hold_all)", nil, ov("hold_excess", 5000, 60), true},
		{"none to hold_excess is a weaker mode than the source-driven default", nil, ov("hold_excess", 1, 60), true},
		{"none to hold_all with a low limit tightens", nil, ov("hold_all", 5, 60), false},
		{"off loosens", ov("hold_all", 5, 60), ov("off", 5, 60), true},
		{"a higher count loosens", ov("hold_all", 5, 60), ov("hold_all", 6, 60), true},
		{"a longer window for the same count tightens", ov("hold_all", 5, 60), ov("hold_all", 5, 120), false},
		{"removing a tight override loosens", ov("hold_all", 5, 60), nil, true},
		{"removing an override that was looser tightens", ov("hold_all", 5000, 60), nil, false},
		{"a higher drop percent loosens", feed(20, true), feed(30, true), true},
		{"a lower drop percent tightens", feed(20, true), feed(10, true), false},
		{"empty check off loosens", feed(20, true), feed(20, false), true},
		{"empty check on tightens", feed(20, false), feed(20, true), false},
		{"default to 20 and on changes nothing", nil, feed(20, true), false},
		{"default to a higher drop loosens", nil, feed(25, true), true},
	}
	for _, c := range cases {
		if got := deleteguard.LoosensResolved(res(c.cur), res(c.nxt), 1000); got != c.loosens {
			t.Errorf("%s: loosens = %v, want %v", c.name, got, c.loosens)
		}
	}
}

func TestSourcePolicyCheck(t *testing.T) {
	ok := deleteguard.SourcePolicy{Kind: "connection", SourceID: "c", Category: deleteguard.CatAccounts, Mode: "hold_all", MaxCount: ten(3), WindowMinutes: 60}
	bad := map[string]func(p *deleteguard.SourcePolicy){
		"kind":            func(p *deleteguard.SourcePolicy) { p.Kind = "tenant" },
		"id":              func(p *deleteguard.SourcePolicy) { p.SourceID = "" },
		"category":        func(p *deleteguard.SourcePolicy) { p.Category = "nope" },
		"mode":            func(p *deleteguard.SourcePolicy) { p.Mode = "sometimes" },
		"no limit":        func(p *deleteguard.SourcePolicy) { p.MaxCount = nil },
		"window":          func(p *deleteguard.SourcePolicy) { p.WindowMinutes = 0 },
		"thresholds only": func(p *deleteguard.SourcePolicy) { p.Mode = "" },
		"drop over":       func(p *deleteguard.SourcePolicy) { p.FeedDropPercent = fp(101) },
		"drop under":      func(p *deleteguard.SourcePolicy) { p.FeedDropPercent = fp(-1) },
		"nothing set": func(p *deleteguard.SourcePolicy) {
			*p = deleteguard.SourcePolicy{Kind: "connection", SourceID: "c", Category: deleteguard.CatAccounts}
		},
	}
	if err := ok.Check(); err != nil {
		t.Fatalf("valid override refused: %v", err)
	}
	feedOnly := deleteguard.SourcePolicy{Kind: "scim_client", SourceID: "c", Category: deleteguard.CatGroups, FeedEmptyCheck: bp(false)}
	if err := feedOnly.Check(); err != nil {
		t.Errorf("a feed-only override is refused: %v", err)
	}
	for name, mut := range bad {
		p := ok
		mut(&p)
		if err := p.Check(); err == nil {
			t.Errorf("%s: accepted %+v", name, p)
		}
	}
}

// A hold opens a deletion_held Inbox task, and the task closes with the hold: done when it is
// released, dismissed when it is discarded or expires.
func TestHoldOpensAnInboxTaskThatFollowsTheHold(t *testing.T) {
	f := storetest.TwoTenants(t)
	setPolicy(t, f, f.A, deleteguard.Policy{Category: deleteguard.CatGroups, MaxCount: ten(1), WindowMinutes: 60, Mode: deleteguard.ModeHoldExcess})
	ap := deleteguard.Appliers{"group_delete": func(_ *store.TenantTx, _ time.Time, _ *store.DeletionHoldItem) (string, string, error) {
		return deleteguard.ItemReleased, "", nil
	}}
	hold := func(tx *store.TenantTx, at time.Time, actor string) string {
		d, err := deleteguard.Admit(tx, at, deleteguard.Request{Category: deleteguard.CatGroups, Items: items(3, "g"), Actor: actor, Source: deleteguard.SourceUser})
		if err != nil || d.HoldID == "" {
			t.Fatalf("no hold: %v", err)
		}
		return d.HoldID
	}
	taskOf := func(tx *store.TenantTx, holdID string) *store.GrpTask {
		ts, err := tx.GrpTasks(store.GrpTaskFilter{Kind: store.TaskDeletionHeld, ObjectType: "deletion_hold", ObjectID: holdID, Limit: 10})
		if err != nil || len(ts) != 1 {
			t.Fatalf("tasks of %s: %v %v", holdID, ts, err)
		}
		return ts[0]
	}
	var released, discarded, expired string
	in(t, f, f.A, func(tx *store.TenantTx) error {
		released = hold(tx, now, "alice")
		if tk := taskOf(tx, released); tk.Status != "open" || tk.DedupeKey == nil || tk.DueAt == nil {
			t.Errorf("task %+v", tk)
		}
		// items joining the same hold do not open another task
		d, err := deleteguard.Admit(tx, now.Add(time.Second), deleteguard.Request{Category: deleteguard.CatGroups, Items: items(2, "z"),
			Source: deleteguard.SourceUser, Correlation: "x"})
		if err != nil {
			return err
		}
		discarded = d.HoldID
		taskOf(tx, discarded)
		return nil
	})
	in(t, f, f.A, func(tx *store.TenantTx) error {
		if _, err := deleteguard.Release(tx, now, released, "bob", nil, ap); err != nil {
			return err
		}
		if tk := taskOf(tx, released); tk.Status != "done" || tk.ClosedAt == nil {
			t.Errorf("released: task %+v", tk)
		}
		if _, err := deleteguard.Discard(tx, now, discarded, "bob", "no"); err != nil {
			return err
		}
		if tk := taskOf(tx, discarded); tk.Status != "dismissed" {
			t.Errorf("discarded: task %+v", tk)
		}
		expired = hold(tx, now.Add(time.Hour*2), "alice")
		return nil
	})
	in(t, f, f.A, func(tx *store.TenantTx) error {
		if n, err := deleteguard.ExpireDue(tx, now.Add(30*24*time.Hour)); err != nil || n < 1 {
			t.Fatalf("ExpireDue = %d %v", n, err)
		}
		if tk := taskOf(tx, expired); tk.Status != "dismissed" {
			t.Errorf("expired: task %+v", tk)
		}
		return nil
	})
	// the other tenant sees none of it
	in(t, f, f.B, func(tx *store.TenantTx) error {
		if ts, err := tx.GrpTasks(store.GrpTaskFilter{Kind: store.TaskDeletionHeld, Limit: 10}); err != nil || len(ts) != 0 {
			t.Errorf("tenant B sees tasks %v %v", ts, err)
		}
		return nil
	})
}
