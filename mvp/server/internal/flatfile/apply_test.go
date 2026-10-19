package flatfile_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/correlation"
	"github.com/nischalravi/tessera/mvp/server/internal/flatfile"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/jml"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/reviews"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

const sys = "hr-app"

const (
	accountsHead = "UserID,Login,Mail,EmpNo,State\n"
	entsHead     = "UserID,Role,RoleName,Admin\n"
	// alice correlates by email, bob by employee number; carol and zed match nobody
	accountsV1 = accountsHead + "u1,alice.a,alice@t.example,,active\nu2,bob.b,,bob,Enabled\nu3,carol.c,carol@elsewhere.example,,suspended\nu4,zed.z,zed@nowhere.example,,active\n"
	entsV1     = entsHead + "u1,invoice:create,Create invoices,no\nu1,invoice:approve,Approve invoices,yes\nu2,invoice:create,Create invoices,no\n"
)

// env is tenant B of the isolation fixture (alice@t.example, bob and the
// other Tiny identities) with a saved mapping for the disconnected app "hr-app".
type env struct {
	t   *testing.T
	f   *storetest.Fixture
	now time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, f: storetest.TwoTenants(t), now: storetest.Now}
	row, err := goodMapping().ToStore()
	if err != nil {
		t.Fatal(err)
	}
	row.UpdatedBy, row.UpdatedAt = "admin", e.now
	e.tx(func(c *store.TenantTx) error { return c.PutFlatMapping(row) })
	return e
}

func (e *env) tx(fn func(c *store.TenantTx) error) {
	e.t.Helper()
	if err := e.f.DB.InTenant(context.Background(), e.f.B.ID, fn); err != nil {
		e.t.Fatal(err)
	}
}

// apply uploads a file (a minute after the last one) and commits.
func (e *env) apply(kind, csv string) *flatfile.Result {
	e.t.Helper()
	var res *flatfile.Result
	e.tx(func(c *store.TenantTx) error {
		e.now = e.now.Add(time.Minute)
		var err error
		res, err = flatfile.Apply(c, e.now, flatfile.Input{System: sys, Kind: kind, Filename: kind + ".csv", Raw: []byte(csv), By: "Pat"})
		return err
	})
	return res
}

func (e *env) accounts(csv string) *flatfile.Result { return e.apply(flatfile.KindAccounts, csv) }
func (e *env) ents(csv string) *flatfile.Result     { return e.apply(flatfile.KindEntitlements, csv) }

func ptr[T any](v T) *T { return &v }

func (e *env) mustApplied(res *flatfile.Result) *flatfile.Result {
	e.t.Helper()
	if res.Upload.Status != store.FlatUploadApplied {
		e.t.Fatalf("upload %s: %v", res.Upload.Status, res.Errors)
	}
	return res
}

func (e *env) read(fn func(c *store.TenantTx)) {
	e.t.Helper()
	if err := e.f.DB.ReadTenant(context.Background(), e.f.B.ID, func(c *store.TenantTx) error { fn(c); return nil }); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) account(xid string) *store.Account {
	e.t.Helper()
	var a *store.Account
	e.read(func(c *store.TenantTx) {
		var err error
		if a, err = c.AccountByXID(sys, xid); err != nil {
			e.t.Fatalf("account %s: %v", xid, err)
		}
	})
	return a
}

func (e *env) auditCounts() map[string]int {
	out := map[string]int{}
	e.read(func(c *store.TenantTx) {
		evs, err := c.AuditEvents(store.AuditFilter{})
		if err != nil {
			e.t.Fatal(err)
		}
		for _, ev := range evs {
			out[ev.Action]++
		}
	})
	return out
}

func (e *env) edgeCount(xid string) int {
	a := e.account(xid)
	n := 0
	e.read(func(c *store.TenantTx) {
		edges, err := c.EdgesFrom(graph.Key("account", a.ID))
		if err != nil {
			e.t.Fatal(err)
		}
		n = len(edges)
	})
	return n
}

func TestApply_ImportsAccountsAndCorrelatesThemWithTheNormalResolver(t *testing.T) {
	e := newEnv(t)
	res := e.mustApplied(e.accounts(accountsV1))
	if u := res.Upload; u.Added != 4 || u.Removed != 0 || u.Changed != 0 || u.RowsTotal != 4 || u.Source != "api" || u.Filename != "accounts.csv" {
		t.Errorf("upload = %+v", u)
	}
	ids := e.f.B.IDs
	for xid, want := range map[string]*int64{"u1": ptr(ids["alice"]), "u2": ptr(ids["bob"]), "u3": nil, "u4": nil} {
		a := e.account(xid)
		if (a.IdentityID == nil) != (want == nil) || (want != nil && *a.IdentityID != *want) {
			t.Errorf("account %s identity = %v, want %v", xid, a.IdentityID, want)
		}
		if a.Kind != "user" || a.System != sys {
			t.Errorf("account %s = %+v", xid, a)
		}
	}
	if st := e.account("u3").Status; st != "disabled" {
		t.Errorf("suspended account status = %s", st)
	}
	// orphans: the accounts that match nobody are in the correlation queue, linked ones are not
	e.read(func(c *store.TenantTx) {
		q, err := correlation.Queue(c)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, it := range q {
			if it.Account.System == sys {
				got[it.Account.ExternalID] = true
			}
		}
		if len(got) != 2 || !got["u3"] || !got["u4"] {
			t.Errorf("orphan accounts of %s = %v, want u3 and u4", sys, got)
		}
	})
}

func TestApply_ReuploadComputesDeltaAndKeepsHistory(t *testing.T) {
	e := newEnv(t)
	e.mustApplied(e.accounts(accountsV1))
	// u1 same, u2 disabled in the file, u3 renamed, u4 gone, u5 new
	v2 := accountsHead + "u1,alice.a,alice@t.example,,active\nu2,bob.b,,bob,disabled\nu3,carol.renamed,carol@elsewhere.example,,suspended\nu5,new.n,,,\n"
	res := e.mustApplied(e.accounts(v2))
	if u := res.Upload; u.Added != 1 || u.Removed != 1 || u.Changed != 2 || u.Unchanged != 1 {
		t.Errorf("delta = %+v", u)
	}
	var lines []string
	for _, c := range res.Changes {
		lines = append(lines, c.Type+" "+c.Label+" "+c.Detail)
	}
	if got := strings.Join(lines, "|"); got != "added u5 |removed u4 |changed u2 status|changed u3 username" {
		t.Errorf("changes = %s", got)
	}
	if st := e.account("u4").Status; st != "disabled" {
		t.Errorf("the removed account is %s, want disabled (not deleted: reviews and audit refer to it)", st)
	}
	if st := e.account("u2").Status; st != "disabled" {
		t.Errorf("u2 status = %s", st)
	}
	if n := e.account("u3").Username; n != "carol.renamed" {
		t.Errorf("u3 username = %s", n)
	}
	// the same file again: no change at all
	res = e.mustApplied(e.accounts(v2))
	if u := res.Upload; u.Added+u.Removed+u.Changed != 0 || u.Unchanged != 4 || len(res.Changes) != 0 {
		t.Errorf("identical re-upload = %+v", u)
	}
	// history: all three uploads, newest first, with their delta kept
	e.read(func(c *store.TenantTx) {
		us, err := c.FlatUploads(sys)
		if err != nil || len(us) != 3 || us[0].Unchanged != 4 || us[1].Removed != 1 || us[2].Added != 4 {
			t.Fatalf("history = %v, %v", us, err)
		}
		chs, err := c.FlatChanges(us[1].ID)
		if err != nil || len(chs) != 4 {
			t.Errorf("stored changes = %v, %v", chs, err)
		}
	})
	if got := e.auditCounts()["flatfile.upload"]; got != 3 {
		t.Errorf("flatfile.upload audit events = %d, want 3", got)
	}
}

func TestApply_EntitlementsFeedReviewsSoDAndLeaverPlans(t *testing.T) {
	e := newEnv(t)
	ids := e.f.B.IDs
	e.mustApplied(e.accounts(accountsV1))
	res := e.mustApplied(e.ents(entsV1))
	if u := res.Upload; u.Added != 3 || u.Kind != "entitlements" {
		t.Errorf("upload = %+v", u)
	}
	sod := &policy.Policy{ID: "sod-invoices", Name: "Invoices: create vs approve", Type: "separation_of_duties", Severity: "high", Enabled: true,
		Spec: map[string]any{"conflict": map[string]any{"a": []any{"invoice:create"}, "b": []any{"invoice:approve"}}}}
	u1 := e.account("u1")
	e.tx(func(c *store.TenantTx) error {
		g, err := graph.Build(c, e.now)
		if err != nil {
			return err
		}
		// effective permissions: alice holds both entitlements, approve is privileged
		actions := map[string]bool{}
		for _, ep := range g.EffectivePermissions(ids["alice"]).Values() {
			if ep.ResourceName == "HR app" {
				actions[ep.Action] = ep.Privileged
			}
		}
		if len(actions) != 2 || actions["invoice:create"] || !actions["invoice:approve"] {
			t.Errorf("alice's imported permissions = %v", actions)
		}
		// SoD
		viol, err := policy.Evaluate([]*policy.Policy{sod}, policy.NewContext(g, c, e.now))
		if err != nil {
			return err
		}
		if len(viol) != 1 || viol[0].IdentityID == nil || *viol[0].IdentityID != ids["alice"] {
			t.Errorf("SoD violations = %+v, want alice only", viol)
		}
		// reviews: the imported grant is an item (policy violation)
		camp, err := reviews.GenerateCampaign(c, e.now, "q", 90, []*policy.Policy{sod})
		if err != nil {
			return err
		}
		items, err := c.CampaignItems(camp)
		if err != nil {
			return err
		}
		found := false
		for _, it := range items {
			if it.EdgeSrc == graph.Key("account", u1.ID) && it.IdentityID == ids["alice"] && strings.Contains(strings.Join(it.Reasons, ","), "policy_violation") {
				found = true
			}
		}
		if !found {
			t.Errorf("no review item for the imported grant among %d items", len(items))
		}
		// leaver plan: disable the imported account
		plan, err := jml.LeaverPlan(c, e.now, ids["alice"], false, nil)
		if err != nil {
			return err
		}
		v, _ := plan.Get("steps")
		steps, _ := v.([]jml.Step)
		hit := false
		for _, st := range steps {
			if act, _ := st.Get("action"); act == "disable_account" {
				if s, _ := st.Get("system"); s == sys {
					hit = true
				}
			}
		}
		if !hit {
			t.Errorf("leaver plan has no disable_account step for %s: %v", sys, steps)
		}
		return nil
	})
	// dropping a row removes the grant; dropping the account takes its entitlements with it
	if n := e.edgeCount("u2"); n != 1 {
		t.Fatalf("u2 edges = %d", n)
	}
	res = e.mustApplied(e.ents(entsHead + "u1,invoice:create,Create invoices,no\nu1,invoice:approve,Approve invoices,yes\n"))
	if res.Upload.Removed != 1 || e.edgeCount("u2") != 0 || e.edgeCount("u1") != 2 {
		t.Errorf("after dropping u2's row: %+v, u2 edges %d, u1 edges %d", res.Upload, e.edgeCount("u2"), e.edgeCount("u1"))
	}
	res = e.mustApplied(e.accounts(accountsHead + "u2,bob.b,,bob,Enabled\nu3,carol.c,carol@elsewhere.example,,suspended\nu4,zed.z,zed@nowhere.example,,active\n"))
	if res.Upload.Removed != 1 || e.edgeCount("u1") != 0 {
		t.Errorf("after dropping u1: %+v, u1 edges %d", res.Upload, e.edgeCount("u1"))
	}
	var gone []string
	for _, c := range res.Changes {
		gone = append(gone, c.Kind+":"+c.Type+":"+c.Label)
	}
	if want := "accounts:removed:u1|entitlements:removed:u1 / invoice:approve|entitlements:removed:u1 / invoice:create"; strings.Join(gone, "|") != want {
		t.Errorf("changes = %v", gone)
	}
	e.read(func(c *store.TenantTx) {
		if rs, err := c.FlatRecords(sys, flatfile.KindEntitlements); err != nil || len(rs) != 0 {
			t.Errorf("entitlement snapshot after its accounts went = %v, %v", rs, err)
		}
	})
}

func TestApply_DoesNotTouchAgentDelegations(t *testing.T) {
	e := newEnv(t)
	var before int
	e.read(func(c *store.TenantTx) {
		d, err := c.Delegations()
		if err != nil || len(d) == 0 {
			t.Fatalf("fixture delegations = %v, %v", d, err)
		}
		before = len(d)
	})
	e.mustApplied(e.accounts(accountsV1))
	e.mustApplied(e.ents(entsV1))
	e.read(func(c *store.TenantTx) {
		if d, err := c.Delegations(); err != nil || len(d) != before {
			t.Errorf("delegations after imports = %d, want %d (%v)", len(d), before, err)
		}
	})
}

// The malformed files of the issue: a rejected upload is reported per row,
// recorded in the history, and changes nothing else.
func TestApply_RejectedUploads(t *testing.T) {
	var many strings.Builder
	many.WriteString(accountsHead)
	for i := 0; i <= flatfile.MaxRows; i++ {
		fmt.Fprintf(&many, "x%d,n%d,,,\n", i, i)
	}
	for _, tc := range []struct {
		name string
		kind string
		csv  string
		want []string // "row:code"
	}{
		{"bad encoding", "accounts", "UserID,Login\nu1,caf\xe9\n", []string{"0:not_utf8"}},
		{"wrong column count", "accounts", accountsHead + "u9,short\nu8,ok,,,\n", []string{"1:column_count"}},
		{"missing required fields", "accounts", accountsHead + ",,,,\nu9,,,,\n", []string{"1:required", "1:required", "2:required"}},
		{"missing mapped column", "accounts", "UserID,Login\nu9,x\n", []string{"0:missing_column", "0:missing_column", "0:missing_column"}},
		{"oversized file", "accounts", accountsHead + strings.Repeat("u9,n,,,\n", flatfile.MaxBytes/8), []string{"0:file_too_large"}},
		{"too many rows", "accounts", many.String(), []string{"0:too_many_rows"}},
		{"formula injection in a key", "accounts", accountsHead + "=cmd|' /C calc'!A0,x,,,\n", []string{"1:formula_prefix"}},
		{"formula injection in an email", "accounts", accountsHead + "u9,x,@sum(1+1),,\n", []string{"1:formula_prefix"}},
		{"duplicate account", "accounts", accountsHead + "u9,a,,,\nu9,b,,,\n", []string{"2:duplicate_key"}},
		{"entitlement of an unknown account", "entitlements", entsHead + "u1,invoice:create,,\nnope,invoice:create,,\n", []string{"2:unknown_account"}},
		{"formula injection in an entitlement", "entitlements", entsHead + "u1,+SUM(1),,\n", []string{"1:formula_prefix"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.mustApplied(e.accounts(accountsV1))
			e.mustApplied(e.ents(entsV1))
			beforeAccounts := e.account("u2")
			res := e.apply(tc.kind, tc.csv)
			if res.Upload.Status != store.FlatUploadRejected {
				t.Fatalf("status %s, want rejected", res.Upload.Status)
			}
			var got []string
			for _, r := range res.Errors {
				got = append(got, fmt.Sprintf("%d:%s", r.Row, r.Code))
			}
			if strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Errorf("errors = %v, want %v", got, tc.want)
			}
			// nothing was applied: the snapshot, the graph and the upload counts are as before
			if u := res.Upload; u.Added+u.Removed+u.Changed != 0 || len(res.Changes) != 0 {
				t.Errorf("rejected upload has a delta: %+v", u)
			}
			if a := e.account("u2"); a.Status != beforeAccounts.Status || a.Username != beforeAccounts.Username || e.edgeCount("u1") != 2 {
				t.Errorf("graph changed by a rejected upload: %+v", a)
			}
			e.read(func(c *store.TenantTx) {
				as, _ := c.FlatRecords(sys, flatfile.KindAccounts)
				es, _ := c.FlatRecords(sys, flatfile.KindEntitlements)
				if len(as) != 4 || len(es) != 3 {
					t.Errorf("snapshot changed: %d accounts, %d entitlements", len(as), len(es))
				}
				// per-row errors are kept with the upload, not dropped
				d, err := flatfile.ViewDetail(c, res.Upload)
				if err != nil || len(d.Errors) != len(tc.want) || d.Status != "rejected" {
					t.Errorf("stored detail = %+v, %v", d, err)
				}
				// and audited, as a failure, in the same transaction
				evs, err := c.AuditEvents(store.AuditFilter{Action: "flatfile.upload"})
				failed := 0
				for _, ev := range evs {
					if ev.Outcome == store.OutcomeFailure {
						failed++
					}
				}
				if err != nil || len(evs) != 3 || failed != 1 {
					t.Errorf("audit = %d upload events, %d failures, %v", len(evs), failed, err)
				}
			})
		})
	}
}

func TestApply_RejectedUploadListsEveryBadRowAndCapsWhatItStores(t *testing.T) {
	e := newEnv(t)
	var b strings.Builder
	b.WriteString(accountsHead)
	for i := 0; i < flatfile.MaxStoredErrors+50; i++ {
		fmt.Fprintf(&b, ",n%d,,,\n", i) // no account id
	}
	res := e.accounts(b.String())
	if len(res.Errors) != flatfile.MaxStoredErrors+50 || res.Upload.RowsRejected != flatfile.MaxStoredErrors+50 {
		t.Errorf("errors %d, rows rejected %d", len(res.Errors), res.Upload.RowsRejected)
	}
	e.read(func(c *store.TenantTx) {
		d, err := flatfile.ViewDetail(c, res.Upload)
		if err != nil || len(d.Errors) != flatfile.MaxStoredErrors || !d.ErrorsTruncated {
			t.Errorf("stored %d errors, truncated %v, %v", len(d.Errors), d.ErrorsTruncated, err)
		}
	})
}

func TestApply_FormulaValuesAreNeutralisedForDisplayAndExport(t *testing.T) {
	e := newEnv(t)
	e.mustApplied(e.accounts(accountsHead + "u1,\"=HYPERLINK(\"\"http://evil\"\")\",,,\nu2,-2+3,,,\nu3,@SUM(A1),,,\n"))
	for xid, want := range map[string]string{"u1": `'=HYPERLINK("http://evil")`, "u2": "'-2+3", "u3": "'@SUM(A1)"} {
		if got := e.account(xid).Username; got != want {
			t.Errorf("%s username = %q, want %q", xid, got, want)
		}
	}
	e.mustApplied(e.ents(entsHead + "u1,r1,=1+1,no\n"))
	e.read(func(c *store.TenantTx) {
		recs, _ := c.FlatRecords(sys, flatfile.KindEntitlements)
		if len(recs) != 1 || !strings.Contains(recs[0].Data, `"name":"'=1+1"`) {
			t.Errorf("stored entitlement = %v", recs)
		}
	})
	// whatever reaches a view is neutralised, including values stored before this rule
	tv := flatfile.ViewTask(&store.FlatTask{AccountXID: "=a", AccountLabel: "=b", Entitlement: "+c", CloseReason: "@d", CreatedBy: "-e",
		Kind: flatfile.TaskRemoveEntitlement, System: sys})
	for _, v := range []string{tv.Account, tv.AccountLabel, tv.Entitlement, tv.CloseReason, tv.CreatedBy} {
		if !strings.HasPrefix(v, "'") {
			t.Errorf("task view value %q is not neutralised", v)
		}
	}
	if strings.Contains(tv.Instruction, " =b") || !strings.Contains(tv.Instruction, "'=b") {
		t.Errorf("instruction = %q", tv.Instruction)
	}
	ev := flatfile.ViewErrors([]flatfile.RowError{{Row: 1, Column: "=col", Code: "x", Message: "+m"}})
	if ev[0].Column != "'=col" || ev[0].Message != "'+m" {
		t.Errorf("error view = %+v", ev[0])
	}
	ch := flatfile.ViewChanges([]flatfile.Change{{Kind: "accounts", Type: "added", Label: "=x"}})
	if ch[0].Label != "'=x" {
		t.Errorf("change view = %+v", ch[0])
	}
	if u := flatfile.ViewUpload(&store.FlatUpload{Filename: "-f.csv", UploadedBy: "=u"}); u.Filename != "'-f.csv" || u.UploadedBy != "'=u" {
		t.Errorf("upload view = %+v", u)
	}
}

func TestApply_RefusesWithoutAMappingOrKind(t *testing.T) {
	e := newEnv(t)
	e.tx(func(c *store.TenantTx) error {
		if _, err := flatfile.Apply(c, e.now, flatfile.Input{System: "other-app", Kind: "accounts", Raw: []byte(accountsV1)}); !errors.Is(err, flatfile.ErrNoMapping) {
			t.Errorf("no mapping = %v", err)
		}
		if _, err := flatfile.Apply(c, e.now, flatfile.Input{System: sys, Kind: "groups", Raw: []byte(accountsV1)}); err == nil {
			t.Error("unknown kind accepted")
		}
		m := goodMapping()
		m.System, m.Entitlements = "no-ents", nil
		row, _ := m.ToStore()
		row.UpdatedBy, row.UpdatedAt = "a", e.now
		if err := c.PutFlatMapping(row); err != nil {
			return err
		}
		var fe *flatfile.Error
		if _, err := flatfile.Apply(c, e.now, flatfile.Input{System: "no-ents", Kind: "entitlements", Raw: []byte(entsV1)}); !errors.As(err, &fe) || fe.Code != "no_entitlement_mapping" {
			t.Errorf("no entitlement mapping = %v", err)
		}
		return nil
	})
}

func executeLeaver(e *env) {
	e.t.Helper()
	e.tx(func(c *store.TenantTx) error {
		_, err := jml.ExecuteEvent(c, e.now, e.f.B.IDs["hris:leaver"], store.UserRef{Display: "Pat"}, nil)
		return err
	})
}

func (e *env) tasks(status string) []*store.FlatTask {
	var out []*store.FlatTask
	e.read(func(c *store.TenantTx) {
		var err error
		if out, err = c.FlatTasks(status); err != nil {
			e.t.Fatal(err)
		}
	})
	return out
}

// A leaver on a disconnected app is a manual task that stays open until the
// next import shows the account gone.
func TestTasks_LeaverTaskStaysOpenUntilTheNextImportConfirmsIt(t *testing.T) {
	e := newEnv(t)
	e.mustApplied(e.accounts(accountsV1))
	e.mustApplied(e.ents(entsV1))
	executeLeaver(e)

	ts := e.tasks("")
	if len(ts) != 1 {
		t.Fatalf("tasks = %d, want one disable_account task for alice's hr-app account (not one per entitlement, not for okta/aws)", len(ts))
	}
	task := ts[0]
	if task.Kind != flatfile.TaskDisableAccount || task.System != sys || task.AccountXID != "u1" || task.Status != "open" ||
		task.Trigger != "leaver" || task.IdentityID == nil || *task.IdentityID != e.f.B.IDs["alice"] || task.CreatedBy != "Pat" {
		t.Errorf("task = %+v", task)
	}
	if st := e.account("u1").Status; st != "disabled" {
		t.Errorf("Tessera's own record of the account: %s", st)
	}

	// the file still lists the account as active: the task stays open, and the
	// account is not brought back to life nor its grants re-created
	res := e.mustApplied(e.accounts(accountsV1))
	if res.Upload.TasksConfirmed != 0 || len(res.Confirmed) != 0 {
		t.Errorf("confirmed %d tasks from a file that still lists the account", res.Upload.TasksConfirmed)
	}
	e.mustApplied(e.ents(entsV1))
	if st := e.account("u1").Status; st != "disabled" || e.edgeCount("u1") != 0 {
		t.Errorf("account %s with %d grants after a re-import that still lists it", st, e.edgeCount("u1"))
	}
	if ts := e.tasks("open"); len(ts) != 1 {
		t.Fatalf("open tasks = %d", len(ts))
	}
	// an entitlements file is not evidence about the account
	e.mustApplied(e.ents(entsHead + "u2,invoice:create,,no\n"))
	if ts := e.tasks("open"); len(ts) != 1 {
		t.Errorf("an entitlements upload confirmed an account task")
	}

	// the next accounts file no longer lists it: confirmed, by that upload
	res = e.mustApplied(e.accounts(accountsHead + "u2,bob.b,,bob,Enabled\nu3,carol.c,,,\nu4,zed.z,,,\n"))
	if res.Upload.TasksConfirmed != 1 || len(res.Confirmed) != 1 || res.Confirmed[0].ID != task.ID {
		t.Fatalf("confirmed = %+v", res.Confirmed)
	}
	got := e.tasks("confirmed")
	if len(got) != 1 || got[0].ClosedUploadID == nil || *got[0].ClosedUploadID != res.Upload.ID || got[0].ClosedAt == nil || got[0].ClosedBy == nil {
		t.Errorf("confirmed task = %+v", got)
	}
	if len(e.tasks("open")) != 0 {
		t.Error("task still open")
	}
	counts := e.auditCounts()
	if counts["flatfile.task_created"] != 1 || counts["flatfile.task_confirmed"] != 1 {
		t.Errorf("audit = %v", counts)
	}
}

func TestTasks_DisabledInTheFileAlsoConfirmsADisableTask(t *testing.T) {
	e := newEnv(t)
	e.mustApplied(e.accounts(accountsV1))
	executeLeaver(e)
	res := e.mustApplied(e.accounts(strings.Replace(accountsV1, "u1,alice.a,alice@t.example,,active", "u1,alice.a,alice@t.example,,disabled", 1)))
	if len(res.Confirmed) != 1 {
		t.Errorf("confirmed %d, want 1: the source now shows the account disabled", len(res.Confirmed))
	}
}

func TestTasks_RevokedEntitlementIsAManualTaskUntilTheFileDropsIt(t *testing.T) {
	e := newEnv(t)
	ids := e.f.B.IDs
	e.mustApplied(e.accounts(accountsV1))
	e.mustApplied(e.ents(entsV1))
	// what the least-privilege revoke and an access review do: task first, then the tombstoning revoke
	bob := e.account("u2")
	e.tx(func(c *store.TenantTx) error {
		p, err := c.PermissionByXID(sys, flatfile.EntitlementPermXID("invoice:create"))
		if err != nil {
			return err
		}
		edge, err := c.EdgeBetween(graph.Key("account", bob.ID), graph.Key("perm", p.ID))
		if err != nil {
			return err
		}
		if err := flatfile.GrantRevoked(c, e.now, "Pat", edge.ID, "review"); err != nil {
			return err
		}
		// a second revoke of the same thing does not open a second task
		if err := flatfile.GrantRevoked(c, e.now, "Pat", edge.ID, "review"); err != nil {
			return err
		}
		return c.RevokeEdge(edge.ID, e.now, "review")
	})
	ts := e.tasks("open")
	if len(ts) != 1 || ts[0].Kind != flatfile.TaskRemoveEntitlement || ts[0].Entitlement != "invoice:create" || ts[0].AccountXID != "u2" ||
		ts[0].Trigger != "review" || *ts[0].IdentityID != ids["bob"] {
		t.Fatalf("tasks = %+v", ts)
	}
	// the file still has the row: still open, and the grant is not re-created
	res := e.mustApplied(e.ents(entsV1))
	if len(res.Confirmed) != 0 || e.edgeCount("u2") != 0 {
		t.Errorf("confirmed %d, bob's edges %d", len(res.Confirmed), e.edgeCount("u2"))
	}
	// the row is gone: confirmed
	res = e.mustApplied(e.ents(entsHead + "u1,invoice:create,Create invoices,no\nu1,invoice:approve,Approve invoices,yes\n"))
	if len(res.Confirmed) != 1 || res.Confirmed[0].ID != ts[0].ID || len(e.tasks("open")) != 0 {
		t.Errorf("confirmed = %+v", res.Confirmed)
	}
}

func TestTasks_AccountGoneConfirmsItsEntitlementTasks(t *testing.T) {
	e := newEnv(t)
	e.mustApplied(e.accounts(accountsV1))
	e.mustApplied(e.ents(entsV1))
	bob := e.account("u2")
	e.tx(func(c *store.TenantTx) error {
		p, _ := c.PermissionByXID(sys, flatfile.EntitlementPermXID("invoice:create"))
		edge, err := c.EdgeBetween(graph.Key("account", bob.ID), graph.Key("perm", p.ID))
		if err != nil {
			return err
		}
		if err := flatfile.GrantRevoked(c, e.now, "Pat", edge.ID, "revoke"); err != nil {
			return err
		}
		return c.RevokeEdge(edge.ID, e.now, "least-privilege")
	})
	res := e.mustApplied(e.accounts(accountsHead + "u1,alice.a,alice@t.example,,active\nu3,carol.c,,,\nu4,zed.z,,,\n"))
	if len(res.Confirmed) != 1 || res.Confirmed[0].Kind != flatfile.TaskRemoveEntitlement {
		t.Errorf("confirmed = %+v", res.Confirmed)
	}
}

func TestTasks_OnlyDisconnectedAppsGetThem(t *testing.T) {
	e := newEnv(t)
	executeLeaver(e) // alice has okta and aws grants, but no account of an imported app
	if ts := e.tasks(""); len(ts) != 0 {
		t.Errorf("tasks for connector-fed systems: %+v", ts)
	}
}

func TestTasks_CloseByHand(t *testing.T) {
	e := newEnv(t)
	e.mustApplied(e.accounts(accountsV1))
	executeLeaver(e)
	task := e.tasks("open")[0]
	e.tx(func(c *store.TenantTx) error {
		closed, err := flatfile.CloseTask(c, e.now, "Vic", task.ID, "access was removed in the app console on the 9th")
		if err != nil {
			return err
		}
		if closed.Status != "closed" || closed.ClosedBy == nil || *closed.ClosedBy != "Vic" || closed.CloseReason == "" || closed.ClosedUploadID != nil {
			t.Errorf("closed = %+v", closed)
		}
		if _, err := flatfile.CloseTask(c, e.now, "Vic", task.ID, "again"); !errors.Is(err, flatfile.ErrTaskNotOpen) {
			t.Errorf("second close = %v", err)
		}
		if _, err := flatfile.CloseTask(c, e.now, "Vic", "00000000-0000-4000-8000-00000000dead", "x"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("unknown task = %v", err)
		}
		return nil
	})
	// a closed task is not confirmed again by an import
	res := e.mustApplied(e.accounts(accountsHead + "u2,bob.b,,bob,Enabled\n"))
	if len(res.Confirmed) != 0 || len(e.tasks("closed")) != 1 {
		t.Errorf("confirmed %d, closed %d", len(res.Confirmed), len(e.tasks("closed")))
	}
	if got := e.auditCounts()["flatfile.task_closed"]; got != 1 {
		t.Errorf("task_closed audit events = %d", got)
	}
}
