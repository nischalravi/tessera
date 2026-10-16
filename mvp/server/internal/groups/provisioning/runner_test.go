package provisioning

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func (x *harness) runs(prov string) []*store.SyncRun {
	x.t.Helper()
	var out []*store.SyncRun
	x.read(func(tx *store.TenantTx) error {
		var err error
		out, err = tx.SyncRuns(prov, 100, 0)
		return err
	})
	return out
}

func newRunner(x *harness) *Runner {
	return &Runner{Svc: x.svc, Clock: func() time.Time { return x.now }}
}

func TestRunner_FullIncrementalAndSchedule(t *testing.T) {
	x := newHarness(t, 4)
	g := x.group(x.root, "eng")
	x.add(g, x.idents[0])
	p, f := x.prov("scim", `{}`)
	x.mark(p.ID, MarkInput{ObjectType: "group", ObjectID: string(g), Include: true})
	r := newRunner(x)
	ctx := context.Background()
	once := func() {
		t.Helper()
		if err := r.Once(ctx); err != nil {
			t.Fatal(err)
		}
	}
	kinds := func() string {
		var out []string
		for _, run := range slices.Backward(x.runs(p.ID)) {
			out = append(out, run.Kind+"/"+run.Mode+"/"+run.Status)
		}
		return strings.Join(out, " ")
	}

	// a new provisioner gets its first (adopt) full sync, once
	once()
	once()
	if got := kinds(); got != "full/adopt/done" {
		t.Fatalf("runs = %q", got)
	}
	if f.writes != 0 {
		t.Fatal("adopt mode wrote to the target")
	}
	// events do not start an incremental sync before the provisioner is active
	x.add(g, x.idents[1])
	x.tick(time.Minute)
	once()
	if got := kinds(); got != "full/adopt/done" {
		t.Fatalf("runs = %q", got)
	}

	// enabling it asks for a full sync
	x.setMode(p.ID, store.ProvModeActive)
	once()
	if got := kinds(); got != "full/adopt/done full/active/done" {
		t.Fatalf("runs = %q", got)
	}
	if got := f.members("eng"); !slices.Equal(got, []string{"u0", "u1"}) {
		t.Fatalf("members = %v", got)
	}

	// a burst of changes is coalesced: nothing runs while events are fresh
	x.tick(time.Minute)
	x.add(g, x.idents[2])
	once()
	if got := kinds(); got != "full/adopt/done full/active/done" {
		t.Fatalf("an incremental run started inside the coalescing window: %q", got)
	}
	x.tick(3 * time.Second)
	x.add(g, x.idents[3]) // still arriving
	x.tick(time.Second)
	once()
	if len(x.runs(p.ID)) != 2 {
		t.Fatalf("runs = %q", kinds())
	}
	x.tick(3 * time.Second)
	once()
	if got := kinds(); got != "full/adopt/done full/active/done incremental/active/done" {
		t.Fatalf("runs = %q", got)
	}
	if got := f.members("eng"); !slices.Equal(got, []string{"u0", "u1", "u2", "u3"}) {
		t.Fatalf("members = %v", got)
	}
	// a long burst does not starve the target: events older than MaxWait go through
	x.add(g, x.idents[0])
	x.remove(g, x.idents[0])
	for i := 0; i < 6; i++ {
		x.tick(2 * time.Second)
		x.add(g, x.idents[0])
		x.remove(g, x.idents[0])
		once()
	}
	if got := len(x.runs(p.ID)); got < 4 {
		t.Errorf("no incremental run after a 12 s burst: %q", kinds())
	}

	// the daily full sync
	before := len(x.runs(p.ID))
	x.now = time.Date(2026, 10, 9, 1, 59, 0, 0, time.UTC)
	once()
	if n := len(x.runs(p.ID)); n != before && !strings.Contains(kinds(), "incremental") {
		t.Fatalf("a run before 02:00: %q", kinds())
	}
	fulls := func() int {
		n := 0
		for _, run := range x.runs(p.ID) {
			if run.Kind == "full" {
				n++
			}
		}
		return n
	}
	nf := fulls()
	x.now = time.Date(2026, 10, 9, 2, 1, 0, 0, time.UTC)
	once()
	once()
	if fulls() != nf+1 {
		t.Errorf("%d full syncs at 02:01, want %d", fulls(), nf+1)
	}

	// paused: never
	x.setMode(p.ID, store.ProvModePaused)
	nr := len(x.runs(p.ID))
	x.tick(48 * time.Hour)
	once()
	if len(x.runs(p.ID)) != nr {
		t.Error("a paused provisioner ran")
	}
}

func TestRunner_BackoffAfterFailure(t *testing.T) {
	x := newHarness(t, 2)
	g := x.group(x.root, "eng")
	x.add(g, x.idents[0])
	p, f := x.prov("scim", `{}`)
	x.mark(p.ID, MarkInput{ObjectType: "group", ObjectID: string(g), Include: true})
	x.setMode(p.ID, store.ProvModeActive) // after a review run in adopt mode
	r := newRunner(x)
	ctx := context.Background()
	base := len(x.runs(p.ID))

	f.failRead = errors.New("target down")
	if err := r.Once(ctx); err == nil {
		t.Fatal("a failing target is not reported")
	}
	if n := len(x.runs(p.ID)); n != base+1 {
		t.Fatalf("%d runs", n)
	}
	runs := x.runs(p.ID)
	if runs[0].Status != store.RunFailed || !strings.Contains(runs[0].Error, "target down") {
		t.Errorf("run = %+v", runs[0])
	}
	x.read(func(tx *store.TenantTx) error {
		if pp, _ := tx.Provisioner(p.ID); !pp.NeedsFull {
			t.Error("a failed full sync is not retried")
		}
		return nil
	})
	// not again straight away
	x.tick(10 * time.Second)
	_ = r.Once(ctx)
	if n := len(x.runs(p.ID)); n != base+1 {
		t.Errorf("%d runs inside the backoff", n)
	}
	// after the retry delay it runs again, and succeeds once the target is back
	x.tick(6 * time.Minute)
	_ = r.Once(ctx)
	if n := len(x.runs(p.ID)); n != base+2 {
		t.Fatalf("%d runs after the delay", n)
	}
	f.failRead = nil
	x.tick(6 * time.Minute)
	if err := r.Once(ctx); err != nil {
		t.Fatal(err)
	}
	runs = x.runs(p.ID)
	if runs[0].Status != store.RunDone || len(f.members("eng")) != 1 {
		t.Errorf("last run %+v, members %v", runs[0], f.members("eng"))
	}
	// an abandoned run (a crash) does not block the next one
	x.must(func(e model.Env) error {
		return e.Tx.InsertSyncRun(&store.SyncRun{ID: "crashed", ProvisionerID: p.ID, Kind: store.RunFull, Mode: store.ProvModeActive, StartedAt: x.now})
	})
	if _, err := x.svc.Run(ctx, tid, p.ID, RunOptions{Kind: store.RunFull}); !errors.Is(err, ErrBusy) {
		t.Errorf("a run while another is in progress = %v, want ErrBusy", err)
	}
	x.tick(time.Hour)
	if _, err := x.svc.Run(ctx, tid, p.ID, RunOptions{Kind: store.RunFull}); err != nil {
		t.Errorf("a run after the stale one was abandoned: %v", err)
	}
}

func TestFullDue(t *testing.T) {
	at := func(h, m int) time.Time { return time.Date(2026, 10, 9, h, m, 0, 0, time.UTC) }
	run := func(d time.Time) *store.SyncRun { return &store.SyncRun{StartedAt: d} }
	for _, c := range []struct {
		schedule string
		last     *store.SyncRun
		now      time.Time
		want     bool
	}{
		{"0 2 * * *", nil, at(1, 0), true},
		{"0 2 * * *", run(at(2, 5)), at(23, 0), false},
		{"0 2 * * *", run(at(2, 5).AddDate(0, 0, -1)), at(1, 59), false},
		{"0 2 * * *", run(at(2, 5).AddDate(0, 0, -1)), at(2, 0), true},
		{"30 4 * * *", run(at(4, 29)), at(4, 31), true},
		{"bogus", nil, at(3, 0), false},
		{"61 2 * * *", nil, at(3, 0), false},
	} {
		if got := fullDue(c.schedule, c.last, c.now); got != c.want {
			t.Errorf("fullDue(%q, %v, %v) = %v", c.schedule, c.last, c.now, got)
		}
	}
}

func TestDiagnose(t *testing.T) {
	x := newHarness(t, 4)
	a := x.folder(x.root, "a")
	g := x.group(a, "eng")
	lonely := x.group(x.root, "lonely")
	x.add(g, x.idents[0])
	x.add(g, x.idents[1])
	x.must(func(e model.Env) error { // u2 has no account in the target system, u3 is not a member
		accts, _ := e.Tx.IdentityAccounts(x.idents[2])
		return e.Tx.DisableAccount(accts[0].ID)
	})
	x.add(g, x.idents[2])
	p, f := x.prov("scim", `{}`)
	ctx := context.Background()

	diag := func(group store.GroupID, ident int64) *Diagnosis {
		t.Helper()
		d, err := x.svc.Diagnose(ctx, tid, p.ID, string(group), ident)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	if d := diag(g, 0); d.Provisioned || !strings.Contains(d.Why, "no mark covers") || len(d.Ops) != 0 {
		t.Errorf("unmarked: %+v", d)
	}
	x.mark(p.ID, MarkInput{ObjectType: "folder", ObjectID: string(a), Scope: "sub", Include: true})
	d := diag(g, x.idents[2])
	if !d.Provisioned || !strings.Contains(d.Why, "folder mark on a (sub)") || d.TargetName != "a-eng" || d.Members != 2 || d.Unmapped != 1 {
		t.Fatalf("marked: %+v", d)
	}
	if len(d.Ops) != 1 || d.Ops[0].Op != OpCreate || !slices.Equal(d.Ops[0].Add, []string{"u0", "u1"}) || d.WouldApply {
		t.Errorf("ops = %+v, would apply %v", d.Ops, d.WouldApply)
	}
	if d.Identity == nil || !d.Identity.Member || d.Identity.Account || !strings.Contains(d.Identity.Verdict, "no active account") {
		t.Errorf("identity = %+v", d.Identity)
	}
	if f.applies != 0 || f.writes != 0 {
		t.Fatal("diagnose wrote to the target")
	}
	if d := diag(g, x.idents[3]); d.Identity.Member || !strings.Contains(d.Identity.Verdict, "not a member") {
		t.Errorf("non-member: %+v", d.Identity)
	}
	if d := diag(g, x.idents[0]); !d.Identity.Account || d.Identity.Reference != "u0" || !strings.Contains(d.Identity.Verdict, "a sync adds it") {
		t.Errorf("member with an account: %+v", d.Identity)
	}
	// opt out one group
	x.mark(p.ID, MarkInput{ObjectType: "group", ObjectID: string(g), Include: false})
	if d := diag(g, 0); d.Provisioned || !strings.Contains(d.Why, "excluded") {
		t.Errorf("opted out: %+v", d)
	}
	x.mark(p.ID, MarkInput{ObjectType: "group", ObjectID: string(g), Include: true})
	// on the target already
	x.setMode(p.ID, store.ProvModeActive)
	x.full(p.ID)
	d = diag(g, x.idents[0])
	if len(d.Ops) != 0 || !d.WouldApply || d.Owned != "synced" || d.Identity.OnTarget == nil || !*d.Identity.OnTarget {
		t.Errorf("after a sync: %+v / %+v", d, d.Identity)
	}
	// stale: someone removed a member on the target
	f.groups["a-eng"].Members = []string{"u1"}
	d = diag(g, x.idents[0])
	if len(d.Ops) != 1 || d.Ops[0].Op != OpMembers || !slices.Equal(d.Ops[0].Add, []string{"u0"}) || *d.Identity.OnTarget {
		t.Errorf("drifted: %+v", d)
	}
	// a group the provisioner owns and no longer covers: a sync would remove it
	x.must(func(e model.Env) error {
		if err := x.svc.RemoveMark(e.Tx, x.now, "t", p.ID, "group", string(g)); err != nil {
			return err
		}
		return x.svc.RemoveMark(e.Tx, x.now, "t", p.ID, "folder", string(a))
	})
	x.mark(p.ID, MarkInput{ObjectType: "group", ObjectID: string(lonely), Include: true})
	if d := diag(g, 0); d.Provisioned || len(d.Ops) != 1 || d.Ops[0].Op != OpDelete {
		t.Errorf("owned but unmarked: %+v", d)
	}
	if _, err := x.svc.Diagnose(ctx, tid, p.ID, "00000000-0000-4000-8000-00000000dead", 0); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown group = %v", err)
	}
}
