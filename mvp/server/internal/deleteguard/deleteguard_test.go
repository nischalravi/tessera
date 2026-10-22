package deleteguard_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/deleteguard"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

var now = storetest.Now

func in(t *testing.T, f *storetest.Fixture, tn storetest.Tenant, fn func(*store.TenantTx) error) {
	t.Helper()
	if err := f.DB.InTenant(context.Background(), tn.ID, fn); err != nil {
		t.Fatal(err)
	}
}

func items(n int, prefix string) []deleteguard.Item {
	out := make([]deleteguard.Item, n)
	// deliberately not in order: Admit sorts
	for i := range out {
		k := n - 1 - i
		out[i] = deleteguard.Item{Kind: "group_delete", Ref: fmt.Sprintf("%s%03d", prefix, k), Label: fmt.Sprintf("g%d", k)}
	}
	return out
}

func setPolicy(t *testing.T, f *storetest.Fixture, tn storetest.Tenant, p deleteguard.Policy) {
	t.Helper()
	in(t, f, tn, func(tx *store.TenantTx) error { return deleteguard.Set(tx, p, nil, now) })
}

func ten(v int) *int { return &v }

func TestDefaultsAreOnForEveryCategory(t *testing.T) {
	f := storetest.TwoTenants(t)
	in(t, f, f.A, func(tx *store.TenantTx) error {
		ps, err := deleteguard.Effective(tx)
		if err != nil {
			return err
		}
		if len(ps) != len(deleteguard.Categories) {
			t.Fatalf("got %d policies", len(ps))
		}
		for _, p := range ps {
			if p.Mode != deleteguard.ModeHoldExcess || !p.Default || p.WindowMinutes != 60 {
				t.Errorf("%s: %+v", p.Category, p)
			}
			if err := p.Check(); err != nil {
				t.Errorf("%s: default fails its own check: %v", p.Category, err)
			}
		}
		// groups 25 per hour: 40 attempted, 25 applied, 15 held
		d, err := deleteguard.Admit(tx, now, deleteguard.Request{Category: deleteguard.CatGroups, Items: items(40, "g"), Actor: "alice", Source: deleteguard.SourceUser})
		if err != nil {
			return err
		}
		if d.NApplied() != 25 || d.NHeld() != 15 || d.HoldID == "" {
			t.Errorf("default groups: applied %d held %d hold %q", d.NApplied(), d.NHeld(), d.HoldID)
		}
		return nil
	})
}

func TestPartialApplyIsDeterministic(t *testing.T) {
	for run := 0; run < 2; run++ {
		f := storetest.TwoTenants(t)
		setPolicy(t, f, f.A, deleteguard.Policy{Category: deleteguard.CatGroups, MaxCount: ten(3), WindowMinutes: 60, Mode: deleteguard.ModeHoldExcess})
		in(t, f, f.A, func(tx *store.TenantTx) error {
			d, err := deleteguard.Admit(tx, now, deleteguard.Request{Category: deleteguard.CatGroups, Items: items(7, "g")})
			if err != nil {
				return err
			}
			var got []string
			for _, it := range d.Applied {
				got = append(got, it.Ref)
			}
			if fmt.Sprint(got) != "[g000 g001 g002]" {
				t.Errorf("applied %v", got)
			}
			h, err := deleteguard.Load(tx, now, d.HoldID)
			if err != nil {
				return err
			}
			if len(h.Items) != 4 || h.Items[0].Ref != "g003" || h.Items[3].Ref != "g006" || h.ItemCount != 4 {
				t.Errorf("held items %+v", h.Items)
			}
			return nil
		})
	}
}

func TestHoldAllHoldsTheWholeBatchAndOffLetsAllThrough(t *testing.T) {
	f := storetest.TwoTenants(t)
	setPolicy(t, f, f.A, deleteguard.Policy{Category: deleteguard.CatGroups, MaxCount: ten(3), WindowMinutes: 60, Mode: deleteguard.ModeHoldAll})
	setPolicy(t, f, f.A, deleteguard.Policy{Category: deleteguard.CatFolders, WindowMinutes: 60, Mode: deleteguard.ModeOff})
	in(t, f, f.A, func(tx *store.TenantTx) error {
		d, err := deleteguard.Admit(tx, now, deleteguard.Request{Category: deleteguard.CatGroups, Items: items(4, "g")})
		if err != nil {
			return err
		}
		if d.NApplied() != 0 || d.NHeld() != 4 {
			t.Errorf("hold_all: applied %d held %d", d.NApplied(), d.NHeld())
		}
		d, err = deleteguard.Admit(tx, now, deleteguard.Request{Category: deleteguard.CatGroups, Items: items(3, "h")})
		if err != nil {
			return err
		}
		if d.NApplied() != 3 || d.NHeld() != 0 {
			t.Errorf("a batch that fits: applied %d held %d", d.NApplied(), d.NHeld())
		}
		d, err = deleteguard.Admit(tx, now, deleteguard.Request{Category: deleteguard.CatFolders, Items: items(500, "f")})
		if err != nil {
			return err
		}
		if d.NApplied() != 500 || d.HoldID != "" {
			t.Errorf("off: applied %d", d.NApplied())
		}
		return nil
	})
}

func TestWindowSlidesAndPercentHasAFloor(t *testing.T) {
	f := storetest.TwoTenants(t)
	setPolicy(t, f, f.A, deleteguard.Policy{Category: deleteguard.CatGroups, MaxCount: ten(2), WindowMinutes: 30, Mode: deleteguard.ModeHoldExcess})
	in(t, f, f.A, func(tx *store.TenantTx) error {
		admit := func(at time.Time, n int, p string) *deleteguard.Decision {
			d, err := deleteguard.Admit(tx, at, deleteguard.Request{Category: deleteguard.CatGroups, Items: items(n, p)})
			if err != nil {
				t.Fatal(err)
			}
			return d
		}
		if d := admit(now, 2, "a"); d.NApplied() != 2 {
			t.Errorf("first: %d", d.NApplied())
		}
		if d := admit(now.Add(10*time.Minute), 1, "b"); d.NApplied() != 0 || d.NHeld() != 1 || d.Used != 2 {
			t.Errorf("inside the window: applied %d held %d used %d", d.NApplied(), d.NHeld(), d.Used)
		}
		if d := admit(now.Add(31*time.Minute), 2, "c"); d.NApplied() != 2 {
			t.Errorf("after the window slid: %d", d.NApplied())
		}
		return nil
	})
	// percent of a tiny population is floored, so one deletion always passes
	p := deleteguard.Policy{Category: deleteguard.CatMembers, MaxPercent: func() *float64 { v := 10.0; return &v }(), WindowMinutes: 60, Mode: deleteguard.ModeHoldExcess}
	if l := p.Limit(12); l == nil || *l != deleteguard.MinPercentLimit {
		t.Errorf("limit of 10%% of 12 = %v", l)
	}
	if l := p.Limit(10000); l == nil || *l != 1000 {
		t.Errorf("limit of 10%% of 10000 = %v", l)
	}
	p.MaxCount = ten(500)
	if l := p.Limit(10000); *l != 500 {
		t.Errorf("both set: the lower applies, got %d", *l)
	}
}

func TestConcurrentRequestsCannotExceedTheThreshold(t *testing.T) {
	f := storetest.TwoTenants(t)
	const limit, workers = 10, 24
	setPolicy(t, f, f.A, deleteguard.Policy{Category: deleteguard.CatGroups, MaxCount: ten(limit), WindowMinutes: 60, Mode: deleteguard.ModeHoldExcess})
	var applied, held atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := f.DB.InTenant(context.Background(), f.A.ID, func(tx *store.TenantTx) error {
				d, err := deleteguard.Admit(tx, now, deleteguard.Request{Category: deleteguard.CatGroups, Items: items(2, fmt.Sprintf("w%02d-", w))})
				if err != nil {
					return err
				}
				applied.Add(int64(d.NApplied()))
				held.Add(int64(d.NHeld()))
				return nil
			})
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if applied.Load() != limit || held.Load() != workers*2-limit {
		t.Errorf("applied %d held %d, want %d and %d", applied.Load(), held.Load(), limit, workers*2-limit)
	}
	in(t, f, f.A, func(tx *store.TenantTx) error {
		if n, err := tx.DeletionsApplied(deleteguard.CatGroups, now.Add(-time.Hour)); err != nil || n != limit {
			t.Errorf("ledger holds %d (%v), want %d", n, err, limit)
		}
		return nil
	})
}

func release(t *testing.T, f *storetest.Fixture, id, by string, ords []int, ap deleteguard.Appliers) (res *deleteguard.ReleaseResult, err error) {
	t.Helper()
	err = f.DB.InTenant(context.Background(), f.A.ID, func(tx *store.TenantTx) error {
		var e error
		res, e = deleteguard.Release(tx, now.Add(time.Minute), id, by, ords, ap)
		return e
	})
	return res, err
}

func makeHold(t *testing.T, f *storetest.Fixture, actor string, n int) string {
	t.Helper()
	setPolicy(t, f, f.A, deleteguard.Policy{Category: deleteguard.CatGroups, MaxCount: ten(1), WindowMinutes: 60, Mode: deleteguard.ModeHoldExcess})
	var id string
	in(t, f, f.A, func(tx *store.TenantTx) error {
		d, err := deleteguard.Admit(tx, now, deleteguard.Request{Category: deleteguard.CatGroups, Items: items(n, "g"), Actor: actor, Source: deleteguard.SourceUser})
		id = d.HoldID
		return err
	})
	return id
}

func TestReleaseByTheSameActorIsRefusedAndRevalidates(t *testing.T) {
	f := storetest.TwoTenants(t)
	id := makeHold(t, f, "alice", 5) // g000 applied; g001..g004 held
	var applied []string
	ap := deleteguard.Appliers{"group_delete": func(_ *store.TenantTx, _ time.Time, it *store.DeletionHoldItem) (string, string, error) {
		switch it.Ref {
		case "g002":
			return deleteguard.ItemGone, "already deleted", nil
		case "g003":
			return deleteguard.ItemFailed, "still in use", nil
		}
		applied = append(applied, it.Ref)
		return deleteguard.ItemReleased, "", nil
	}}
	_, err := release(t, f, id, "alice", nil, ap)
	var ge *deleteguard.Error
	if !errors.As(err, &ge) || ge.Code != "same_actor" {
		t.Fatalf("same actor: %v", err)
	}
	if len(applied) != 0 {
		t.Fatalf("applied despite the refusal: %v", applied)
	}
	res, err := release(t, f, id, "bob", nil, ap)
	if err != nil {
		t.Fatal(err)
	}
	if res.Released != 2 || res.Gone != 1 || res.Failed != 1 || res.Status != "released" || fmt.Sprint(applied) != "[g001 g004]" {
		t.Errorf("result %+v applied %v", res, applied)
	}
	// a release is an override: it does not count against the window again
	in(t, f, f.A, func(tx *store.TenantTx) error {
		if n, _ := tx.DeletionsApplied(deleteguard.CatGroups, now.Add(-time.Hour)); n != 1 {
			t.Errorf("window used %d after a release, want the original 1", n)
		}
		h, err := deleteguard.Load(tx, now, id)
		if err != nil {
			return err
		}
		if h.Status != "released" || h.ResolvedBy == nil || *h.ResolvedBy != "bob" {
			t.Errorf("hold %+v", h.DeletionHold)
		}
		return nil
	})
	if _, err := release(t, f, id, "carol", nil, ap); !errors.As(err, &ge) || ge.Code != "hold_resolved" {
		t.Errorf("second release: %v", err)
	}
}

func TestPartialApprovalDiscardsTheRest(t *testing.T) {
	f := storetest.TwoTenants(t)
	id := makeHold(t, f, "alice", 5)
	var applied []string
	ap := deleteguard.Appliers{"group_delete": func(_ *store.TenantTx, _ time.Time, it *store.DeletionHoldItem) (string, string, error) {
		applied = append(applied, it.Ref)
		return deleteguard.ItemReleased, "", nil
	}}
	var ge *deleteguard.Error
	if _, err := release(t, f, id, "bob", []int{9}, ap); !errors.As(err, &ge) || ge.Code != "invalid_items" {
		t.Errorf("unknown item: %v", err)
	}
	res, err := release(t, f, id, "bob", []int{1, 2}, ap)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "partially_released" || res.Released != 2 || res.Discards != 2 || fmt.Sprint(applied) != "[g002 g003]" {
		t.Errorf("result %+v applied %v", res, applied)
	}
}

func TestDiscardAndExpiry(t *testing.T) {
	f := storetest.TwoTenants(t)
	id := makeHold(t, f, "alice", 3)
	in(t, f, f.A, func(tx *store.TenantTx) error {
		if _, err := deleteguard.Discard(tx, now.Add(time.Minute), id, "alice", "oops"); err != nil {
			return err
		}
		h, err := deleteguard.Load(tx, now, id)
		if err != nil {
			return err
		}
		if h.Status != "discarded" || h.Items[0].Status != "discarded" {
			t.Errorf("discarded hold %+v", h.DeletionHold)
		}
		return nil
	})

	// a hold left alone expires as discarded after the configured time (default 7 days)
	in(t, f, f.A, func(tx *store.TenantTx) error {
		d, err := deleteguard.Admit(tx, now.Add(2*time.Hour), deleteguard.Request{Category: deleteguard.CatGroups, Items: items(3, "x"), Actor: "alice"})
		if err != nil {
			return err
		}
		if n, err := deleteguard.ExpireDue(tx, now.Add(2*time.Hour+6*24*time.Hour)); err != nil || n != 0 {
			t.Errorf("expired early: %d %v", n, err)
		}
		if n, err := deleteguard.ExpireDue(tx, now.Add(2*time.Hour+7*24*time.Hour+time.Minute)); err != nil || n != 1 {
			t.Errorf("expired %d, %v", n, err)
		}
		h, err := deleteguard.Load(tx, now, d.HoldID)
		if err != nil {
			return err
		}
		if h.Status != "expired" || h.Items[0].Status != "discarded" {
			t.Errorf("expired hold %+v", h.DeletionHold)
		}
		return nil
	})

	// releasing an overdue hold expires it instead
	f2 := storetest.TwoTenants(t)
	id = makeHold(t, f2, "alice", 3)
	err := f2.DB.InTenant(context.Background(), f2.A.ID, func(tx *store.TenantTx) error {
		_, err := deleteguard.Release(tx, now.Add(8*24*time.Hour), id, "bob", nil, deleteguard.Appliers{})
		var ge *deleteguard.Error
		if !errors.As(err, &ge) || ge.Code != "hold_expired" {
			t.Errorf("release after expiry: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestHoldsOfOneCorrelationJoinOneHold(t *testing.T) {
	f := storetest.TwoTenants(t)
	setPolicy(t, f, f.A, deleteguard.Policy{Category: deleteguard.CatGroups, MaxCount: ten(1), WindowMinutes: 60, Mode: deleteguard.ModeHoldExcess})
	in(t, f, f.A, func(tx *store.TenantTx) error {
		var ids []string
		for i := 0; i < 3; i++ {
			d, err := deleteguard.Admit(tx, now, deleteguard.Request{Category: deleteguard.CatGroups, Items: items(2, fmt.Sprintf("r%d-", i)),
				Source: deleteguard.SourceLoader, SourceID: "ldr", Correlation: "run-1"})
			if err != nil {
				return err
			}
			ids = append(ids, d.HoldID)
		}
		if ids[0] == "" || ids[0] != ids[1] || ids[1] != ids[2] {
			t.Errorf("holds %v", ids)
		}
		h, err := deleteguard.Load(tx, now, ids[0])
		if err != nil {
			return err
		}
		// 1 applied of the first call; 1 + 2 + 2 held
		if h.ItemCount != 5 || len(h.Items) != 5 || h.Source != "loader" || h.SourceID != "ldr" {
			t.Errorf("hold %+v items %d", h.DeletionHold, len(h.Items))
		}
		return nil
	})
}

func TestTenantsDoNotShareAWindow(t *testing.T) {
	f := storetest.TwoTenants(t)
	setPolicy(t, f, f.A, deleteguard.Policy{Category: deleteguard.CatGroups, MaxCount: ten(2), WindowMinutes: 60, Mode: deleteguard.ModeHoldExcess})
	in(t, f, f.A, func(tx *store.TenantTx) error {
		d, err := deleteguard.Admit(tx, now, deleteguard.Request{Category: deleteguard.CatGroups, Items: items(5, "a")})
		if d.NApplied() != 2 {
			t.Errorf("A applied %d", d.NApplied())
		}
		return err
	})
	in(t, f, f.B, func(tx *store.TenantTx) error {
		d, err := deleteguard.Admit(tx, now, deleteguard.Request{Category: deleteguard.CatGroups, Items: items(20, "b")})
		if d.NApplied() != 20 || d.NHeld() != 0 { // B has the default 25
			t.Errorf("B applied %d held %d", d.NApplied(), d.NHeld())
		}
		return err
	})
	in(t, f, f.B, func(tx *store.TenantTx) error {
		hs, err := tx.DeletionHolds("", "", 10, 0)
		if len(hs) != 0 {
			t.Errorf("B sees %d holds", len(hs))
		}
		return err
	})
}

func TestLoosens(t *testing.T) {
	base := deleteguard.Policy{Category: "groups", MaxCount: ten(25), WindowMinutes: 60, Mode: deleteguard.ModeHoldExcess}
	pct := 5.0
	cases := []struct {
		name string
		mut  func(p *deleteguard.Policy)
		want bool
	}{
		{"same", func(p *deleteguard.Policy) {}, false},
		{"lower count", func(p *deleteguard.Policy) { p.MaxCount = ten(10) }, false},
		{"higher count", func(p *deleteguard.Policy) { p.MaxCount = ten(26) }, true},
		{"same rate, longer window", func(p *deleteguard.Policy) { p.MaxCount = ten(50); p.WindowMinutes = 120 }, false},
		{"higher rate, shorter window", func(p *deleteguard.Policy) { p.WindowMinutes = 30 }, true},
		{"count swapped for a percent that allows more", func(p *deleteguard.Policy) { p.MaxCount = nil; p.MaxPercent = &pct }, true},
		{"percent added to a count", func(p *deleteguard.Policy) { p.MaxPercent = &pct }, false},
		{"count tightened and percent dropped", func(p *deleteguard.Policy) { p.MaxCount = ten(2) }, false},
		{"hold_all is stricter", func(p *deleteguard.Policy) { p.Mode = deleteguard.ModeHoldAll }, false},
		{"off", func(p *deleteguard.Policy) { p.Mode = deleteguard.ModeOff }, true},
	}
	for _, c := range cases {
		next := base
		c.mut(&next)
		if got := deleteguard.Loosens(base, next, 1000); got != c.want {
			t.Errorf("%s: Loosens = %v, want %v", c.name, got, c.want)
		}
	}
	off := base
	off.Mode = deleteguard.ModeOff
	if !deleteguard.Loosens(base, off, 1000) || deleteguard.Loosens(off, base, 1000) {
		t.Errorf("turning on is tightening and turning off is loosening")
	}
}

func TestPolicyCheck(t *testing.T) {
	bad := []deleteguard.Policy{
		{Category: "nope", MaxCount: ten(1), WindowMinutes: 60, Mode: deleteguard.ModeHoldAll},
		{Category: "groups", MaxCount: ten(1), WindowMinutes: 0, Mode: deleteguard.ModeHoldAll},
		{Category: "groups", MaxCount: ten(1), WindowMinutes: 60, Mode: "weird"},
		{Category: "groups", WindowMinutes: 60, Mode: deleteguard.ModeHoldAll},
		{Category: "groups", MaxCount: ten(-1), WindowMinutes: 60, Mode: deleteguard.ModeHoldAll},
	}
	for i, p := range bad {
		if p.Check() == nil {
			t.Errorf("case %d accepted: %+v", i, p)
		}
	}
}
