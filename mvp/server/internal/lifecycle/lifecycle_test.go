package lifecycle_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nischalravi/tessera/mvp/server/internal/lifecycle"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// The fixture is the tiny world (connectors.Tiny) in tenant B: alice and
// carol are active Engineering employees with okta accounts (alice in
// okta:eng), dave is terminated, svc-etl is a service account.

type world struct {
	t              *testing.T
	f              *storetest.Fixture
	ids            map[string]int64
	pat, carol, al lifecycle.Actor
	now            time.Time
}

func newWorld(t *testing.T) *world {
	t.Helper()
	f := storetest.TwoTenants(t)
	w := &world{t: t, f: f, ids: f.B.IDs, now: storetest.Now}
	w.tx(func(c *store.TenantTx) error {
		carol, alice := w.ids["carol"], w.ids["alice"]
		for _, u := range []struct {
			a     *lifecycle.Actor
			name  string
			ident *int64
		}{{&w.pat, "Pat", nil}, {&w.carol, "Carol", &carol}, {&w.al, "Alice", &alice}} {
			pu := &store.PlatformUser{DisplayName: u.name, IdentityID: u.ident, CreatedAt: w.now}
			if err := c.InsertPlatformUser(pu); err != nil {
				return err
			}
			*u.a = lifecycle.Actor{UserID: pu.ID, Display: u.name, IdentityID: u.ident}
		}
		return nil
	})
	return w
}

func (w *world) tx(fn func(c *store.TenantTx) error) {
	w.t.Helper()
	if err := w.f.DB.InTenant(context.Background(), w.f.B.ID, fn); err != nil {
		w.t.Fatal(err)
	}
}

func code(err error) string {
	var e *lifecycle.Error
	if errors.As(err, &e) {
		return e.Code
	}
	if err != nil {
		return "error: " + err.Error()
	}
	return ""
}

func at(t time.Time) *time.Time { return &t }

func (w *world) contractor(days int) lifecycle.Spec {
	carol := w.ids["carol"]
	return lifecycle.Spec{WorkerType: store.WorkerContractor, SponsorID: &carol, EndsAt: at(w.now.Add(time.Duration(days) * 24 * time.Hour)),
		Reason: "statement of work 42"}
}

func TestSet_Validation(t *testing.T) {
	w := newWorld(t)
	alice, carol, dave := w.ids["alice"], w.ids["carol"], w.ids["dave"]
	cases := map[string]struct {
		id   int64
		spec lifecycle.Spec
	}{
		"reason_required":     {alice, lifecycle.Spec{WorkerType: store.WorkerContractor}},
		"invalid_worker_type": {alice, lifecycle.Spec{WorkerType: "robot", Reason: "x"}},
		"end_required":        {alice, lifecycle.Spec{WorkerType: store.WorkerContractor, SponsorID: &carol, Reason: "x"}},
		"sponsor_required":    {alice, lifecycle.Spec{WorkerType: store.WorkerVendor, EndsAt: at(w.now.Add(48 * time.Hour)), Reason: "x"}},
		"invalid_end":         {alice, lifecycle.Spec{WorkerType: store.WorkerContractor, SponsorID: &carol, EndsAt: at(w.now.Add(-time.Hour)), Reason: "x"}},
		"term_too_long":       {alice, w.contractor(400)},
		"sponsor_is_self":     {carol, w.contractor(30)},
		"sponsor_not_active": {alice, lifecycle.Spec{WorkerType: store.WorkerContractor, SponsorID: &dave,
			EndsAt: at(w.now.Add(48 * time.Hour)), Reason: "x"}},
		"not_a_person":        {w.ids["svc-etl"], w.contractor(30)},
		"identity_not_active": {dave, w.contractor(30)},
		"identity_not_found":  {w.f.A.IDs["alice"], w.contractor(30)}, // another tenant's person
	}
	w.tx(func(c *store.TenantTx) error {
		for want, tc := range cases {
			if _, err := lifecycle.Set(c, tc.id, tc.spec, w.pat, w.now); code(err) != want {
				t.Errorf("%s: got %v", want, err)
			}
		}
		// a contractor cannot sponsor
		if _, err := lifecycle.Set(c, carol, lifecycle.Spec{WorkerType: store.WorkerContractor, SponsorID: &alice,
			EndsAt: at(w.now.Add(240 * time.Hour)), Reason: "x"}, w.pat, w.now); err != nil {
			return err
		}
		if _, err := lifecycle.Set(c, alice, w.contractor(30), w.pat, w.now); code(err) != "sponsor_not_employee" {
			t.Errorf("contractor sponsor = %v", err)
		}
		return nil
	})
}

func TestSweep_WarnsThenEndsWithLeaverPlan(t *testing.T) {
	w := newWorld(t)
	alice := w.ids["alice"]
	w.tx(func(c *store.TenantTx) error {
		l, err := lifecycle.Set(c, alice, w.contractor(20), w.pat, w.now)
		if err != nil {
			return err
		}
		if s := lifecycle.State(l, w.now); s != lifecycle.StateActive {
			t.Errorf("state = %s", s)
		}
		if need, _ := lifecycle.NeedsSweep(c, w.now); need {
			t.Error("nothing is due at day 0")
		}
		return nil
	})
	day := func(n float64) time.Time { return w.now.Add(time.Duration(n * 24 * float64(time.Hour))) }
	sweep := func(at time.Time) lifecycle.SweepResult {
		var r lifecycle.SweepResult
		w.tx(func(c *store.TenantTx) error {
			var err error
			r, err = lifecycle.Sweep(c, at)
			return err
		})
		return r
	}
	if r := sweep(day(7)); r.Warned != 1 || r.Ended != 0 { // 13 days left: the 14-day warning
		t.Fatalf("day 7 = %+v", r)
	}
	if r := sweep(day(7.5)); r.Warned != 0 { // already sent
		t.Fatalf("day 7.5 = %+v", r)
	}
	if r := sweep(day(14)); r.Warned != 1 { // 6 days left: the 7-day warning
		t.Fatalf("day 14 = %+v", r)
	}
	if r := sweep(day(20)); r.Ended != 1 {
		t.Fatalf("day 20 = %+v", r)
	}
	w.tx(func(c *store.TenantTx) error {
		p, err := c.Identity(alice)
		if err != nil {
			return err
		}
		if p.Status != "terminated" {
			t.Errorf("alice is %s", p.Status)
		}
		accts, err := c.IdentityAccounts(alice)
		if err != nil {
			return err
		}
		for _, a := range accts {
			if a.Status == "active" {
				t.Errorf("%s account still active", a.System)
			}
		}
		l, err := c.LifecycleFor(alice)
		if err != nil || l.EndedAt == nil || lifecycle.State(l, day(21)) != lifecycle.StateEnded {
			t.Errorf("lifecycle = %+v, %v", l, err)
		}
		evs, err := c.LifecycleEvents(alice)
		if err != nil {
			return err
		}
		var kinds []string
		for _, e := range evs {
			kinds = append(kinds, e.Event)
		}
		if len(kinds) != 4 || kinds[0] != "set" || kinds[1] != "warned" || kinds[2] != "warned" || kinds[3] != "ended" {
			t.Errorf("history = %v", kinds)
		}
		log, err := c.AuditLog(10)
		if err != nil {
			return err
		}
		acts := map[string]int{}
		for _, e := range log {
			acts[e.Action]++
		}
		if acts["lifecycle.end"] != 1 || acts["lifecycle.warn"] != 2 || acts["lifecycle.set"] != 1 {
			t.Errorf("audit = %v", acts)
		}
		if need, _ := lifecycle.NeedsSweep(c, day(30)); need {
			t.Error("an ended term is still due")
		}
		return nil
	})
}

func TestSweep_AlreadyTerminatedIsOnlyMarked(t *testing.T) {
	w := newWorld(t)
	alice := w.ids["alice"]
	w.tx(func(c *store.TenantTx) error {
		if _, err := lifecycle.Set(c, alice, w.contractor(2), w.pat, w.now); err != nil {
			return err
		}
		if err := c.TerminateIdentity(alice, w.now); err != nil { // the HRIS leaver ran first
			return err
		}
		r, err := lifecycle.Sweep(c, w.now.Add(72*time.Hour))
		if err != nil || r.Ended != 1 {
			t.Errorf("sweep = %+v, %v", r, err)
		}
		return nil
	})
}

func TestExtend(t *testing.T) {
	w := newWorld(t)
	alice := w.ids["alice"]
	later := w.now.Add(60 * 24 * time.Hour)
	w.tx(func(c *store.TenantTx) error {
		if _, err := lifecycle.Set(c, alice, w.contractor(10), w.pat, w.now); err != nil {
			return err
		}
		if _, err := lifecycle.Sweep(c, w.now); err != nil { // the 14-day warning
			return err
		}
		if _, err := lifecycle.Extend(c, alice, later, "renewed", w.al, false, w.now); code(err) != "not_sponsor" {
			t.Errorf("alice extends herself = %v", err)
		}
		if _, err := lifecycle.Extend(c, alice, later, "renewed", w.al, true, w.now); code(err) != "self_extension" {
			t.Errorf("admin alice extends herself = %v", err)
		}
		unlinked := lifecycle.Actor{UserID: uuid.New(), Display: "unlinked"}
		if _, err := lifecycle.Extend(c, alice, later, "renewed", unlinked, true, w.now); code(err) != "actor_unlinked" {
			t.Errorf("unlinked manager extends = %v", err)
		}
		if _, err := lifecycle.Extend(c, alice, w.now.Add(time.Hour), "x", w.carol, false, w.now); code(err) != "not_later" {
			t.Errorf("earlier = %v", err)
		}
		if _, err := lifecycle.Extend(c, alice, w.now.Add(400*24*time.Hour), "x", w.carol, false, w.now); code(err) != "term_too_long" {
			t.Errorf("too long = %v", err)
		}
		l, err := lifecycle.Extend(c, alice, later, "renewed for Q3", w.carol, false, w.now)
		if err != nil {
			return err
		}
		if l.WarnedDays != nil || !l.EndsAt.Equal(later) {
			t.Errorf("extended = %+v", l)
		}
		if need, _ := lifecycle.NeedsSweep(c, w.now.Add(24*time.Hour)); need {
			t.Error("an extended term is still due")
		}
		return nil
	})
	if _, err := w.extendBy(w.ids["bob"], later); code(err) != "no_end_date" {
		t.Errorf("bob has no term: %v", err)
	}
}

func (w *world) extendBy(id int64, to time.Time) (*store.Lifecycle, error) {
	var l *store.Lifecycle
	var e error
	w.tx(func(c *store.TenantTx) error {
		l, e = lifecycle.Extend(c, id, to, "x", w.pat, true, w.now)
		return nil
	})
	return l, e
}

func TestConvertToEmployee(t *testing.T) {
	w := newWorld(t)
	alice := w.ids["alice"]
	w.tx(func(c *store.TenantTx) error {
		if _, err := lifecycle.Set(c, alice, w.contractor(10), w.pat, w.now); err != nil {
			return err
		}
		l, err := lifecycle.Set(c, alice, lifecycle.Spec{WorkerType: store.WorkerEmployee, Reason: "hired"}, w.pat, w.now)
		if err != nil {
			return err
		}
		if l.EndsAt != nil || lifecycle.State(l, w.now.Add(30*24*time.Hour)) != lifecycle.StateActive {
			t.Errorf("converted = %+v", l)
		}
		evs, _ := c.LifecycleEvents(alice)
		if len(evs) != 2 || evs[1].Event != "converted" {
			t.Errorf("history = %+v", evs)
		}
		if need, _ := lifecycle.NeedsSweep(c, w.now.Add(30*24*time.Hour)); need {
			t.Error("an employee is due")
		}
		return nil
	})
}

func TestUpcomingState(t *testing.T) {
	w := newWorld(t)
	spec := w.contractor(30)
	spec.StartsAt = at(w.now.Add(5 * 24 * time.Hour))
	w.tx(func(c *store.TenantTx) error {
		l, err := lifecycle.Set(c, w.ids["alice"], spec, w.pat, w.now)
		if err != nil {
			return err
		}
		if s := lifecycle.State(l, w.now); s != lifecycle.StateUpcoming {
			t.Errorf("state = %s", s)
		}
		bad := spec
		bad.StartsAt = at(w.now.Add(40 * 24 * time.Hour))
		if _, err := lifecycle.Set(c, w.ids["alice"], bad, w.pat, w.now); code(err) != "invalid_end" {
			t.Errorf("end before start = %v", err)
		}
		return nil
	})
}
