package guestlife_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	guestlife "github.com/nischalravi/tessera/mvp/server/internal/guests/lifecycle"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/sponsorship"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

var now = storetest.Now

func day(n int) time.Time { return now.AddDate(0, 0, n) }

type env struct {
	t     *testing.T
	f     *storetest.Fixture
	sp    *sponsorship.Service
	gl    *guestlife.Service
	carol sponsorship.Actor // Bob's and Alice's manager, an eligible sponsor
	bob   sponsorship.Actor
	admin sponsorship.Actor // holds sponsorships.approve, is nobody's identity
	alice sponsorship.Actor // neither a manager of Bob nor an approver
}

func actor(name string, id *int64, approver bool) sponsorship.Actor {
	return sponsorship.Actor{UserID: uuid.New(), Display: name, IdentityID: id, Approver: approver}
}

func newEnv(t *testing.T) *env {
	t.Helper()
	f := storetest.TwoTenants(t)
	carol, bob, alice := f.B.IDs["carol"], f.B.IDs["bob"], f.B.IDs["alice"]
	sp := sponsorship.New(storetest.IdentityKeyer(t))
	gl := guestlife.New(sp)
	gl.Secrets, gl.BaseURL = notify.NewSecrets(), "https://tessera.example"
	return &env{t: t, f: f, sp: sp, gl: gl, carol: actor("Carol", &carol, false), bob: actor("Bob", &bob, false),
		admin: actor("Pat", nil, true), alice: actor("Alice", &alice, false)}
}

func (e *env) do(fn func(tx *store.TenantTx) error) error {
	e.t.Helper()
	return e.f.DB.InTenant(context.Background(), e.f.B.ID, fn)
}

func (e *env) must(fn func(tx *store.TenantTx) error) {
	e.t.Helper()
	if err := e.do(fn); err != nil {
		e.t.Fatal(err)
	}
}

func code(err error) string {
	var ge *guestlife.Error
	if errors.As(err, &ge) {
		return ge.Code
	}
	var se *sponsorship.Error
	if errors.As(err, &se) {
		return se.Code
	}
	if err == nil {
		return ""
	}
	return "other: " + err.Error()
}

func (e *env) wantCode(err error, want string) {
	e.t.Helper()
	if code(err) != want {
		e.t.Errorf("error = %v, want code %s", err, want)
	}
}

// invite makes `by` sponsor a new contractor who is claimed (active) at once, so
// reminders and the guest's own rights apply.
func (e *env) invite(by sponsorship.Actor, email string, ends int) *store.Sponsorship {
	e.t.Helper()
	var ss *store.Sponsorship
	e.must(func(tx *store.TenantTx) error {
		r, err := e.sp.Invite(tx, by, sponsorship.Invite{GivenName: "Gwen", FamilyName: "Guest", Email: email, Population: "contractor",
			Purpose: "project", EndsAt: day(ends)}, store.ChannelSponsorInvite, "", now)
		if r != nil {
			ss = r.Sponsorship
		}
		return err
	})
	return ss
}

// claimed does what a completed claim does to the person.
func (e *env) claimed(guest int64, ial int) {
	e.t.Helper()
	e.must(func(tx *store.TenantTx) error {
		if err := tx.SetIdentityStatus(guest, "active"); err != nil {
			return err
		}
		all, err := tx.Sponsorships(store.SponsorshipFilter{Guest: guest})
		if err != nil {
			return err
		}
		for _, s := range all {
			affs, err := tx.AffiliationsFor(guest)
			if err != nil {
				return err
			}
			for _, a := range affs {
				if a.SourceRef != nil && *a.SourceRef == s.ID && a.Status == store.AffPending {
					if err := tx.ActivateAffiliation(a.ID); err != nil {
						return err
					}
				}
			}
		}
		return tx.PutIdentityAssurance(&store.Assurance{IdentityID: guest, IAL: ial, AAL: 1, Source: "claim", RecordedAt: now})
	})
}

func (e *env) get(id string) (s *store.Sponsorship) {
	e.t.Helper()
	e.must(func(tx *store.TenantTx) (err error) { s, err = tx.Sponsorship(id); return err })
	return s
}

func (e *env) person(id int64) (p *store.Identity) {
	e.t.Helper()
	e.must(func(tx *store.TenantTx) (err error) { p, err = tx.Identity(id); return err })
	return p
}

func (e *env) tasks(f store.LifecycleTaskFilter) (ts []*store.LifecycleTask) {
	e.t.Helper()
	e.must(func(tx *store.TenantTx) (err error) { ts, err = tx.LifecycleTasks(f); return err })
	return ts
}

func (e *env) audits() map[string]int {
	e.t.Helper()
	out := map[string]int{}
	e.must(func(tx *store.TenantTx) error {
		evs, err := tx.AuditLog(-1)
		for _, ev := range evs {
			out[ev.Action]++
		}
		return err
	})
	return out
}

func (e *env) settings(mut func(s *store.GuestLifecycleSettings)) {
	e.t.Helper()
	e.must(func(tx *store.TenantTx) error {
		s, err := tx.GuestLifecycleSettings()
		if err != nil {
			return err
		}
		mut(&s)
		_, err = guestlife.PutSettings(tx, s, e.admin, now)
		return err
	})
}

// leaves is what the HRIS leaver event does to a sponsor, then the lifecycle hook.
func (e *env) leaves(id int64, typ string, at time.Time) (n int) {
	e.t.Helper()
	e.must(func(tx *store.TenantTx) (err error) {
		if typ == "leaver" {
			if err := tx.TerminateIdentity(id, at); err != nil {
				return err
			}
		}
		n, err = e.gl.OnEvent(tx, typ, id, at)
		return err
	})
	return n
}

func (e *env) resolve(by sponsorship.Actor, task, action string, at time.Time) error {
	return e.do(func(tx *store.TenantTx) error { _, err := e.gl.Resolve(tx, by, task, action, at); return err })
}

func TestSponsorLeaver_TransfersOrEnds(t *testing.T) {
	e := newEnv(t)
	bob, carol := e.f.B.IDs["bob"], e.f.B.IDs["carol"]
	a := e.invite(e.bob, "a@x.example", 60)
	b := e.invite(e.bob, "b@x.example", 60)
	if n := e.leaves(bob, "leaver", now); n != 2 {
		t.Fatalf("transfer tasks opened = %d, want 2 (one per sponsorship)", n)
	}
	if n := e.leaves(bob, "leaver", now); n != 0 {
		t.Errorf("the event ran twice and opened %d more tasks", n)
	}
	ts := e.tasks(store.LifecycleTaskFilter{Status: store.TaskOpen})
	if len(ts) != 2 {
		t.Fatalf("open tasks = %d", len(ts))
	}
	for _, task := range ts {
		if task.Kind != store.TaskSponsorTransfer || task.Trigger != store.TaskTriggerLeaver || task.SubjectIdentityID != bob ||
			task.Deadline == nil || !task.Deadline.Equal(day(14)) {
			t.Errorf("task = %+v", task)
		}
	}
	// until the deadline the sponsorships stand, still named for the departed sponsor
	if s := e.get(a.ID); s.Status != store.SponsorActive || s.SponsorIdentityID != bob {
		t.Errorf("before any decision = %+v", s)
	}
	taskOf := func(ss *store.Sponsorship) string {
		for _, task := range ts {
			if task.SponsorshipID == ss.ID {
				return task.ID
			}
		}
		t.Fatal("no task for " + ss.ID)
		return ""
	}
	// only Bob's manager and the sponsor admins decide; for anyone else the task is not there
	e.wantCode(e.resolve(e.alice, taskOf(a), guestlife.ActionAccept, day(1)), "task_not_found")
	e.wantCode(e.resolve(e.carol, taskOf(a), "nonsense", day(1)), "invalid_action")
	e.wantCode(e.resolve(e.carol, taskOf(a), guestlife.ActionKeep, day(1)), "invalid_action") // only after a move
	// accepting moves the sponsorship, after a fresh policy check as the new sponsor
	if err := e.resolve(e.carol, taskOf(a), guestlife.ActionAccept, day(1)); err != nil {
		t.Fatal(err)
	}
	if s := e.get(a.ID); s.Status != store.SponsorActive || s.SponsorIdentityID != carol {
		t.Errorf("accepted = %+v", s)
	}
	e.wantCode(e.resolve(e.carol, taskOf(a), guestlife.ActionAccept, day(1)), "not_open")
	// declining ends the sponsorship (the default), and with it the person
	if err := e.resolve(e.admin, taskOf(b), guestlife.ActionDecline, day(2)); err != nil {
		t.Fatal(err)
	}
	if s := e.get(b.ID); s.Status != store.SponsorEnded || s.EndReason == nil || !strings.Contains(*s.EndReason, "transfer was declined") {
		t.Errorf("declined = %+v", s)
	}
	// nothing is left waiting: the deadline sweep has nothing to end
	e.must(func(tx *store.TenantTx) error {
		if n, err := e.gl.ExpireTasks(tx, day(15)); err != nil || n != 0 {
			t.Errorf("ExpireTasks = %d, %v", n, err)
		}
		return nil
	})
	// the deadline passing ends a sponsorship nobody took over
	c := e.invite(e.carol, "c@x.example", 60)
	e.must(func(tx *store.TenantTx) error {
		// Alice, a contractor's sponsor? she is an employee: she sponsors, then moves
		return nil
	})
	d := e.invite(e.alice, "d@x.example", 60)
	if n := e.leaves(e.f.B.IDs["alice"], "mover", now); n != 1 {
		t.Fatalf("a mover's sponsorships = %d tasks", n)
	}
	e.must(func(tx *store.TenantTx) error {
		if n, err := e.gl.ExpireTasks(tx, day(13)); err != nil || n != 0 {
			t.Errorf("before the deadline: %d, %v", n, err)
		}
		if n, err := e.gl.ExpireTasks(tx, day(14)); err != nil || n != 1 {
			t.Errorf("at the deadline: %d, %v", n, err)
		}
		return nil
	})
	if s := e.get(d.ID); s.Status != store.SponsorEnded {
		t.Errorf("after the deadline = %+v", s)
	}
	if s := e.get(c.ID); s.Status != store.SponsorActive {
		t.Errorf("an unrelated sponsorship changed: %+v", s)
	}
	au := e.audits()
	if au["guestlife.transfer_task.open"] != 3 || au["guestlife.task.accept"] != 1 || au["guestlife.task.decline"] != 1 ||
		au["guestlife.transfer_task.expire"] != 1 || au["sponsorship.accept_transfer"] != 1 {
		t.Errorf("audit = %v", au)
	}
}

func TestSponsorLeaver_SuspendSetting(t *testing.T) {
	e := newEnv(t)
	bob := e.f.B.IDs["bob"]
	e.settings(func(s *store.GuestLifecycleSettings) { s.OnSponsorDeparture, s.TransferDeadlineDays = "suspend", 7 })
	a := e.invite(e.bob, "a@x.example", 60)
	b := e.invite(e.bob, "b@x.example", 60)
	e.claimed(a.GuestIdentityID, 1)
	// the sweep finds a sponsor who is no longer eligible without any event
	e.must(func(tx *store.TenantTx) error {
		if err := tx.TerminateIdentity(bob, now); err != nil {
			return err
		}
		n, err := e.gl.ScanDepartures(tx, now)
		if n != 2 {
			t.Errorf("ScanDepartures = %d, %v", n, err)
		}
		return err
	})
	ts := e.tasks(store.LifecycleTaskFilter{Status: store.TaskOpen})
	if len(ts) != 2 || !ts[0].Deadline.Equal(day(7)) {
		t.Fatalf("tasks = %+v", ts)
	}
	// declining and the deadline both suspend instead of ending
	var onA, onB string
	for _, task := range ts {
		if task.SponsorshipID == a.ID {
			onA = task.ID
		} else {
			onB = task.ID
		}
	}
	if err := e.resolve(e.admin, onA, guestlife.ActionDecline, day(1)); err != nil {
		t.Fatal(err)
	}
	e.must(func(tx *store.TenantTx) error {
		_, err := e.gl.ExpireTasks(tx, day(7))
		return err
	})
	for _, id := range []string{a.ID, b.ID} {
		s := e.get(id)
		if s.Status != store.SponsorSuspended || s.EndedAt != nil || s.Live() {
			t.Errorf("sponsorship %s = %+v, want suspended and not final", id, s)
		}
		e.must(func(tx *store.TenantTx) error {
			affs, err := tx.AffiliationsFor(s.GuestIdentityID)
			for _, af := range affs {
				if af.SourceRef != nil && *af.SourceRef == id && (af.Status == store.AffActive || af.Status == store.AffPending) {
					t.Errorf("a suspended sponsorship still has a running affiliation: %+v", af)
				}
			}
			return err
		})
	}
	got := e.tasks(store.LifecycleTaskFilter{Kind: store.TaskSponsorTransfer})
	for _, task := range got {
		if task.Outcome == nil || *task.Outcome != store.OutcomeSuspended {
			t.Errorf("task outcome = %v", task.Outcome)
		}
	}
	_ = onB
	e.must(func(tx *store.TenantTx) error {
		c, err := guestlife.Counts(tx, day(8))
		if c[guestlife.BucketAutoEnded] != 2 || c[guestlife.BucketSuspended] != 2 || c[guestlife.BucketPendingTransfer] != 0 {
			t.Errorf("counts = %v", c)
		}
		return err
	})
	// a suspended sponsorship ends for good at its own end date, and the sponsor admin can end it sooner
	e.must(func(tx *store.TenantTx) error {
		_, err := e.sp.End(tx, e.admin, a.ID, "not coming back", day(9))
		return err
	})
	if s := e.get(a.ID); s.Status != store.SponsorRevoked || s.EndedAt == nil {
		t.Errorf("an admin ended a suspended sponsorship: %+v", s)
	}
	e.must(func(tx *store.TenantTx) error { _, err := e.sp.Sweep(tx, day(61)); return err })
	if s := e.get(b.ID); s.Status != store.SponsorEnded {
		t.Errorf("a suspended sponsorship at its end date = %+v", s)
	}
}

func TestSponsorLeaver_MoverCanKeepOrLose(t *testing.T) {
	e := newEnv(t)
	alice := e.f.B.IDs["alice"]
	a := e.invite(e.alice, "a@x.example", 60)
	if n := e.leaves(alice, "mover", now); n != 1 {
		t.Fatalf("tasks = %d", n)
	}
	task := e.tasks(store.LifecycleTaskFilter{Status: store.TaskOpen})[0]
	// Alice's manager (Carol) asks to keep her as the sponsor: she is still eligible
	if err := e.resolve(e.carol, task.ID, guestlife.ActionKeep, day(1)); err != nil {
		t.Fatal(err)
	}
	if s := e.get(a.ID); s.Status != store.SponsorActive || s.SponsorIdentityID != alice {
		t.Errorf("kept = %+v", s)
	}
	// a sponsor who left cannot be kept
	b := e.invite(e.alice, "b@x.example", 60)
	e.leaves(alice, "mover", day(2))
	e.must(func(tx *store.TenantTx) error { return tx.TerminateIdentity(alice, day(2)) })
	for _, task := range e.tasks(store.LifecycleTaskFilter{Status: store.TaskOpen}) {
		if task.SponsorshipID == b.ID {
			e.wantCode(e.resolve(e.admin, task.ID, guestlife.ActionKeep, day(3)), "sponsor_not_eligible")
		}
	}
}

func TestExpiry_LastSponsorshipEndsIdentity(t *testing.T) {
	e := newEnv(t)
	first := e.invite(e.bob, "g@x.example", 10)
	guest := first.GuestIdentityID
	e.claimed(guest, 1)
	var second *store.Sponsorship
	e.must(func(tx *store.TenantTx) error {
		r, err := e.sp.SponsorExisting(tx, e.carol, guest, sponsorship.Invite{Population: "contractor", Purpose: "second project", EndsAt: day(30)}, now)
		if r != nil {
			second = r.Sponsorship
		}
		return err
	})
	sweep := func(at time.Time) {
		e.must(func(tx *store.TenantTx) error {
			if _, err := e.sp.Sweep(tx, at); err != nil {
				return err
			}
			_, err := e.gl.Sweep(tx, at)
			return err
		})
	}
	sweep(day(5))
	if p := e.person(guest); p.Status != "active" {
		t.Fatalf("before any end: %s", p.Status)
	}
	sweep(day(11)) // the first sponsorship ended: the person stays active on the second
	if s := e.get(first.ID); s.Status != store.SponsorEnded {
		t.Errorf("first = %+v", s)
	}
	if s := e.get(second.ID); s.Status != store.SponsorActive {
		t.Errorf("second = %+v", s)
	}
	p := e.person(guest)
	if p.Status != "active" {
		t.Errorf("one sponsorship ended and the person became %s", p.Status)
	}
	e.must(func(tx *store.TenantTx) error {
		l, err := tx.LifecycleFor(guest)
		if err != nil || l.EndedAt != nil || l.EndsAt == nil || !l.EndsAt.Equal(day(30)) {
			t.Errorf("lifecycle after the first end = %+v, %v", l, err)
		}
		if _, err := tx.Deprovisioning(guest); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("deprovisioning started while a sponsorship stands: %v", err)
		}
		return nil
	})
	sweep(day(31)) // the last one ended: the person ends, and their grace period starts
	if s := e.get(second.ID); s.Status != store.SponsorEnded {
		t.Errorf("second after its end = %+v", s)
	}
	if p := e.person(guest); p.Status != "terminated" {
		t.Errorf("after the last end the person is %s", p.Status)
	}
	e.must(func(tx *store.TenantTx) error {
		l, err := tx.LifecycleFor(guest)
		if err != nil || l.EndedAt == nil {
			t.Errorf("lifecycle = %+v, %v", l, err)
		}
		d, err := tx.Deprovisioning(guest)
		if err != nil || d.Stage != store.StageGrace || d.Population != "contractor" ||
			!d.GraceUntil.Equal(d.EndedAt.AddDate(0, 0, 30)) {
			t.Errorf("deprovisioning = %+v, %v", d, err)
		}
		return nil
	})
}
