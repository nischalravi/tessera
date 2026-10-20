package guestlife_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/guests/claim"
	guestlife "github.com/nischalravi/tessera/mvp/server/internal/guests/lifecycle"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/sponsorship"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func (e *env) remind(gl *guestlife.Service, at time.Time) (res guestlife.RemindResult) {
	e.t.Helper()
	e.must(func(tx *store.TenantTx) (err error) { res, err = gl.Remind(tx, at); return err })
	return res
}

func TestReminders_SentOncePerThresholdAcrossSweepsAndRestarts(t *testing.T) {
	e := newEnv(t)
	ss := e.invite(e.carol, "g@x.example", 40)
	e.claimed(ss.GuestIdentityID, 1)
	count := func(aud string) (n int) {
		e.must(func(tx *store.TenantTx) (err error) { n, err = tx.CountReminders(ss.ID, aud); return err })
		return n
	}
	// nothing is due 40 days out; 29 days out the 30-day sponsor reminder is
	if r := e.remind(e.gl, day(0)); r.Sponsor != 0 || r.Guest != 0 {
		t.Errorf("day 0 = %+v", r)
	}
	if r := e.remind(e.gl, day(11)); r.Sponsor != 1 || r.Guest != 0 {
		t.Errorf("day 11 = %+v", r)
	}
	// the same sweep again, the next day, and a restarted service: still one
	restarted := guestlife.New(e.sp)
	restarted.Secrets, restarted.BaseURL = e.gl.Secrets, e.gl.BaseURL
	for _, d := range []int{11, 12, 20} {
		for _, gl := range []*guestlife.Service{e.gl, restarted} {
			if r := e.remind(gl, day(d)); r.Sponsor != 0 || r.Guest != 0 {
				t.Errorf("day %d repeated the reminder: %+v", d, r)
			}
		}
	}
	// 14 days left: the 14-day sponsor reminder and the guest's, with a link
	if r := e.remind(restarted, day(26)); r.Sponsor != 1 || r.Guest != 1 {
		t.Errorf("day 26 = %+v", r)
	}
	if e.gl.Secrets.Len() != 1 {
		t.Errorf("the guest's renewal link was not handed to the mailer: %d held", e.gl.Secrets.Len())
	}
	var tokens []*store.RenewalToken
	e.must(func(tx *store.TenantTx) (err error) { tokens, err = tx.RenewalTokensFor(ss.ID); return err })
	if len(tokens) != 1 || tokens[0].Status != store.TokenIssued || len(tokens[0].TokenHash) != 64 || !tokens[0].ExpiresAt.Equal(ss.EndsAt) {
		t.Errorf("tokens = %+v", tokens)
	}
	if r := e.remind(e.gl, day(27)); r.Sponsor != 0 || r.Guest != 0 {
		t.Errorf("day 27 repeated: %+v", r)
	}
	if r := e.remind(e.gl, day(37)); r.Sponsor != 1 || r.Guest != 0 { // 3 days left
		t.Errorf("day 37 = %+v", r)
	}
	if count(store.AudienceSponsor) != 3 || count(store.AudienceGuest) != 1 {
		t.Errorf("recorded reminders: sponsor %d, guest %d", count(store.AudienceSponsor), count(store.AudienceGuest))
	}
	if a := e.audits(); a["guestlife.reminder"] != 4 {
		t.Errorf("audit = %v", a)
	}
	// a renewal moves the end date and arms the reminders again
	e.must(func(tx *store.TenantTx) error {
		_, err := e.sp.Renew(tx, e.carol, ss.ID, day(80), "more work", day(38))
		return err
	})
	if r := e.remind(e.gl, day(52)); r.Sponsor != 1 { // 28 days before day 80
		t.Errorf("after the renewal = %+v", r)
	}
	// the guest with no claim cannot ask for a renewal: no reminder, no token
	other := e.invite(e.carol, "u@x.example", 14)
	before := e.gl.Secrets.Len()
	e.remind(e.gl, day(1))
	if e.gl.Secrets.Len() != before {
		t.Errorf("an unclaimed guest was sent a renewal link for %s", other.ID)
	}
}

func TestRenewalRequest_TokenIsSingleUseAndOpensATask(t *testing.T) {
	e := newEnv(t)
	ss := e.invite(e.carol, "g@x.example", 20)
	e.claimed(ss.GuestIdentityID, 1)
	token := claim.NewToken()
	e.must(func(tx *store.TenantTx) error {
		return tx.InsertRenewalToken(&store.RenewalToken{ID: uuid.NewString(), SponsorshipID: ss.ID, GuestIdentityID: ss.GuestIdentityID,
			TokenHash: claim.HashToken(tx.Tenant(), token), ExpiresAt: ss.EndsAt, CreatedAt: now})
	})
	request := func(tok string, at time.Time) {
		e.must(func(tx *store.TenantTx) error { return e.gl.RequestRenewal(tx, tok, at) })
	}
	for _, bad := range []string{"", "short", claim.NewToken(), token + "x"} {
		request(bad, day(1)) // answers nothing, whatever is wrong
	}
	if ts := e.tasks(store.LifecycleTaskFilter{Kind: store.TaskRenewalRequest}); len(ts) != 0 {
		t.Fatalf("a bad token opened a task: %+v", ts)
	}
	request(token, day(1))
	ts := e.tasks(store.LifecycleTaskFilter{Kind: store.TaskRenewalRequest, Status: store.TaskOpen})
	if len(ts) != 1 || ts[0].SubjectIdentityID != ss.GuestIdentityID || ts[0].Trigger != store.TaskTriggerGuest {
		t.Fatalf("tasks = %+v", ts)
	}
	request(token, day(2)) // the second use does nothing
	if n := len(e.tasks(store.LifecycleTaskFilter{Kind: store.TaskRenewalRequest})); n != 1 {
		t.Errorf("the link worked twice: %d tasks", n)
	}
	// an expired token does nothing either
	late := claim.NewToken()
	e.must(func(tx *store.TenantTx) error {
		return tx.InsertRenewalToken(&store.RenewalToken{ID: uuid.NewString(), SponsorshipID: ss.ID, GuestIdentityID: ss.GuestIdentityID,
			TokenHash: claim.HashToken(tx.Tenant(), late), ExpiresAt: day(3), CreatedAt: now})
	})
	e.must(func(tx *store.TenantTx) error { _, err := e.gl.ExpireTasks(tx, day(4)); return err })
	request(late, day(4))
	// the sponsor renews: the request task is closed
	e.must(func(tx *store.TenantTx) error {
		_, err := e.sp.Renew(tx, e.carol, ss.ID, day(40), "still needed", day(5))
		return err
	})
	if t1 := e.tasks(store.LifecycleTaskFilter{Kind: store.TaskRenewalRequest})[0]; t1.Status != store.TaskDone || *t1.Outcome != store.OutcomeRenewed {
		t.Errorf("after the renewal = %+v", t1)
	}
	if a := e.audits(); a["guestlife.renewal_requested"] != 1 {
		t.Errorf("audit = %v", a)
	}
	// dismissing a request: only the sponsor or an admin
	token2 := claim.NewToken()
	e.must(func(tx *store.TenantTx) error {
		return tx.InsertRenewalToken(&store.RenewalToken{ID: uuid.NewString(), SponsorshipID: ss.ID, GuestIdentityID: ss.GuestIdentityID,
			TokenHash: claim.HashToken(tx.Tenant(), token2), ExpiresAt: day(40), CreatedAt: now})
	})
	request(token2, day(6))
	open := e.tasks(store.LifecycleTaskFilter{Kind: store.TaskRenewalRequest, Status: store.TaskOpen})
	if len(open) != 1 {
		t.Fatalf("open = %+v", open)
	}
	e.wantCode(e.resolve(e.bob, open[0].ID, guestlife.ActionDismiss, day(7)), "task_not_found")
	if err := e.resolve(e.carol, open[0].ID, guestlife.ActionDismiss, day(7)); err != nil {
		t.Fatal(err)
	}
}

func TestRenewal_HeldUntilIdentityAssuranceIsMet(t *testing.T) {
	e := newEnv(t)
	ss := e.invite(e.carol, "g@x.example", 20)
	g := ss.GuestIdentityID
	e.claimed(g, 1)
	// the tenant raises the population's identity assurance: the next renewal needs IAL 2
	e.must(func(tx *store.TenantTx) error {
		gp, err := tx.GuestPopulation("guest")
		if err != nil {
			return err
		}
		gp.DefaultIAL = 2
		return tx.PutGuestPopulation(gp)
	})
	var held *store.Stepup
	e.must(func(tx *store.TenantTx) (err error) {
		_, held, err = e.sp.RenewOrHold(tx, e.carol, ss.ID, day(50), "one more quarter", day(1))
		return err
	})
	if held == nil || held.RequiredIAL != 2 || held.Status != store.StepupPending || !held.RequestedEndsAt.Equal(day(50)) {
		t.Fatalf("held = %+v", held)
	}
	if s := e.get(ss.ID); !s.EndsAt.Equal(day(20)) || s.Status != store.SponsorActive {
		t.Errorf("a held renewal extended access: %+v", s)
	}
	e.must(func(tx *store.TenantTx) error {
		l, err := tx.LifecycleFor(g)
		if err != nil || !l.EndsAt.Equal(day(20)) {
			t.Errorf("lifecycle end moved: %+v, %v", l, err)
		}
		evs, err := tx.SponsorshipEvents(ss.ID)
		last := evs[len(evs)-1]
		if last.Event != "stepup_required" || last.ToStatus != store.SponsorActive {
			t.Errorf("last event = %+v", last)
		}
		c, err := guestlife.Counts(tx, day(2))
		if c[guestlife.BucketStepUp] != 1 {
			t.Errorf("counts = %v", c)
		}
		return err
	})
	// a sweep with the assurance still too low changes nothing
	e.must(func(tx *store.TenantTx) error {
		if n, err := e.sp.ApplyStepups(tx, 0, day(3)); err != nil || n != 0 {
			t.Errorf("applied %d before the assurance was met: %v", n, err)
		}
		return nil
	})
	// the guest verifies at IAL 2: the held renewal is applied
	e.must(func(tx *store.TenantTx) error {
		if err := tx.PutIdentityAssurance(&store.Assurance{IdentityID: g, IAL: 2, AAL: 1, Source: "stepup", RecordedAt: day(4)}); err != nil {
			return err
		}
		n, err := e.sp.ApplyStepups(tx, g, day(4))
		if n != 1 {
			t.Errorf("applied = %d", n)
		}
		return err
	})
	if s := e.get(ss.ID); !s.EndsAt.Equal(day(50)) || s.RequiredIAL != 2 {
		t.Errorf("after the step-up = %+v", s)
	}
	e.must(func(tx *store.TenantTx) error {
		if ups, err := tx.Stepups(store.StepupPending, ""); err != nil || len(ups) != 0 {
			t.Errorf("pending = %v, %v", ups, err)
		}
		l, err := tx.LifecycleFor(g)
		if err != nil || !l.EndsAt.Equal(day(50)) {
			t.Errorf("lifecycle = %+v, %v", l, err)
		}
		return nil
	})
	if a := e.audits(); a["sponsorship.renew_stepup_required"] != 1 || a["sponsorship.renew"] != 1 {
		t.Errorf("audit = %v", a)
	}
	// a held renewal that is overtaken is cancelled, not applied
	e.must(func(tx *store.TenantTx) error {
		if _, err := e.sp.End(tx, e.carol, ss.ID, "done early", day(5)); err != nil {
			return err
		}
		return nil
	})
}

func TestRenewal_HeldRequestIsCancelledWhenTheSponsorshipEnds(t *testing.T) {
	e := newEnv(t)
	ss := e.invite(e.carol, "g@x.example", 20)
	e.claimed(ss.GuestIdentityID, 0)
	e.must(func(tx *store.TenantTx) error {
		gp, _ := tx.GuestPopulation("guest")
		gp.DefaultIAL = 1
		return tx.PutGuestPopulation(gp)
	})
	e.must(func(tx *store.TenantTx) error {
		_, up, err := e.sp.RenewOrHold(tx, e.carol, ss.ID, day(50), "again", day(1))
		if up == nil {
			t.Error("not held")
		}
		return err
	})
	e.must(func(tx *store.TenantTx) error { _, err := e.sp.End(tx, e.carol, ss.ID, "ended", day(2)); return err })
	e.must(func(tx *store.TenantTx) error {
		if err := tx.PutIdentityAssurance(&store.Assurance{IdentityID: ss.GuestIdentityID, IAL: 2, AAL: 1, Source: "stepup", RecordedAt: day(3)}); err != nil {
			return err
		}
		n, err := e.sp.ApplyStepups(tx, 0, day(3))
		if n != 0 {
			t.Errorf("applied %d to an ended sponsorship", n)
		}
		ups, err := tx.Stepups(store.StepupCancelled, "")
		if len(ups) != 1 {
			t.Errorf("cancelled = %v", ups)
		}
		return err
	})
}

func TestConversion_ContractorToEmployeeKeepsOneIdentity(t *testing.T) {
	e := newEnv(t)
	ss := e.invite(e.carol, "g@x.example", 60)
	g := ss.GuestIdentityID
	e.claimed(g, 1)
	hire := func(start time.Time, status string) {
		e.must(func(tx *store.TenantTx) error {
			return tx.InsertAffiliation(&store.Affiliation{ID: uuid.NewString(), IdentityID: g, Type: store.AffEmployee, Source: store.AffSourceHRIS,
				StartsAt: start, Status: status, CreatedAt: now})
		})
	}
	convert := func(at time.Time) (r guestlife.ConvertResult) {
		e.must(func(tx *store.TenantTx) (err error) { r, err = e.gl.Convert(tx, at); return err })
		return r
	}
	// a hire that has not started changes nothing
	hire(day(10), store.AffPending)
	if r := convert(day(1)); r.Ended != 0 || r.Asked != 0 {
		t.Fatalf("pre-hire = %+v", r)
	}
	if r := convert(day(11)); r.Ended != 1 { // by default the contractor sponsorship ends at the hire date
		t.Fatalf("at the hire date = %+v", r)
	}
	if s := e.get(ss.ID); s.Status != store.SponsorEnded || s.EndReason == nil {
		t.Errorf("sponsorship = %+v", s)
	}
	p := e.person(g)
	if p.Status != "active" || p.ID != g {
		t.Errorf("the person after the conversion = %+v", p)
	}
	e.must(func(tx *store.TenantTx) error {
		l, err := tx.LifecycleFor(g)
		if err != nil || l.WorkerType != store.WorkerEmployee || l.EndedAt != nil || l.EndsAt != nil {
			t.Errorf("lifecycle = %+v, %v", l, err)
		}
		if _, err := tx.Deprovisioning(g); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("an employee was put through deprovisioning: %v", err)
		}
		affs, err := tx.AffiliationsFor(g)
		kinds := map[string]bool{}
		for _, a := range affs {
			kinds[a.Type] = true
		}
		if !kinds[store.AffEmployee] || !kinds[store.AffContractor] || len(affs) != 2 {
			t.Errorf("one identity keeps both histories: %+v", affs)
		}
		evs, err := tx.SponsorshipEvents(ss.ID)
		got := false
		for _, ev := range evs {
			got = got || ev.Event == "conversion"
		}
		if !got {
			t.Errorf("no conversion event in %+v", evs)
		}
		return err
	})
	if a := e.audits(); a["jml.conversion"] != 1 {
		t.Errorf("audit = %v", a)
	}
	if r := convert(day(12)); r.Ended != 0 {
		t.Errorf("converted twice: %+v", r)
	}
}

func TestConversion_DualStatusNeedsTheSponsorsConfirmation(t *testing.T) {
	e := newEnv(t)
	e.settings(func(s *store.GuestLifecycleSettings) { s.ConversionDualStatus = "sponsor_confirms" })
	keep := e.invite(e.carol, "a@x.example", 90)
	lose := e.invite(e.carol, "b@x.example", 90)
	for _, ss := range []*store.Sponsorship{keep, lose} {
		g := ss.GuestIdentityID
		e.claimed(g, 1)
		e.must(func(tx *store.TenantTx) error {
			return tx.InsertAffiliation(&store.Affiliation{ID: uuid.NewString(), IdentityID: g, Type: store.AffEmployee, Source: store.AffSourceHRIS,
				StartsAt: now, Status: store.AffActive, CreatedAt: now})
		})
	}
	e.must(func(tx *store.TenantTx) error {
		r, err := e.gl.Convert(tx, day(1))
		if r.Asked != 2 || r.Ended != 0 {
			t.Errorf("convert = %+v", r)
		}
		r, err = e.gl.Convert(tx, day(2)) // asked once
		if r.Asked != 0 {
			t.Errorf("asked again: %+v", r)
		}
		return err
	})
	ts := e.tasks(store.LifecycleTaskFilter{Kind: store.TaskDualStatus, Status: store.TaskOpen})
	if len(ts) != 2 || !ts[0].Deadline.Equal(day(15)) {
		t.Fatalf("tasks = %+v", ts)
	}
	for _, task := range ts {
		if task.SponsorshipID == keep.ID {
			e.wantCode(e.resolve(e.bob, task.ID, guestlife.ActionConfirm, day(3)), "task_not_found") // not the sponsor
			if err := e.resolve(e.carol, task.ID, guestlife.ActionConfirm, day(3)); err != nil {
				t.Fatal(err)
			}
		}
	}
	e.must(func(tx *store.TenantTx) error { _, err := e.gl.ExpireTasks(tx, day(15)); return err })
	if s := e.get(keep.ID); s.Status != store.SponsorActive {
		t.Errorf("confirmed dual status ended: %+v", s)
	}
	if s := e.get(lose.ID); s.Status != store.SponsorEnded {
		t.Errorf("unconfirmed dual status = %+v", s)
	}
	if p := e.person(lose.GuestIdentityID); p.Status != "active" {
		t.Errorf("the converted person is %s", p.Status)
	}
}

func TestEmployeeToGuest_FormerEmployeeKeepsTheirIdentity(t *testing.T) {
	e := newEnv(t)
	dave := e.f.B.IDs["dave"] // terminated, with an ended employee affiliation
	var res *sponsorship.Result
	e.must(func(tx *store.TenantTx) (err error) {
		res, err = e.sp.SponsorExisting(tx, e.carol, dave, sponsorship.Invite{Population: "contractor", Purpose: "consulting after leaving",
			EndsAt: day(60)}, now)
		return err
	})
	if res.Guest.ID != dave {
		t.Fatalf("a different person: %d", res.Guest.ID)
	}
	p := e.person(dave)
	if p.Status != "active" {
		t.Errorf("a returning person = %s", p.Status)
	}
	e.must(func(tx *store.TenantTx) error {
		affs, err := tx.AffiliationsFor(dave)
		types := map[string]string{}
		for _, a := range affs {
			types[a.Type] = a.Status
		}
		if types[store.AffEmployee] != store.AffEnded || types[store.AffContractor] == "" {
			t.Errorf("affiliations of one identity = %+v", affs)
		}
		l, err := tx.LifecycleFor(dave)
		if err != nil || l.WorkerType != store.WorkerContractor || l.EndedAt != nil {
			t.Errorf("lifecycle = %+v, %v", l, err)
		}
		return err
	})
	if a := e.audits(); a["guest.return"] != 1 {
		t.Errorf("audit = %v", a)
	}
}
