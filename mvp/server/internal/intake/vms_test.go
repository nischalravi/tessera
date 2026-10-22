package intake_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/intake"
	"github.com/nischalravi/tessera/mvp/server/internal/lifecycle"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// employee adds an active employee (no lifecycle row) who can sponsor.
func (r *rig) employee(xid, email string) int64 {
	r.t.Helper()
	var id int64
	r.do(func(c *store.TenantTx) {
		var err error
		if id, err = c.InsertIdentity(&store.Identity{ExternalID: xid, Name: "Sponsor " + xid, Email: &email, Type: "human",
			Status: "active", CreatedAt: now}); err != nil {
			r.t.Fatal(err)
		}
	})
	return id
}

func (r *rig) vms(rec *connectors.VmsRecord, at time.Time) *intake.Result {
	r.t.Helper()
	var res *intake.Result
	r.do(func(c *store.TenantTx) {
		var err error
		if res, err = intake.ApplyVMS(c, r.k, rec, at); err != nil {
			r.t.Fatalf("ApplyVMS(%s %s) = %v", rec.WorkerID, rec.Status, err)
		}
	})
	return res
}

func (r *rig) lifecycleOf(id int64) *store.Lifecycle {
	r.t.Helper()
	var l *store.Lifecycle
	r.do(func(c *store.TenantTx) {
		var err error
		if l, err = c.LifecycleFor(id); err != nil {
			r.t.Fatalf("LifecycleFor(%d) = %v", id, err)
		}
	})
	return l
}

func vmsRec(evt, worker, sponsorEmail string, ends time.Time) *connectors.VmsRecord {
	e := ends
	return &connectors.VmsRecord{System: store.VmsFieldglass, EventID: evt, WorkerID: worker, Name: "Casey Contractor",
		Email: worker + "@agency.example", Supplier: "Acme Staffing", Role: "Analyst", SponsorEmail: sponsorEmail,
		Status: connectors.VmsActive, EndsAt: &e, UpdatedAt: day(-1)}
}

func TestVMS_NewContractorGetsSponsorAndEndDate(t *testing.T) {
	r := newRig(t)
	sp := r.employee("emp-100", "dana.s@corp.example")
	res := r.vms(vmsRec("e1", "W-1", "Dana.S@corp.example", day(60)), now)
	if res.Outcome != intake.OutcomeCreated || res.IdentityID == 0 {
		t.Fatalf("res = %+v", res)
	}
	l := r.lifecycleOf(res.IdentityID)
	if l.WorkerType != store.WorkerContractor || l.SponsorID == nil || *l.SponsorID != sp || l.EndsAt == nil || !l.EndsAt.Equal(day(60)) {
		t.Errorf("lifecycle = %+v", l)
	}
	if l.Organization == nil || *l.Organization != "Acme Staffing" {
		t.Errorf("organization = %v", l.Organization)
	}
	// a replay of the same event changes nothing
	_, _, intakes, _, audits := r.counts()
	if dup := r.vms(vmsRec("e1", "W-1", "Dana.S@corp.example", day(60)), now); dup.Outcome != intake.OutcomeDuplicate {
		t.Errorf("replay = %+v", dup)
	}
	if _, _, i2, _, a2 := r.counts(); i2 != intakes || a2 != audits {
		t.Errorf("replay wrote rows: intakes %d -> %d, audits %d -> %d", intakes, i2, audits, a2)
	}
	// the same facts under a new event id: nothing to change
	if same := r.vms(vmsRec("e2", "W-1", "dana.s@corp.example", day(60)), now); same.Outcome != intake.OutcomeUnchanged {
		t.Errorf("same facts = %+v", same)
	}
	acts := r.actions()
	if acts["lifecycle.set"] != 1 || acts["intake.vms.created"] != 1 || acts["intake.vms.unchanged"] != 1 {
		t.Errorf("audit actions = %v", acts)
	}
	r.do(func(c *store.TenantTx) {
		evs, err := c.IntakeEventsByChannel(store.ChannelVMS, 10)
		if err != nil || len(evs) != 2 {
			t.Fatalf("vms intake events = %d, %v", len(evs), err)
		}
		if evs[0].SponsorOrg != nil || evs[0].MatchMode != store.MatchAuthoritative {
			t.Errorf("event = %+v", evs[0])
		}
	})
}

// Every contractor needs a sponsor: without an eligible one nothing is created.
func TestVMS_NoSponsorNoContractor(t *testing.T) {
	r := newRig(t)
	r.employee("emp-100", "dana.s@corp.example")
	r.employee("emp-101", "shared@corp.example")
	r.employee("emp-102", "shared@corp.example")
	r.vms(vmsRec("c0", "W-0", "dana.s@corp.example", day(30)), now)
	cases := []struct {
		name    string
		sponsor string
		empID   string
		reason  string
	}{
		{"none named", "", "", "sponsor_required"},
		{"unknown address", "nobody@corp.example", "", "sponsor_not_found"},
		{"unknown employee id", "", "emp-999", "sponsor_not_found"},
		{"two people share the address", "shared@corp.example", "", "sponsor_ambiguous"},
		{"a contractor cannot sponsor", "", "vms-fieldglass-W-0", "sponsor_not_eligible"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			people, _, _, _, _ := r.counts()
			rec := vmsRec("n"+string(rune('a'+i)), "W-n"+string(rune('a'+i)), tc.sponsor, day(30))
			rec.SponsorEmployeeID = tc.empID
			res := r.vms(rec, now)
			if res.Outcome != intake.OutcomeReview || res.Reason != tc.reason || res.IdentityID != 0 {
				t.Fatalf("res = %+v, want review %s", res, tc.reason)
			}
			if after, _, _, _, _ := r.counts(); after != people {
				t.Errorf("%d people created without a sponsor", after-people)
			}
		})
	}
}

func TestVMS_RejectedAndHeldRecords(t *testing.T) {
	r := newRig(t)
	r.employee("emp-100", "dana.s@corp.example")
	noEnd := vmsRec("a", "W-a", "dana.s@corp.example", day(30))
	noEnd.EndsAt = nil
	badStatus := vmsRec("b", "W-b", "dana.s@corp.example", day(30))
	badStatus.Status = "maybe"
	badMail := vmsRec("c", "W-c", "dana.s@corp.example", day(30))
	badMail.Email = "not-an-email"
	noID := vmsRec("", "W-d", "dana.s@corp.example", day(30))
	badSystem := vmsRec("e", "W-e", "dana.s@corp.example", day(30))
	badSystem.System = "sap"
	takenMail := vmsRec("f", "W-f", "dana.s@corp.example", day(30))
	takenMail.Email = "A-1001@mail.example"
	r.sis(sisRec("s1", "A-1001", connectors.SisApplied, day(-9)), now) // A-1001@mail.example is now this person's authoritative address
	cases := []struct {
		name    string
		rec     *connectors.VmsRecord
		outcome string
		reason  string
	}{
		{"no end date", noEnd, intake.OutcomeRejected, "end_required"},
		{"unknown status", badStatus, intake.OutcomeRejected, "invalid_record"},
		{"bad address", badMail, intake.OutcomeRejected, "invalid_record"},
		{"no event id", noID, intake.OutcomeRejected, "invalid_record"},
		{"unknown feed", badSystem, intake.OutcomeRejected, "invalid_record"},
		{"address of another person", takenMail, intake.OutcomeReview, "email_matches_another_person"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			people, _, _, _, _ := r.counts()
			res := r.vms(tc.rec, now)
			if res.Outcome != tc.outcome || res.Reason != tc.reason || res.IdentityID != 0 {
				t.Fatalf("res = %+v, want %s %s", res, tc.outcome, tc.reason)
			}
			if after, _, _, _, _ := r.counts(); after != people {
				t.Errorf("a rejected record created %d people", after-people)
			}
		})
	}
}

func TestVMS_EndDateAndSponsorChangesFollowTheFeed(t *testing.T) {
	r := newRig(t)
	a := r.employee("emp-100", "dana.s@corp.example")
	b := r.employee("emp-101", "lee.m@corp.example")
	id := r.vms(vmsRec("e1", "W-1", "dana.s@corp.example", day(30)), now).IdentityID

	later := vmsRec("e2", "W-1", "dana.s@corp.example", day(90))
	later.UpdatedAt = day(0)
	if res := r.vms(later, now); res.Outcome != intake.OutcomeStarted || res.IdentityID != id {
		t.Fatalf("extended = %+v", res)
	}
	if l := r.lifecycleOf(id); !l.EndsAt.Equal(day(90)) || *l.SponsorID != a {
		t.Errorf("after extension: %+v", l)
	}
	moved := vmsRec("e3", "W-1", "lee.m@corp.example", day(90))
	moved.UpdatedAt = day(0).Add(time.Hour)
	r.vms(moved, now)
	if l := r.lifecycleOf(id); *l.SponsorID != b {
		t.Errorf("sponsor = %d, want %d", *l.SponsorID, b)
	}
	// an older version arriving late changes nothing, whatever its event id
	stale := vmsRec("e0", "W-1", "dana.s@corp.example", day(5))
	stale.UpdatedAt = day(-10)
	if res := r.vms(stale, now); res.Outcome != intake.OutcomeUnchanged || res.Reason != "stale_record" {
		t.Errorf("stale = %+v", res)
	}
	if l := r.lifecycleOf(id); !l.EndsAt.Equal(day(90)) || *l.SponsorID != b {
		t.Errorf("stale record changed the lifecycle: %+v", l)
	}
	// a record that loses its sponsor holds, and the contractor keeps the last good one
	lost := vmsRec("e4", "W-1", "", day(90))
	lost.UpdatedAt = day(0).Add(2 * time.Hour)
	if res := r.vms(lost, now); res.Outcome != intake.OutcomeReview || res.Reason != "sponsor_required" {
		t.Errorf("lost sponsor = %+v", res)
	}
	if l := r.lifecycleOf(id); *l.SponsorID != b {
		t.Errorf("sponsor cleared: %+v", l)
	}
}

func TestVMS_FarEndDateIsClamped(t *testing.T) {
	r := newRig(t)
	r.employee("emp-100", "dana.s@corp.example")
	res := r.vms(vmsRec("e1", "W-1", "dana.s@corp.example", day(900)), now)
	if res.Outcome != intake.OutcomeCreated || res.Reason != "end_clamped" {
		t.Fatalf("res = %+v", res)
	}
	if l := r.lifecycleOf(res.IdentityID); !l.EndsAt.Equal(day(lifecycle.MaxTermDays)) {
		t.Errorf("ends %v, want %v", l.EndsAt, day(lifecycle.MaxTermDays))
	}
}

func TestVMS_PendingContractorStartsLater(t *testing.T) {
	r := newRig(t)
	r.employee("emp-100", "dana.s@corp.example")
	rec := vmsRec("e1", "W-1", "dana.s@corp.example", day(120))
	start := day(14)
	rec.StartsAt, rec.Status = &start, connectors.VmsPending
	res := r.vms(rec, now)
	if res.Outcome != intake.OutcomeCreated {
		t.Fatalf("res = %+v", res)
	}
	l := r.lifecycleOf(res.IdentityID)
	if l.StartsAt == nil || !l.StartsAt.Equal(start) || lifecycle.State(l, now) != lifecycle.StateUpcoming {
		t.Errorf("lifecycle = %+v state %s", l, lifecycle.State(l, now))
	}
}

// The end date drives the leaver plan: the lifecycle sweep ends the term on the
// day, and a VMS "ended" record ends it at once.
func TestVMS_EndDateDrivesTheLeaverPlan(t *testing.T) {
	r := newRig(t)
	r.employee("emp-100", "dana.s@corp.example")
	a := r.vms(vmsRec("a1", "W-1", "dana.s@corp.example", day(3)), now).IdentityID
	b := r.vms(vmsRec("b1", "W-2", "dana.s@corp.example", day(40)), now).IdentityID

	r.do(func(c *store.TenantTx) {
		res, err := lifecycle.Sweep(c, day(4))
		if err != nil || res.Ended != 1 {
			t.Fatalf("Sweep = %+v, %v", res, err)
		}
	})
	if l := r.lifecycleOf(a); l.EndedAt == nil {
		t.Error("the contractor past the end date was not ended")
	}
	if l := r.lifecycleOf(b); l.EndedAt != nil {
		t.Error("the contractor with time left was ended")
	}
	end := vmsRec("b2", "W-2", "dana.s@corp.example", day(40))
	end.Status, end.UpdatedAt = connectors.VmsEnded, day(0)
	if res := r.vms(end, now); res.Outcome != intake.OutcomeEnded || res.IdentityID != b {
		t.Fatalf("ended = %+v", res)
	}
	if l := r.lifecycleOf(b); l.EndedAt == nil {
		t.Error("an ended record did not end the term")
	}
	// a feed that reports an unknown worker as already ended creates nobody
	people, _, _, _, _ := r.counts()
	ghost := vmsRec("g1", "W-9", "dana.s@corp.example", day(-3))
	if res := r.vms(ghost, now); res.Outcome != intake.OutcomeUnchanged {
		t.Errorf("ghost = %+v", res)
	}
	if after, _, _, _, _ := r.counts(); after != people {
		t.Error("an ended record for an unknown worker created a person")
	}
	// and a contractor that has ended is not revived by a later active record
	again := vmsRec("b3", "W-2", "dana.s@corp.example", day(40))
	again.UpdatedAt = day(0).Add(time.Hour)
	if res := r.vms(again, now); res.Outcome != intake.OutcomeReview || res.Reason != "identity_not_active" && res.Reason != "term_already_ended" {
		t.Errorf("returning contractor = %+v", res)
	}
}

// A VMS feed that ends many contractors at once (a bad export) is a source-driven run, but it arrives
// record by record: the default threshold (5 here) lets that many through and holds the rest as one
// hold for a second admin; the held contractors keep their access.
func TestVMS_MassEndedFeedIsHeldPastTheThreshold(t *testing.T) {
	r := newRig(t)
	r.employee("emp-100", "dana.s@corp.example")
	var ids []int64
	for i := 0; i < 8; i++ {
		w := fmt.Sprintf("W-%d", i)
		ids = append(ids, r.vms(vmsRec("a"+w, w, "dana.s@corp.example", day(40)), now).IdentityID)
	}
	for i := 0; i < 8; i++ {
		w := fmt.Sprintf("W-%d", i)
		end := vmsRec("e"+w, w, "dana.s@corp.example", day(40))
		end.Status, end.UpdatedAt = connectors.VmsEnded, day(0)
		r.vms(end, now)
	}
	r.do(func(c *store.TenantTx) {
		ended := 0
		for _, id := range ids {
			if i, err := c.Identity(id); err != nil {
				t.Fatal(err)
			} else if i.Status != "active" {
				ended++
			}
		}
		if ended != 5 {
			t.Errorf("%d contractors ended, want the 5 the threshold allows", ended)
		}
		hs, err := c.DeletionHolds("held", "identities", 10, 0)
		if err != nil || len(hs) != 1 || hs[0].ItemCount != 3 || hs[0].Mode != "hold_all" {
			t.Errorf("holds %+v %v", hs, err)
		}
	})
}
