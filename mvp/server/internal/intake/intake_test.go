package intake_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/affiliations"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/identifiers"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/intake"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

var now = storetest.Now

func day(n int) time.Time { return now.AddDate(0, 0, n) }

// rig is a tenant of the two-tenant fixture, with the identity keyer.
type rig struct {
	t  *testing.T
	f  *storetest.Fixture
	k  *identifiers.Keyer
	tn storetest.Tenant
}

func newRig(t *testing.T) *rig {
	f := storetest.TwoTenants(t)
	return &rig{t: t, f: f, k: storetest.IdentityKeyer(t), tn: f.B}
}

// do runs fn in a write transaction of the rig's tenant.
func (r *rig) do(fn func(c *store.TenantTx)) {
	r.t.Helper()
	if err := r.f.DB.InTenant(context.Background(), r.tn.ID, func(c *store.TenantTx) error {
		fn(c)
		return nil
	}); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) sis(rec *connectors.SisRecord, at time.Time) *intake.Result {
	r.t.Helper()
	var res *intake.Result
	r.do(func(c *store.TenantTx) {
		var err error
		if res, err = intake.ApplySIS(c, r.k, rec, at); err != nil {
			r.t.Fatalf("ApplySIS(%s %s) = %v", rec.ApplicantID, rec.Status, err)
		}
	})
	return res
}

func (r *rig) hris(ev *connectors.HrisEventRecord, at time.Time) *intake.Result {
	r.t.Helper()
	var res *intake.Result
	r.do(func(c *store.TenantTx) {
		var err error
		if res, err = intake.ApplyHRIS(c, r.k, ev, at); err != nil {
			r.t.Fatalf("ApplyHRIS(%s) = %v", ev.ExternalID, err)
		}
	})
	return res
}

func (r *rig) counts() (people, affs, intakes, convs, audits int) {
	r.t.Helper()
	r.do(func(c *store.TenantTx) {
		p, _ := c.Identities()
		a, _ := c.Affiliations()
		i, _ := c.IntakeRecords()
		v, _ := c.Conversions()
		l, _ := c.AuditLog(-1)
		people, affs, intakes, convs, audits = len(p), len(a), len(i), len(v), len(l)
	})
	return
}

func (r *rig) affs(id int64) []*store.Affiliation {
	r.t.Helper()
	var out []*store.Affiliation
	r.do(func(c *store.TenantTx) {
		var err error
		if out, err = c.AffiliationsFor(id); err != nil {
			r.t.Fatal(err)
		}
	})
	return out
}

func (r *rig) actions() map[string]int {
	r.t.Helper()
	out := map[string]int{}
	r.do(func(c *store.TenantTx) {
		log, err := c.AuditLog(-1)
		if err != nil {
			r.t.Fatal(err)
		}
		for _, e := range log {
			out[e.Action]++
		}
	})
	return out
}

func ofType(affs []*store.Affiliation, typ string) *store.Affiliation {
	for _, a := range affs {
		if a.Type == typ {
			return a
		}
	}
	return nil
}

func sisRec(evt, id, status string, at time.Time) *connectors.SisRecord {
	return &connectors.SisRecord{EventID: evt, ApplicantID: id, Name: "Priya Natarajan", Email: id + "@mail.example",
		Program: "Computer Science BS", Term: "Fall", Status: status, EffectiveAt: at}
}

func joiner(evt, worker string, at time.Time) *connectors.HrisEventRecord {
	return &connectors.HrisEventRecord{ExternalID: evt, Type: "joiner", EffectiveAt: at, Payload: ojson.Object{
		{Key: "worker_id", Value: worker}, {Key: "name", Value: "Rowan Pelletier"}, {Key: "personal_email", Value: worker + "@mail.example"},
		{Key: "department", Value: "Finance"}, {Key: "title", Value: "Analyst"}}}
}

func rescind(evt, worker string, at time.Time) *connectors.HrisEventRecord {
	return &connectors.HrisEventRecord{ExternalID: evt, Type: "leaver", Identity: &connectors.IdentityRef{ExternalID: worker},
		EffectiveAt: at, Payload: ojson.Object{{Key: "reason", Value: "Offer rescinded"}}}
}

// An applicant is admitted and matriculates: one identity throughout, the
// affiliations convert, each step is a conversion and an audit event, and a
// replay changes nothing.
func TestSIS_ApplicantToAdmitToStudentKeepsIdentity(t *testing.T) {
	r := newRig(t)
	peopleBefore, _, _, convsBefore, _ := r.counts() // the fixture holds one conversion already
	term := day(120)

	a := r.sis(sisRec("e1", "A-1001", connectors.SisApplied, day(-90)), now)
	if a.Outcome != intake.OutcomeCreated || a.IdentityID == 0 {
		t.Fatalf("applied = %+v", a)
	}
	id := a.IdentityID
	adm := sisRec("e2", "A-1001", connectors.SisAdmitted, day(-45))
	adm.TermStart = &term
	b := r.sis(adm, now)
	mat := sisRec("e3", "A-1001", connectors.SisMatriculated, day(-1))
	mat.StudentID = "S-5001"
	c := r.sis(mat, now)
	if b.Outcome != intake.OutcomeConverted || c.Outcome != intake.OutcomeConverted || b.IdentityID != id || c.IdentityID != id {
		t.Fatalf("admitted = %+v, matriculated = %+v, want conversions on identity %d", b, c, id)
	}
	if people, _, _, convs, _ := r.counts(); people != peopleBefore+1 || convs != convsBefore+2 {
		t.Errorf("%d new people, %d new conversions; want 1 and 2", people-peopleBefore, convs-convsBefore)
	}

	affs := r.affs(id)
	app, admit, stu := ofType(affs, store.AffApplicant), ofType(affs, store.AffAdmit), ofType(affs, store.AffStudent)
	if app == nil || admit == nil || stu == nil || len(affs) != 3 {
		t.Fatalf("affiliations = %+v", affs)
	}
	if app.Status != store.AffEnded || !app.EndsAt.Equal(day(-45)) || admit.Status != store.AffEnded || !admit.EndsAt.Equal(day(-1)) {
		t.Errorf("applicant %+v admit %+v should have ended at the next step", app, admit)
	}
	if stu.Status != store.AffActive || stu.EndsAt != nil || stu.Source != store.AffSourceSIS || !stu.StartsAt.Equal(day(-1)) {
		t.Errorf("student = %+v", stu)
	}
	if admit.EndsAt == nil || app.Population == nil || *app.Population != "applicant" {
		t.Errorf("applicant population = %+v", app)
	}
	r.do(func(c *store.TenantTx) {
		// the one identity is the person the HR-style lookups find, and it holds the SIS source and identifiers
		who, err := c.Identity(id)
		if err != nil || who.ExternalID != "sis-A-1001" || who.Email != nil || who.Type != "human" {
			t.Errorf("identity = %+v, %v", who, err)
		}
		srcs, _ := c.SourceRecordsFor(id)
		if len(srcs) != 1 || srcs[0].SOR != intake.SorSIS || srcs[0].SORID != "A-1001" {
			t.Errorf("source records = %+v", srcs)
		}
		if strings.Contains(srcs[0].Attributes, "@") {
			t.Errorf("source attributes hold an email: %s", srcs[0].Attributes)
		}
		xs, _ := c.IdentifiersFor(id)
		have := map[string]bool{}
		for _, x := range xs {
			have[x.Type] = true
			if x.VerifiedBy == nil || *x.VerifiedBy != store.VerifiedBySource {
				t.Errorf("identifier %s not verified by the source", x.Type)
			}
		}
		if !have[store.IdentApplicantID] || !have[store.IdentStudentID] || !have[store.IdentEmail] {
			t.Errorf("identifier types = %v", have)
		}
		cs, _ := c.ConversionsFor(id)
		if len(cs) != 2 || cs[0].FromType != store.AffApplicant || cs[0].ToType != store.AffAdmit ||
			cs[1].FromType != store.AffAdmit || cs[1].ToType != store.AffStudent || cs[1].Trigger != store.ConvSISStatus {
			t.Errorf("conversions = %+v", cs)
		}
		recs, _ := c.IntakeRecords()
		for _, ir := range recs {
			if ir.Channel == store.ChannelSIS && ir.EventKey != "sis:evt-1" && (ir.SponsorOrg == nil || *ir.SponsorOrg != intake.SponsorAdmissions ||
				ir.MatchMode != store.MatchAuthoritative || ir.Status != store.IntakeResolved || ir.IdentityID == nil || *ir.IdentityID != id) {
				t.Errorf("intake record = %+v", ir)
			}
		}
		if got := affiliations.Derive(who.Status, affs, now, affiliations.DefaultNotice); got != affiliations.StateActive {
			t.Errorf("state = %s", got)
		}
	})
	acts := r.actions()
	if acts["identity.conversion"] != 2 || acts["intake.sis.created"] != 1 || acts["intake.sis.converted"] != 2 {
		t.Errorf("audit actions = %v", acts)
	}

	// a replay, and an older status arriving late, change nothing
	_, affsN, intakesN, convsN, auditN := r.counts()
	for _, rec := range []*connectors.SisRecord{sisRec("e1", "A-1001", connectors.SisApplied, day(-90)), adm, mat} {
		if got := r.sis(rec, now); got.Outcome != intake.OutcomeDuplicate || got.IdentityID != id {
			t.Errorf("replay of %s = %+v", rec.EventID, got)
		}
	}
	if late := r.sis(sisRec("e0", "A-1001", connectors.SisApplied, day(-100)), now); late.Outcome != intake.OutcomeUnchanged {
		t.Errorf("late applied = %+v, want unchanged", late)
	}
	if _, a2, i2, c2, l2 := r.counts(); a2 != affsN || c2 != convsN || i2 != intakesN+1 || l2 != auditN+1 {
		t.Errorf("after replays: %d affiliations, %d intakes, %d conversions, %d audit events", a2, i2, c2, l2)
	}
}

// Withdrawn and denied end an open application; they create nobody and leave a student alone.
func TestSIS_WithdrawnAndDenied(t *testing.T) {
	r := newRig(t)
	a := r.sis(sisRec("w1", "A-2001", connectors.SisApplied, day(-20)), now)
	w := r.sis(sisRec("w2", "A-2001", connectors.SisWithdrawn, day(-2)), now)
	if w.Outcome != intake.OutcomeEnded || w.IdentityID != a.IdentityID {
		t.Fatalf("withdrawn = %+v", w)
	}
	app := ofType(r.affs(a.IdentityID), store.AffApplicant)
	if app.Status != store.AffRevoked || app.EndReason == nil || !strings.Contains(*app.EndReason, "withdrawn") {
		t.Errorf("applicant = %+v", app)
	}
	// the person returns: the same identity gets a new admit affiliation
	back := r.sis(sisRec("w3", "A-2001", connectors.SisAdmitted, day(-1)), now)
	if back.IdentityID != a.IdentityID || back.Outcome != intake.OutcomeStarted {
		t.Errorf("re-admit = %+v", back)
	}
	// denial of someone never seen creates no person
	people, _, _, _, _ := r.counts()
	if d := r.sis(sisRec("w4", "A-2999", connectors.SisDenied, day(-1)), now); d.Outcome != intake.OutcomeUnchanged || d.IdentityID != 0 {
		t.Errorf("denied unknown = %+v", d)
	}
	if p2, _, _, _, _ := r.counts(); p2 != people {
		t.Error("a denial created a person")
	}
	// a matriculated student who is later reported withdrawn keeps the student affiliation
	r.sis(sisRec("w5", "A-2001", connectors.SisMatriculated, day(-1)), now)
	if st := r.sis(sisRec("w6", "A-2001", connectors.SisWithdrawn, day(0)), now); st.Outcome != intake.OutcomeUnchanged {
		t.Errorf("withdrawn after matriculation = %+v", st)
	}
	if s := ofType(r.affs(a.IdentityID), store.AffStudent); s == nil || s.Status != store.AffActive {
		t.Errorf("student = %+v", s)
	}
}

// Authoritative identifiers attach a record to a person; an email alone never does.
func TestSIS_MatchingIsAuthoritativeOnly(t *testing.T) {
	r := newRig(t)
	first := sisRec("m1", "A-3001", connectors.SisAdmitted, day(-5))
	first.StudentID = "S-3001"
	a := r.sis(first, now)

	// a new applicant id that the SIS says belongs to student S-3001: same person
	same := sisRec("m2", "A-3001b", connectors.SisMatriculated, day(-1))
	same.StudentID = "S-3001"
	same.Email = "other.address@mail.example"
	if got := r.sis(same, now); got.IdentityID != a.IdentityID || got.Outcome != intake.OutcomeConverted {
		t.Errorf("student id match = %+v, want identity %d", got, a.IdentityID)
	}

	// an applicant whose personal email another person holds is held for review: nothing is created
	var aliceEmail string
	r.do(func(c *store.TenantTx) {
		who, err := c.Identity(r.tn.IDs["alice"])
		if err != nil || who.Email == nil {
			t.Fatalf("alice = %+v, %v", who, err)
		}
		aliceEmail = *who.Email
	})
	people, affs, _, _, _ := r.counts()
	clash := sisRec("m3", "A-3002", connectors.SisApplied, day(-1))
	clash.Email = aliceEmail
	got := r.sis(clash, now)
	if got.Outcome != intake.OutcomeReview || got.IdentityID != 0 || got.Reason == "" {
		t.Fatalf("clashing email = %+v", got)
	}
	if p2, a2, _, _, _ := r.counts(); p2 != people || a2 != affs {
		t.Error("a held record created a person or an affiliation")
	}
	r.do(func(c *store.TenantTx) {
		rec, err := c.IntakeRecord(got.IntakeID)
		if err != nil || rec.Status != store.IntakeReview || rec.IdentityID != nil {
			t.Errorf("held intake = %+v, %v", rec, err)
		}
		if strings.Contains(rec.Detail, aliceEmail) {
			t.Error("intake detail names the email")
		}
	})

	// malformed records are rejected, not applied
	for name, rec := range map[string]*connectors.SisRecord{
		"bad email":      {EventID: "m4", ApplicantID: "A-3003", Name: "X Y", Email: "not-an-email", Status: connectors.SisApplied, EffectiveAt: day(-1)},
		"unknown status": {EventID: "m5", ApplicantID: "A-3004", Name: "X Y", Email: "x@mail.example", Status: "enrolled", EffectiveAt: day(-1)},
		"no name":        {EventID: "m6", ApplicantID: "A-3005", Email: "y@mail.example", Status: connectors.SisApplied, EffectiveAt: day(-1)},
		"no event id":    {ApplicantID: "A-3006", Name: "X Y", Email: "z@mail.example", Status: connectors.SisApplied, EffectiveAt: day(-1)},
	} {
		if res := r.sis(rec, now); res.Outcome != intake.OutcomeRejected || res.IdentityID != 0 {
			t.Errorf("%s = %+v", name, res)
		}
	}
	if p2, _, _, _, _ := r.counts(); p2 != people {
		t.Error("a rejected record created a person")
	}
}

// A pre-hire is announced with a future hire date and becomes an employee on
// that date, on the same identity, which a later HR sync then keeps.
func TestHRIS_PrehireToEmployeeKeepsIdentity(t *testing.T) {
	r := newRig(t)
	people, _, _, _, _ := r.counts()
	hire := day(14)

	a := r.hris(joiner("wd-1", "W-7001", hire), now)
	if a.Outcome != intake.OutcomeCreated || a.IdentityID == 0 {
		t.Fatalf("announce = %+v", a)
	}
	id := a.IdentityID
	if p2, _, _, _, _ := r.counts(); p2 != people+1 {
		t.Errorf("%d new people, want 1", p2-people)
	}
	pre := ofType(r.affs(id), store.AffPrehire)
	if pre == nil || pre.Status != store.AffActive || pre.Source != store.AffSourceHRIS || pre.Population == nil || *pre.Population != "prehire" ||
		pre.EndsAt == nil || !pre.EndsAt.Equal(hire.Add(30*24*time.Hour)) || pre.OrgUnit == nil || *pre.OrgUnit != "Finance" {
		t.Fatalf("prehire = %+v", pre)
	}
	r.do(func(c *store.TenantTx) {
		rec, err := c.IntakeRecord(a.IntakeID)
		if err != nil || rec.SponsorOrg == nil || *rec.SponsorOrg != intake.SponsorHR || rec.Channel != store.ChannelHRIS {
			t.Errorf("announce intake = %+v, %v", rec, err)
		}
		src, err := c.SourceRecordBySOR(intake.SorHRIS, "W-7001")
		if err != nil || src.IdentityID == nil || *src.IdentityID != id {
			t.Errorf("hris source record = %+v, %v", src, err)
		}
		who, _ := c.Identity(id)
		if who.Email != nil || who.HiredAt == nil || !who.HiredAt.Equal(hire) {
			t.Errorf("identity = %+v", who)
		}
	})
	// announcing again (same event, or a second event for the same worker) adds nothing
	if dup := r.hris(joiner("wd-1", "W-7001", hire), now); dup.Outcome != intake.OutcomeDuplicate {
		t.Errorf("replayed announce = %+v", dup)
	}
	if again := r.hris(joiner("wd-1b", "W-7001", hire), now); again.Outcome != intake.OutcomeUnchanged || again.IdentityID != id {
		t.Errorf("second announce = %+v", again)
	}
	// before the date nothing converts: the event is still an announcement
	if _, a1, _, _, _ := r.counts(); len(r.affs(id)) != 1 || a1 == 0 {
		t.Errorf("affiliations before the start date = %+v", r.affs(id))
	}

	// the start date arrives
	later := hire.Add(time.Hour)
	h := r.hris(joiner("wd-1", "W-7001", hire), later)
	if h.Outcome != intake.OutcomeConverted || h.IdentityID != id || h.Conversion == nil {
		t.Fatalf("hire = %+v", h)
	}
	affs := r.affs(id)
	pre, emp := ofType(affs, store.AffPrehire), ofType(affs, store.AffEmployee)
	if len(affs) != 2 || pre.Status != store.AffEnded || !pre.EndsAt.Equal(hire) || emp == nil || emp.Status != store.AffActive ||
		emp.EndsAt != nil || !emp.StartsAt.Equal(hire) || emp.Source != store.AffSourceHRIS {
		t.Fatalf("affiliations after hire = %+v", affs)
	}
	if h.Conversion.FromAffiliationID != pre.ID || h.Conversion.ToAffiliationID != emp.ID || h.Conversion.Trigger != store.ConvHRISHire {
		t.Errorf("conversion = %+v", h.Conversion)
	}
	if got := affiliations.Derive("active", affs, later, affiliations.DefaultNotice); got != affiliations.StateActive {
		t.Errorf("state after hire = %s", got)
	}
	if dup := r.hris(joiner("wd-1", "W-7001", hire), later.Add(time.Hour)); dup.Outcome != intake.OutcomeDuplicate {
		t.Errorf("replayed hire = %+v", dup)
	}
	acts := r.actions()
	if acts["identity.conversion"] != 1 || acts["intake.hris.created"] != 1 || acts["intake.hris.converted"] != 1 {
		t.Errorf("audit actions = %v", acts)
	}

	// the HR system's own discovery of the new employee lands on the same identity
	r.do(func(c *store.TenantTx) {
		hired := hire
		d := &connectors.DiscoveryResult{Identities: []connectors.IdentityRecord{{ExternalID: "W-7001", Name: "Rowan Pelletier",
			Type: "human", Status: "active", HiredAt: &hired}}}
		if _, err := ingest.Discovery(c, later, []*connectors.DiscoveryResult{d}, true); err != nil {
			t.Fatal(err)
		}
		who, err := c.IdentityByExternalID("W-7001")
		if err != nil || who.ID != id {
			t.Errorf("after discovery the worker is identity %v (%v), want %d", who, err, id)
		}
	})
	if p2, _, _, _, _ := r.counts(); p2 != people+1 {
		t.Errorf("%d new people after the HR sync, want 1", p2-people)
	}
}

// A rescinded offer ends the pre-hire; the person remains, the hire date
// passing later does not make an employee, and a new offer reuses the identity.
func TestHRIS_RescindedOfferEndsPrehire(t *testing.T) {
	r := newRig(t)
	hire := day(10)
	a := r.hris(joiner("wd-2", "W-7002", hire), now)
	id := a.IdentityID

	res := r.hris(rescind("wd-2-r", "W-7002", now.Add(time.Hour)), now.Add(time.Hour))
	if res.Outcome != intake.OutcomeEnded || res.IdentityID != id {
		t.Fatalf("rescind = %+v", res)
	}
	pre := ofType(r.affs(id), store.AffPrehire)
	if pre.Status != store.AffRevoked || pre.EndReason == nil || *pre.EndReason != "offer rescinded" || !pre.EndsAt.Equal(now.Add(time.Hour)) {
		t.Errorf("prehire = %+v", pre)
	}
	if got := affiliations.Derive("active", r.affs(id), now.Add(2*time.Hour), affiliations.DefaultNotice); got != affiliations.StateRevoked {
		t.Errorf("state = %s, want revoked", got)
	}
	if dup := r.hris(rescind("wd-2-r", "W-7002", now.Add(time.Hour)), now.Add(2*time.Hour)); dup.Outcome != intake.OutcomeDuplicate {
		t.Errorf("replayed rescind = %+v", dup)
	}

	// the hire date passes: no employee is made from a rescinded offer
	_, _, _, convs, _ := r.counts()
	if h := r.hris(joiner("wd-2", "W-7002", hire), hire.Add(time.Hour)); h.Outcome != intake.OutcomeIgnored {
		t.Errorf("hire of a rescinded offer = %+v, want ignored", h)
	}
	if ofType(r.affs(id), store.AffEmployee) != nil {
		t.Error("a rescinded offer became an employee")
	}
	if _, _, _, c2, _ := r.counts(); c2 != convs {
		t.Error("a rescinded offer produced a conversion")
	}

	// a joiner event marked rescinded does the same
	b := r.hris(joiner("wd-3", "W-7003", hire), now)
	mark := joiner("wd-3-x", "W-7003", hire)
	mark.Payload = append(mark.Payload, ojson.KV{Key: "rescinded", Value: true})
	if got := r.hris(mark, now); got.Outcome != intake.OutcomeEnded || got.IdentityID != b.IdentityID {
		t.Errorf("rescinded joiner = %+v", got)
	}

	// a new offer to the same worker attaches to the same identity
	again := r.hris(joiner("wd-2-new", "W-7002", day(40)), day(1))
	if again.Outcome != intake.OutcomeStarted || again.IdentityID != id {
		t.Errorf("re-offer = %+v", again)
	}
	if n := len(r.affs(id)); n != 2 {
		t.Errorf("%d affiliations after the re-offer, want 2", n)
	}
}

// Events that are not intake are left to the JML process: a leaver of an
// existing employee, a hire nobody announced, an announcement for someone already employed.
func TestHRIS_NotIntakeIsIgnored(t *testing.T) {
	r := newRig(t)
	var alice string
	r.do(func(c *store.TenantTx) {
		who, _ := c.Identity(r.tn.IDs["alice"])
		alice = who.ExternalID
	})
	people, affs, intakes, _, audits := r.counts()
	for name, ev := range map[string]*connectors.HrisEventRecord{
		"leaver of an employee": rescind("x1", alice, now),
		"unannounced hire":      joiner("x2", "W-9001", day(-1)),
		"mover":                 {ExternalID: "x3", Type: "mover", Identity: &connectors.IdentityRef{ExternalID: alice}, EffectiveAt: now},
		"no worker id":          {ExternalID: "x4", Type: "joiner", EffectiveAt: day(3), Payload: ojson.Object{{Key: "name", Value: "Noor"}}},
	} {
		if res := r.hris(ev, now); res.Outcome != intake.OutcomeIgnored {
			t.Errorf("%s = %+v, want ignored", name, res)
		}
	}
	// an announcement for a worker who is already an employee changes nothing
	ann := joiner("x5", alice, day(5))
	got := r.hris(ann, now)
	if got.Outcome != intake.OutcomeUnchanged || got.IdentityID != r.tn.IDs["alice"] {
		t.Errorf("announce for an employee = %+v", got)
	}
	p2, a2, i2, _, au2 := r.counts()
	if p2 != people || a2 != affs || i2 != intakes+1 || au2 != audits+1 {
		t.Errorf("people %d->%d affiliations %d->%d intakes %d->%d audit %d->%d", people, p2, affs, a2, intakes, i2, audits, au2)
	}
}

// The demo SIS and HRIS connectors run through the generic entry point; a
// second run is a no-op.
func TestRun_DemoFeeds(t *testing.T) {
	r := newRig(t)
	conns := []connectors.Connector{connectors.NewDemoSIS(now), connectors.NewDemoPrehireHRIS(now)}
	var st intake.Stats
	r.do(func(c *store.TenantTx) {
		var err error
		if st, err = intake.Run(c, r.k, now, conns, nil); err != nil {
			t.Fatal(err)
		}
	})
	if st.Applied[intake.OutcomeCreated] != 6 || st.Applied[intake.OutcomeConverted] != 1 || st.Applied[intake.OutcomeEnded] != 2 || st.Records != 9 {
		t.Errorf("first run = %+v", st)
	}
	_, affs, intakes, convs, audits := r.counts()
	r.do(func(c *store.TenantTx) {
		var err error
		if st, err = intake.Run(c, r.k, now, conns, nil); err != nil {
			t.Fatal(err)
		}
	})
	if st.Applied[intake.OutcomeDuplicate] != 9 || st.Records != 9 {
		t.Errorf("second run = %+v", st)
	}
	if _, a2, i2, c2, l2 := r.counts(); a2 != affs || i2 != intakes || c2 != convs || l2 != audits {
		t.Error("a second run changed the tenant")
	}
}

// The demo workday HR feed, which has no worker ids on its joiner, produces no intake.
func TestRun_WorkdayDemoFeedIsNotIntake(t *testing.T) {
	r := newRig(t)
	people, affs, intakes, _, _ := r.counts()
	r.do(func(c *store.TenantTx) {
		wd := connectors.DemoConnectors(connectors.GetCompany(connectors.DemoSeed, now))[0]
		if wd.System() != "workday" {
			t.Fatalf("first demo connector is %s", wd.System())
		}
		if _, err := intake.Run(c, r.k, now, []connectors.Connector{wd}, nil); err != nil {
			t.Fatal(err)
		}
	})
	if p2, a2, i2, _, _ := r.counts(); p2 != people || a2 != affs || i2 != intakes {
		t.Errorf("the workday demo feed changed people %d->%d affiliations %d->%d intakes %d->%d", people, p2, affs, a2, intakes, i2)
	}
}

// Everything an intake does is one transaction with its audit event: a failure
// afterwards leaves neither.
func TestIntake_RollsBackWithItsAuditEvent(t *testing.T) {
	r := newRig(t)
	people, affs, intakes, convs, audits := r.counts()
	boom := errors.New("boom")
	err := r.f.DB.InTenant(context.Background(), r.tn.ID, func(c *store.TenantTx) error {
		adm := sisRec("t2", "A-8001", connectors.SisAdmitted, day(-1))
		if _, err := intake.ApplySIS(c, r.k, sisRec("t1", "A-8001", connectors.SisApplied, day(-2)), now); err != nil {
			return err
		}
		if _, err := intake.ApplySIS(c, r.k, adm, now); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if p, a, i, c, l := r.counts(); p != people || a != affs || i != intakes || c != convs || l != audits {
		t.Error("a rolled-back intake left rows or audit events behind")
	}
}

// The same feed in two tenants builds two separate people; neither sees the other's intake.
func TestIntake_TenantScoped(t *testing.T) {
	r := newRig(t)
	rec := sisRec("s1", "A-9001", connectors.SisApplied, day(-3))
	inB := r.sis(rec, now)
	var inA *intake.Result
	if err := r.f.DB.InTenant(context.Background(), r.f.A.ID, func(c *store.TenantTx) error {
		var err error
		inA, err = intake.ApplySIS(c, r.k, rec, now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if inA.Outcome != intake.OutcomeCreated || inB.Outcome != intake.OutcomeCreated {
		t.Errorf("A = %+v, B = %+v: the same event must apply once per tenant", inA, inB)
	}
	for _, tn := range []storetest.Tenant{r.f.A, r.f.B} {
		if err := r.f.DB.ReadTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			recs, err := c.IntakeRecords()
			if err != nil {
				return err
			}
			n := 0
			for _, ir := range recs {
				if ir.EventKey == "sis:s1" {
					n++
				}
			}
			if n != 1 {
				t.Errorf("tenant %s has %d intake records for the event", tn.Slug, n)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}
