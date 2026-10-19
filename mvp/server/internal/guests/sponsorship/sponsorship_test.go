package sponsorship_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/guests/sponsorship"
	"github.com/nischalravi/tessera/mvp/server/internal/lifecycle"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

var now = storetest.Now

func day(n int) time.Time { return now.AddDate(0, 0, n) }

type env struct {
	t     *testing.T
	f     *storetest.Fixture
	svc   *sponsorship.Service
	carol sponsorship.Actor // sponsors
	bob   sponsorship.Actor
	admin sponsorship.Actor // holds sponsorships.approve, is nobody's identity
}

func actor(name string, id *int64, approver bool) sponsorship.Actor {
	return sponsorship.Actor{UserID: uuid.New(), Display: name, IdentityID: id, Approver: approver}
}

func newEnv(t *testing.T) *env {
	t.Helper()
	f := storetest.TwoTenants(t)
	carol, bob := f.B.IDs["carol"], f.B.IDs["bob"]
	return &env{t: t, f: f, svc: sponsorship.New(storetest.IdentityKeyer(t)),
		carol: actor("Carol", &carol, false), bob: actor("Bob", &bob, false), admin: actor("Pat", nil, true)}
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

func invite(email, pop string, ends time.Time) sponsorship.Invite {
	return sponsorship.Invite{GivenName: "Gwen", FamilyName: "Guest", Email: email, Population: pop, Purpose: "conference talk", EndsAt: ends}
}

// catalog puts a group of the fixture in the access catalog.
func (e *env) catalog(key, risk string) int64 {
	e.t.Helper()
	gid := e.f.B.IDs[key]
	e.must(func(tx *store.TenantTx) error {
		return tx.PutCatalogItem(&store.CatalogItem{ID: uuid.NewString(), GroupID: gid, Requestable: true, Risk: risk,
			EligibleTypes: []string{"human"}, UpdatedAt: now})
	})
	return gid
}

func (e *env) invited(by sponsorship.Actor, in sponsorship.Invite) *sponsorship.Result {
	e.t.Helper()
	var res *sponsorship.Result
	e.must(func(tx *store.TenantTx) (err error) {
		res, err = e.svc.Invite(tx, by, in, store.ChannelSponsorInvite, "", now)
		return err
	})
	return res
}

func (e *env) lifecycleOf(id int64) (l *store.Lifecycle) {
	e.t.Helper()
	e.must(func(tx *store.TenantTx) (err error) {
		l, err = tx.LifecycleFor(id)
		if errors.Is(err, store.ErrNotFound) {
			l, err = nil, nil
		}
		return err
	})
	return l
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

func (e *env) affs(id int64) (a []*store.Affiliation) {
	e.t.Helper()
	e.must(func(tx *store.TenantTx) (err error) { a, err = tx.AffiliationsFor(id); return err })
	return a
}

func (e *env) auditActions() map[string]int {
	e.t.Helper()
	out := map[string]int{}
	e.must(func(tx *store.TenantTx) error {
		evs, err := tx.AuditEvents(store.AuditFilter{})
		for _, ev := range evs {
			out[ev.Action]++
		}
		return err
	})
	return out
}

// ---------------------------------------------------------------- policy

func TestSponsorPolicy_DefaultsAndVersion(t *testing.T) {
	p := sponsorship.DefaultPolicy()
	for pop, want := range map[string]int{"visitor": 50, "contractor": 25, "volunteer": 100, "partner": 25} {
		if p.MaxActive[pop] != want {
			t.Errorf("max active %s = %d, want %d", pop, p.MaxActive[pop], want)
		}
	}
	if p.MaxInvitesPerDay != 50 || p.TransferDeadlineDays != 14 || p.SensitiveBundleMinIAL != 2 {
		t.Errorf("policy = %+v", p)
	}
	if !strings.HasPrefix(p.Version, "tessera-default-sponsor-policy@") || len(p.Version) != len("tessera-default-sponsor-policy@")+12 {
		t.Errorf("version = %q", p.Version)
	}
	if sponsorship.DefaultPolicy().Version != p.Version {
		t.Error("the version is not stable")
	}
	raw := `{"id":"x","max_active_per_population":{"visitor":1,"contractor":1,"volunteer":1,"partner":1},"max_invites_per_day":1,` +
		`"ineligible_worker_types":[],"approval_required":{},"sensitive_bundle_min_ial":2,` +
		`"default_ial":{"visitor":0,"contractor":0,"volunteer":0,"partner":0},"transfer_deadline_days":1,"max_start_ahead_days":1}`
	q, err := sponsorship.LoadPolicy([]byte(raw))
	if err != nil || q.Version == p.Version || !strings.HasPrefix(q.Version, "x@") {
		t.Errorf("another policy: %v, %v", q, err)
	}
	q2, _ := sponsorship.LoadPolicy([]byte(strings.Replace(raw, `"max_invites_per_day":1`, `"max_invites_per_day":2`, 1)))
	if q2 == nil || q2.Version == q.Version {
		t.Error("a changed file keeps its version")
	}
	for name, bad := range map[string]string{"not json": `{`, "no limits": `{"id":"x"}`,
		"no ial": strings.Replace(raw, `"default_ial":{"visitor":0,"contractor":0,"volunteer":0,"partner":0}`, `"default_ial":{}`, 1)} {
		if _, err := sponsorship.LoadPolicy([]byte(bad)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestSponsorPolicy_LimitsAndDurations(t *testing.T) {
	p := sponsorship.DefaultPolicy()
	employee := &store.Identity{ID: 1, Type: "human", Status: "active"}
	base := func(mod func(*sponsorship.Request)) sponsorship.Request {
		r := sponsorship.Request{Sponsor: employee, Population: "visitor", Starts: now, Ends: day(10), Now: now, MaxDays: 30}
		if mod != nil {
			mod(&r)
		}
		return r
	}
	cases := []struct {
		name  string
		mod   func(*sponsorship.Request)
		code  string // "" allowed
		needs bool
	}{
		{"visitor ok", nil, "", false},
		{"an employee with a lifecycle row", func(r *sponsorship.Request) { r.SponsorWorkerType = "employee" }, "", false},
		{"contractor cannot sponsor", func(r *sponsorship.Request) { r.SponsorWorkerType = "contractor" }, "sponsor_not_eligible", false},
		{"intern cannot sponsor", func(r *sponsorship.Request) { r.SponsorWorkerType = "intern" }, "sponsor_not_eligible", false},
		{"partner cannot sponsor", func(r *sponsorship.Request) { r.SponsorWorkerType = "partner" }, "sponsor_not_eligible", false},
		{"vendor cannot sponsor", func(r *sponsorship.Request) { r.SponsorWorkerType = "vendor" }, "sponsor_not_eligible", false},
		{"guest cannot sponsor", func(r *sponsorship.Request) { r.SponsorWorkerType = "guest" }, "sponsor_not_eligible", false},
		{"invited cannot sponsor", func(r *sponsorship.Request) { r.Sponsor = &store.Identity{ID: 1, Type: "human", Status: "invited"} }, "sponsor_not_eligible", false},
		{"terminated cannot sponsor", func(r *sponsorship.Request) { r.Sponsor = &store.Identity{ID: 1, Type: "human", Status: "terminated"} }, "sponsor_not_eligible", false},
		{"a service cannot sponsor", func(r *sponsorship.Request) { r.Sponsor = &store.Identity{ID: 1, Type: "service", Status: "active"} }, "sponsor_not_eligible", false},
		{"sponsor whose term ended", func(r *sponsorship.Request) { r.SponsorEnded = true }, "sponsor_not_eligible", false},
		{"self", func(r *sponsorship.Request) { r.GuestIdentityID = 1 }, "cannot_sponsor_self", false},
		{"unknown population", func(r *sponsorship.Request) { r.Population = "student" }, "unknown_population", false},
		{"end before start", func(r *sponsorship.Request) { r.Ends = r.Starts }, "invalid_dates", false},
		{"end in the past", func(r *sponsorship.Request) { r.Starts, r.Ends = day(-10), day(-1) }, "invalid_dates", false},
		{"start too far ahead", func(r *sponsorship.Request) { r.Starts, r.Ends = day(400), day(410) }, "invalid_dates", false},
		{"visitor at the maximum", func(r *sponsorship.Request) { r.Ends = day(30) }, "", false},
		{"visitor over the maximum", func(r *sponsorship.Request) { r.Ends = day(31) }, "exceeds_max_duration", false},
		{"contractor a year", func(r *sponsorship.Request) { r.Population, r.MaxDays, r.Ends = "contractor", 365, day(365) }, "", false},
		{"contractor over a year", func(r *sponsorship.Request) { r.Population, r.MaxDays, r.Ends = "contractor", 365, day(366) }, "exceeds_max_duration", false},
		{"visitor 49 live", func(r *sponsorship.Request) { r.LiveCount = 49 }, "", false},
		{"visitor 50 live", func(r *sponsorship.Request) { r.LiveCount = 50 }, "sponsor_limit_reached", false},
		{"contractor 24 live", func(r *sponsorship.Request) { r.Population, r.MaxDays, r.LiveCount = "contractor", 365, 24 }, "", false},
		{"contractor 25 live", func(r *sponsorship.Request) { r.Population, r.MaxDays, r.LiveCount = "contractor", 365, 25 }, "sponsor_limit_reached", false},
		{"volunteer 99 live", func(r *sponsorship.Request) { r.Population, r.MaxDays, r.LiveCount = "volunteer", 365, 99 }, "", false},
		{"volunteer 100 live", func(r *sponsorship.Request) { r.Population, r.MaxDays, r.LiveCount = "volunteer", 365, 100 }, "sponsor_limit_reached", false},
		{"partner 25 live", func(r *sponsorship.Request) { r.Population, r.MaxDays, r.LiveCount = "partner", 365, 25 }, "sponsor_limit_reached", false},
		{"49 invitations today", func(r *sponsorship.Request) { r.Inviting, r.InvitesToday = true, 49 }, "", false},
		{"50 invitations today", func(r *sponsorship.Request) { r.Inviting, r.InvitesToday = true, 50 }, "daily_invite_limit", false},
		{"the daily limit is for invitations", func(r *sponsorship.Request) { r.InvitesToday = 80 }, "", false},
		{"sensitive bundle at IAL 1", func(r *sponsorship.Request) { r.SensitiveBundle, r.RequiredIAL = true, 1 }, "bundle_needs_ial2", false},
		{"sensitive bundle at IAL 2", func(r *sponsorship.Request) { r.SensitiveBundle, r.RequiredIAL = true, 2 }, "", false},
		{"contractor, sensitive bundle needs approval", func(r *sponsorship.Request) {
			r.Population, r.MaxDays, r.Ends, r.SensitiveBundle, r.RequiredIAL = "contractor", 365, day(100), true, 2
		}, "", true},
		{"contractor, plain bundle needs none", func(r *sponsorship.Request) { r.Population, r.MaxDays, r.Ends = "contractor", 365, day(100) }, "", false},
		{"visitor, sensitive bundle needs none", func(r *sponsorship.Request) { r.SensitiveBundle, r.RequiredIAL = true, 2 }, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := p.Evaluate(base(tc.mod))
			if d.Version != p.Version || len(d.Rules) == 0 {
				t.Errorf("decision without version or rules: %+v", d)
			}
			if d.Code != tc.code || d.Allowed != (tc.code == "") || d.NeedsApproval != tc.needs {
				t.Errorf("decision = %+v, want code %q needs approval %v", d, tc.code, tc.needs)
			}
			if !d.Allowed && d.Message == "" {
				t.Error("a refusal without a message")
			}
		})
	}
}

// ---------------------------------------------------------------- invitations

func TestSponsor_CannotSponsorSelfOrMatch(t *testing.T) {
	e := newEnv(t)
	alice, carol := e.f.B.IDs["alice"], e.f.B.IDs["carol"]
	before := map[int64]int{}
	e.must(func(tx *store.TenantTx) error {
		ids, err := tx.Identities()
		for _, i := range ids {
			x, _ := tx.IdentifiersFor(i.ID)
			before[i.ID] = len(x)
		}
		return err
	})

	// carol inviting herself, however the address is written, is refused: by her
	// record's address and by the keyed hash of her email identifier
	for _, email := range []string{"carol@t.example", " Carol@T.Example ", "CAROL@t.example"} {
		err := e.do(func(tx *store.TenantTx) error {
			_, err := e.svc.Invite(tx, e.carol, invite(email, "visitor", day(5)), store.ChannelSponsorInvite, "", now)
			return err
		})
		e.wantCode(err, "cannot_sponsor_self")
	}
	// the same through an existing person
	err := e.do(func(tx *store.TenantTx) error {
		_, err := e.svc.SponsorExisting(tx, e.carol, carol, invite("", "visitor", day(5)), now)
		return err
	})
	e.wantCode(err, "cannot_sponsor_self")
	// an employee cannot be taken on as a guest
	err = e.do(func(tx *store.TenantTx) error {
		_, err := e.svc.SponsorExisting(tx, e.carol, alice, invite("", "visitor", day(5)), now)
		return err
	})
	e.wantCode(err, "guest_not_sponsorable")

	// alice's address is accepted exactly like an address nobody has: a NEW
	// identity, never linked, and nothing tells the sponsor the address is known
	known := e.invited(e.carol, invite("alice@t.example", "visitor", day(5)))
	fresh := e.invited(e.carol, invite("nobody.knows@t.example", "visitor", day(5)))
	for _, r := range []*sponsorship.Result{known, fresh} {
		g := r.Guest
		if g.ID == alice || g.Status != "invited" || g.Type != "human" || !strings.HasPrefix(g.ExternalID, "guest:") ||
			g.Source == nil || *g.Source != "sponsorship" {
			t.Errorf("guest = %+v", g)
		}
		if r.Sponsorship.Status != store.SponsorActive || r.Decision.NeedsApproval {
			t.Errorf("sponsorship = %+v", r.Sponsorship)
		}
	}
	if known.Guest.ID == fresh.Guest.ID {
		t.Error("an invitation linked to a person")
	}
	e.must(func(tx *store.TenantTx) error {
		ids, err := tx.Identities()
		for _, i := range ids {
			if i.ID == known.Guest.ID || i.ID == fresh.Guest.ID {
				continue
			}
			if x, _ := tx.IdentifiersFor(i.ID); len(x) != before[i.ID] {
				t.Errorf("identity %d gained identifiers", i.ID)
			}
		}
		// the invited address is an unverified, sponsor-asserted identifier of the new person
		xs, err := tx.IdentifiersFor(known.Guest.ID)
		if err != nil || len(xs) != 1 || xs[0].Type != store.IdentEmail || xs[0].VerifiedAt != nil || xs[0].VerifiedBy != nil ||
			xs[0].SourceRecordID == nil || !strings.HasPrefix(xs[0].Issuer, "sponsor-invite:") {
			t.Errorf("identifiers = %+v, %v", xs, err)
		}
		src, err := tx.SourceRecord(*xs[0].SourceRecordID)
		if err != nil || src.SOR != "sponsorship" || src.IdentityID == nil || *src.IdentityID != known.Guest.ID {
			t.Errorf("source record = %+v, %v", src, err)
		}
		in, err := tx.Intake(known.Sponsorship.IntakeID)
		if err != nil || in.Channel != store.ChannelSponsorInvite || in.MatchMode != store.MatchSelfAsserted ||
			in.InvitationStatus != store.InvitationReady || in.SponsorIdentityID == nil || *in.SponsorIdentityID != carol {
			t.Errorf("intake = %+v, %v", in, err)
		}
		return err
	})
	// alice kept her own affiliations
	for _, a := range e.affs(alice) {
		if a.Source == store.AffSourceSponsorship {
			t.Errorf("alice got an affiliation from the invitation: %+v", a)
		}
	}
	// the same address invited twice is two invitations, not a collision
	again := e.invited(e.bob, invite("nobody.knows@t.example", "visitor", day(5)))
	if again.Guest.ID == fresh.Guest.ID {
		t.Error("the second invitation reused the first person")
	}
}

func TestSponsorship_InvitationRefusals(t *testing.T) {
	e := newEnv(t)
	privileged := e.catalog("group:aws:ProdAdmin", "medium")
	plain := e.catalog("group:aws:DevAdmin", "low")
	uncataloged := e.f.B.IDs["group:okta:eng"]
	two := 2
	one := 1
	for name, tc := range map[string]struct {
		mod  func(*sponsorship.Invite)
		code string
	}{
		"no email":         {func(i *sponsorship.Invite) { i.Email = "" }, "invalid_email"},
		"bad email":        {func(i *sponsorship.Invite) { i.Email = "not-an-email" }, "invalid_email"},
		"no name":          {func(i *sponsorship.Invite) { i.GivenName = " " }, "invalid_name"},
		"long name":        {func(i *sponsorship.Invite) { i.FamilyName = strings.Repeat("x", 101) }, "invalid_name"},
		"control in name":  {func(i *sponsorship.Invite) { i.GivenName = "a\x00b" }, "invalid_name"},
		"no purpose":       {func(i *sponsorship.Invite) { i.Purpose = "" }, "invalid_purpose"},
		"no end":           {func(i *sponsorship.Invite) { i.EndsAt = time.Time{} }, "invalid_dates"},
		"unknown pop":      {func(i *sponsorship.Invite) { i.Population = "student" }, "unknown_population"},
		"too long":         {func(i *sponsorship.Invite) { i.EndsAt = day(31) }, "exceeds_max_duration"},
		"bad ial":          {func(i *sponsorship.Invite) { v := 3; i.RequiredIAL = &v }, "invalid_ial"},
		"uncataloged item": {func(i *sponsorship.Invite) { i.Bundle = []int64{uncataloged} }, "bundle_item_not_requestable"},
		"unknown item":     {func(i *sponsorship.Invite) { i.Bundle = []int64{987654} }, "bundle_item_not_requestable"},
		"privileged at IAL 1": {func(i *sponsorship.Invite) {
			i.Bundle, i.RequiredIAL = []int64{privileged}, &one
		}, "bundle_needs_ial2"},
	} {
		t.Run(name, func(t *testing.T) {
			in := invite("g@x.example", "visitor", day(5))
			tc.mod(&in)
			err := e.do(func(tx *store.TenantTx) error {
				_, err := e.svc.Invite(tx, e.carol, in, store.ChannelSponsorInvite, "", now)
				return err
			})
			e.wantCode(err, tc.code)
		})
	}
	var n int
	e.must(func(tx *store.TenantTx) error {
		ss, err := tx.Sponsorships(store.SponsorshipFilter{})
		n = len(ss)
		return err
	})
	if n != 0 {
		t.Errorf("%d sponsorships written by refusals", n)
	}
	// the sponsor must be a person
	err := e.do(func(tx *store.TenantTx) error {
		_, err := e.svc.Invite(tx, e.admin, invite("g@x.example", "visitor", day(5)), store.ChannelSponsorInvite, "", now)
		return err
	})
	e.wantCode(err, "sponsor_identity_required")

	// a privileged bundle raises the required IAL on its own; a plain one leaves the default
	r := e.invited(e.carol, func() sponsorship.Invite {
		i := invite("p@x.example", "visitor", day(5))
		i.Bundle = []int64{privileged, plain, privileged}
		return i
	}())
	items := sponsorship.ParseBundle(r.Sponsorship.AccessBundle)
	if r.Sponsorship.RequiredIAL != 2 || len(items) != 2 || !items[0].Privileged || items[1].Privileged {
		t.Errorf("bundle = %+v ial %d", items, r.Sponsorship.RequiredIAL)
	}
	r = e.invited(e.carol, invite("q@x.example", "contractor", day(40)))
	if r.Sponsorship.RequiredIAL != 1 || r.Sponsorship.RequiredAAL != 2 {
		t.Errorf("contractor IAL %d AAL %d", r.Sponsorship.RequiredIAL, r.Sponsorship.RequiredAAL)
	}
	i := invite("r@x.example", "visitor", day(5))
	i.RequiredIAL = &two
	if r = e.invited(e.carol, i); r.Sponsorship.RequiredIAL != 2 {
		t.Errorf("explicit IAL %d", r.Sponsorship.RequiredIAL)
	}
}

func TestSponsorship_ActivationWritesAffiliationAndLifecycle(t *testing.T) {
	e := newEnv(t)
	carol := e.f.B.IDs["carol"]
	for _, tc := range []struct{ pop, aff, worker string }{
		{"visitor", store.AffGuestVisitor, store.WorkerGuest},
		{"contractor", store.AffContractor, store.WorkerContractor},
		{"volunteer", store.AffVolunteer, store.WorkerGuest},
		{"partner", store.AffPartner, store.WorkerPartner},
	} {
		t.Run(tc.pop, func(t *testing.T) {
			res := e.invited(e.carol, invite(tc.pop+"@x.example", tc.pop, day(20)))
			g := res.Guest.ID
			affs := e.affs(g)
			if len(affs) != 1 || affs[0].Type != tc.aff || affs[0].Source != store.AffSourceSponsorship || affs[0].SourceRef == nil ||
				*affs[0].SourceRef != res.Sponsorship.ID || affs[0].Status != store.AffPending || !affs[0].EndsAt.Equal(day(20)) ||
				affs[0].Population == nil || affs[0].CreatedBy == nil {
				t.Errorf("affiliations = %+v", affs)
			}
			l := e.lifecycleOf(g)
			if l == nil || l.WorkerType != tc.worker || l.SponsorID == nil || *l.SponsorID != carol || !l.EndsAt.Equal(day(20)) ||
				l.Source != "sponsorship" || l.EndedAt != nil {
				t.Errorf("lifecycle = %+v", l)
			}
			if p := e.person(g); p.Status != "invited" {
				t.Errorf("status = %s: a guest is active only after the claim (GU-6)", p.Status)
			}
		})
	}
	if a := e.auditActions(); a["sponsorship.create"] != 4 {
		t.Errorf("audit = %v", a)
	}
}

func TestSponsorship_PolicyVersionOnEveryDecision(t *testing.T) {
	e := newEnv(t)
	prod := e.catalog("group:aws:ProdAdmin", "medium")
	version := e.svc.Policy.Version
	// every kind of decision: invite, approval needed, approve, renew, transfer, accept, end, reject
	contractorIn := invite("c@x.example", "contractor", day(60))
	contractorIn.Bundle = []int64{prod}
	pending := e.invited(e.carol, contractorIn).Sponsorship
	e.must(func(tx *store.TenantTx) error { _, err := e.svc.Approve(tx, e.admin, pending.ID, now); return err })
	rejected := e.invited(e.carol, contractorIn).Sponsorship
	e.must(func(tx *store.TenantTx) error {
		_, err := e.svc.Reject(tx, e.admin, rejected.ID, "no", now)
		return err
	})
	visitor := e.invited(e.carol, invite("v@x.example", "visitor", day(10))).Sponsorship
	e.must(func(tx *store.TenantTx) error {
		_, err := e.svc.Renew(tx, e.carol, visitor.ID, day(20), "still here", now)
		return err
	})
	e.must(func(tx *store.TenantTx) error {
		_, err := e.svc.Transfer(tx, e.carol, visitor.ID, e.f.B.IDs["bob"], "I leave", now)
		return err
	})
	e.must(func(tx *store.TenantTx) error { _, err := e.svc.AcceptTransfer(tx, e.bob, visitor.ID, now); return err })
	e.must(func(tx *store.TenantTx) error { _, err := e.svc.End(tx, e.bob, visitor.ID, "done", now); return err })
	for _, id := range []string{pending.ID, rejected.ID, visitor.ID} {
		if s := e.get(id); s.PolicyVersion != version {
			t.Errorf("%s: policy version %q", id, s.PolicyVersion)
		}
		e.must(func(tx *store.TenantTx) error {
			evs, err := tx.SponsorshipEvents(id)
			if len(evs) < 2 {
				t.Errorf("%s: %d events", id, len(evs))
			}
			for _, ev := range evs {
				if ev.PolicyVersion != version {
					t.Errorf("%s event %s: policy version %q", id, ev.Event, ev.PolicyVersion)
				}
			}
			return err
		})
	}
	// and in the audit ledger
	e.must(func(tx *store.TenantTx) error {
		evs, err := tx.AuditEvents(store.AuditFilter{})
		seen := map[string]bool{}
		for _, ev := range evs {
			if !strings.HasPrefix(ev.Action, "sponsorship.") {
				continue
			}
			seen[ev.Action] = true
			if !strings.Contains(string(ev.Detail), `"policy_version":"`+version+`"`) {
				t.Errorf("audit %s has no policy_version %s: %s", ev.Action, version, ev.Detail)
			}
		}
		for _, a := range []string{"create", "approve", "reject", "renew", "transfer", "accept_transfer", "end"} {
			if !seen["sponsorship."+a] {
				t.Errorf("no audit event sponsorship.%s", a)
			}
		}
		return err
	})
}

func TestSponsorship_TwoSponsorshipsActiveUntilTheLastEnds(t *testing.T) {
	e := newEnv(t)
	carol, bob := e.f.B.IDs["carol"], e.f.B.IDs["bob"]
	first := e.invited(e.carol, invite("two@x.example", "visitor", day(10)))
	g := first.Guest.ID
	var second *store.Sponsorship
	e.must(func(tx *store.TenantTx) error {
		r, err := e.svc.SponsorExisting(tx, e.bob, g, invite("", "contractor", day(40)), now)
		if r != nil {
			second = r.Sponsorship
		}
		return err
	})
	if l := e.lifecycleOf(g); l == nil || l.WorkerType != store.WorkerContractor || *l.SponsorID != bob || !l.EndsAt.Equal(day(40)) {
		t.Fatalf("two sponsorships: lifecycle = %+v", l)
	}
	// ending the one that ends last leaves the other: its sponsor, its end, its worker type
	e.must(func(tx *store.TenantTx) error {
		_, err := e.svc.End(tx, e.bob, second.ID, "project over", now)
		return err
	})
	l := e.lifecycleOf(g)
	if l == nil || l.EndedAt != nil || l.WorkerType != store.WorkerGuest || *l.SponsorID != carol || !l.EndsAt.Equal(day(10)) {
		t.Fatalf("after the first end: lifecycle = %+v", l)
	}
	if p := e.person(g); p.Status != "invited" || p.TerminatedAt != nil {
		t.Errorf("the person ended with a sponsorship left: %+v", p)
	}
	byType := map[string]*store.Affiliation{}
	for _, a := range e.affs(g) {
		byType[a.Type] = a
	}
	if byType[store.AffContractor].Status != store.AffEnded || byType[store.AffGuestVisitor].Status != store.AffPending {
		t.Errorf("affiliations = %+v / %+v", byType[store.AffContractor], byType[store.AffGuestVisitor])
	}
	// ending the last one ends the person now, through the lifecycle's end path
	e.must(func(tx *store.TenantTx) error {
		_, err := e.svc.End(tx, e.carol, first.Sponsorship.ID, "left early", now)
		return err
	})
	l = e.lifecycleOf(g)
	if l == nil || l.EndedAt == nil || !l.EndedAt.Equal(now) {
		t.Fatalf("after the last end: lifecycle = %+v", l)
	}
	if p := e.person(g); p.Status != "terminated" || p.TerminatedAt == nil {
		t.Errorf("person = %+v", p)
	}
	for _, a := range e.affs(g) {
		if a.Status != store.AffEnded && a.Status != store.AffRevoked {
			t.Errorf("affiliation still %s", a.Status)
		}
	}
	if s := e.get(first.Sponsorship.ID); s.Status != store.SponsorEnded || s.EndedAt == nil {
		t.Errorf("sponsorship = %+v", s)
	}
	acts := e.auditActions()
	if acts["lifecycle.end"] != 1 || acts["sponsorship.end"] != 2 {
		t.Errorf("audit = %v", acts)
	}
	// a finished sponsorship cannot end again, or be renewed
	e.wantCode(e.do(func(tx *store.TenantTx) error {
		_, err := e.svc.End(tx, e.carol, first.Sponsorship.ID, "again", now)
		return err
	}), "already_ended")
	e.wantCode(e.do(func(tx *store.TenantTx) error {
		_, err := e.svc.Renew(tx, e.carol, first.Sponsorship.ID, day(20), "why", now)
		return err
	}), "not_active")
}

func TestSponsorship_ApprovalFlow(t *testing.T) {
	e := newEnv(t)
	prod := e.catalog("group:aws:ProdAdmin", "medium")
	in := invite("con@x.example", "contractor", day(90))
	in.Bundle = []int64{prod}
	res := e.invited(e.carol, in)
	id, g := res.Sponsorship.ID, res.Guest.ID
	if res.Sponsorship.Status != store.SponsorPendingApproval || !res.Decision.NeedsApproval || res.Sponsorship.RequiredIAL != 2 {
		t.Fatalf("sponsorship = %+v", res.Sponsorship)
	}
	// nothing is granted before the second person decides
	if len(e.affs(g)) != 0 || e.lifecycleOf(g) != nil {
		t.Error("an unapproved sponsorship wrote an affiliation or a lifecycle")
	}
	approve := func(by sponsorship.Actor) error {
		return e.do(func(tx *store.TenantTx) error { _, err := e.svc.Approve(tx, by, id, now); return err })
	}
	e.wantCode(approve(e.carol), "approver_required")
	self := e.admin
	self.IdentityID = e.carol.IdentityID // an approver who is the sponsor
	e.wantCode(approve(self), "self_approval")
	sameUser := e.carol
	sameUser.Approver = true // the requesting user, now holding the permission
	e.wantCode(approve(sameUser), "self_approval")
	if err := approve(e.admin); err != nil {
		t.Fatal(err)
	}
	s := e.get(id)
	if s.Status != store.SponsorActive || s.ApprovedBy == nil || *s.ApprovedBy != e.admin.UserID.String() || s.ApprovedAt == nil {
		t.Errorf("approved = %+v", s)
	}
	if l := e.lifecycleOf(g); l == nil || l.WorkerType != store.WorkerContractor || !l.EndsAt.Equal(day(90)) || len(e.affs(g)) != 1 {
		t.Errorf("lifecycle = %+v, affiliations = %+v", l, e.affs(g))
	}
	e.wantCode(approve(e.admin), "not_pending")

	// a rejection retires the invited identity and needs a reason
	res2 := e.invited(e.carol, in)
	rej := func(reason string) error {
		return e.do(func(tx *store.TenantTx) error {
			_, err := e.svc.Reject(tx, e.admin, res2.Sponsorship.ID, reason, now)
			return err
		})
	}
	e.wantCode(rej(" "), "reason_required")
	if err := rej("not needed"); err != nil {
		t.Fatal(err)
	}
	if s := e.get(res2.Sponsorship.ID); s.Status != store.SponsorRejected || s.EndedAt == nil || *s.EndReason != "not needed" {
		t.Errorf("rejected = %+v", s)
	}
	if p := e.person(res2.Guest.ID); p.Status != "terminated" {
		t.Errorf("rejected guest = %+v", p)
	}
	if len(e.affs(res2.Guest.ID)) != 0 || e.lifecycleOf(res2.Guest.ID) != nil {
		t.Error("a rejected sponsorship left an affiliation or lifecycle")
	}
	// the sponsor can withdraw a request that waits: revoked, and the identity retired
	res3 := e.invited(e.carol, in)
	e.must(func(tx *store.TenantTx) error {
		_, err := e.svc.End(tx, e.carol, res3.Sponsorship.ID, "changed my mind", now)
		return err
	})
	if s := e.get(res3.Sponsorship.ID); s.Status != store.SponsorRevoked {
		t.Errorf("withdrawn = %+v", s)
	}
	if a := e.auditActions(); a["sponsorship.approve"] != 1 || a["sponsorship.reject"] != 1 {
		t.Errorf("audit = %v", a)
	}
}

func TestSponsorship_Renew(t *testing.T) {
	e := newEnv(t)
	prod := e.catalog("group:aws:ProdAdmin", "medium")
	res := e.invited(e.carol, invite("r@x.example", "visitor", day(10)))
	id, g := res.Sponsorship.ID, res.Guest.ID
	renew := func(by sponsorship.Actor, to time.Time, why string) error {
		return e.do(func(tx *store.TenantTx) error { _, err := e.svc.Renew(tx, by, id, to, why, now); return err })
	}
	e.wantCode(renew(e.carol, day(20), " "), "justification_required")
	e.wantCode(renew(e.carol, day(10), "same"), "not_later")
	e.wantCode(renew(e.carol, day(5), "earlier"), "not_later")
	e.wantCode(renew(e.carol, day(31), "too long"), "exceeds_max_duration") // a visitor: 30 days from now
	e.wantCode(renew(e.bob, day(20), "not mine"), "not_sponsor")
	if err := renew(e.carol, day(30), "extended conference"); err != nil {
		t.Fatal(err)
	}
	if s := e.get(id); !s.EndsAt.Equal(day(30)) || s.Status != store.SponsorActive {
		t.Errorf("renewed = %+v", s)
	}
	if l := e.lifecycleOf(g); !l.EndsAt.Equal(day(30)) || l.Source != "sponsorship" {
		t.Errorf("lifecycle = %+v", l)
	}
	if a := e.affs(g); len(a) != 1 || !a[0].EndsAt.Equal(day(30)) {
		t.Errorf("affiliation = %+v", a)
	}
	e.must(func(tx *store.TenantTx) error {
		evs, err := tx.SponsorshipEvents(id)
		last := evs[len(evs)-1]
		if last.Event != "renewed" || last.Note == nil || *last.Note != "extended conference" {
			t.Errorf("history = %+v", last)
		}
		l, _ := tx.LifecycleFor(g)
		le, _ := tx.LifecycleEvents(g)
		if l == nil || le[len(le)-1].Event != "extended" {
			t.Errorf("lifecycle history = %+v", le)
		}
		return err
	})
	// a renewal re-runs the policy: the sponsor must still be eligible
	e.must(func(tx *store.TenantTx) error {
		end := day(200)
		return tx.PutLifecycle(&store.Lifecycle{IdentityID: e.f.B.IDs["carol"], WorkerType: store.WorkerContractor,
			SponsorID: e.bob.IdentityID, EndsAt: &end, Source: "manual", UpdatedAt: now})
	})
	e.wantCode(renew(e.carol, day(30).Add(time.Hour), "once more"), "sponsor_not_eligible")

	// a sponsorship that needs a second approver is renewed by one, not by its sponsor alone
	in := invite("c2@x.example", "contractor", day(60))
	in.Bundle = []int64{prod}
	c := e.invited(e.bob, in)
	e.must(func(tx *store.TenantTx) error {
		_, err := e.svc.Approve(tx, e.admin, c.Sponsorship.ID, now)
		return err
	})
	renewC := func(by sponsorship.Actor) error {
		return e.do(func(tx *store.TenantTx) error {
			_, err := e.svc.Renew(tx, by, c.Sponsorship.ID, day(120), "next phase", now)
			return err
		})
	}
	e.wantCode(renewC(e.bob), "renewal_needs_approval")
	if err := renewC(e.admin); err != nil {
		t.Fatal(err)
	}
	if s := e.get(c.Sponsorship.ID); !s.EndsAt.Equal(day(120)) {
		t.Errorf("approver renewal = %+v", s)
	}
}

func TestSponsorship_TransferAcceptAndDeadline(t *testing.T) {
	e := newEnv(t)
	carol, bob, alice := e.f.B.IDs["carol"], e.f.B.IDs["bob"], e.f.B.IDs["alice"]
	res := e.invited(e.carol, invite("t@x.example", "visitor", day(25)))
	id, g := res.Sponsorship.ID, res.Guest.ID
	transfer := func(by sponsorship.Actor, to int64) error {
		return e.do(func(tx *store.TenantTx) error {
			_, err := e.svc.Transfer(tx, by, id, to, "I am leaving", now)
			return err
		})
	}
	accept := func(by sponsorship.Actor, at time.Time) error {
		return e.do(func(tx *store.TenantTx) error { _, err := e.svc.AcceptTransfer(tx, by, id, at); return err })
	}
	e.wantCode(transfer(e.bob, bob), "not_sponsor")          // bob is not the sponsor
	e.wantCode(transfer(e.carol, carol), "transfer_to_self") // to themselves
	e.wantCode(transfer(e.carol, g), "sponsor_not_eligible") // to the guest: invited people cannot sponsor
	e.wantCode(transfer(e.carol, 987654), "transfer_target_not_found")
	e.wantCode(transfer(e.carol, e.f.B.IDs["dave"]), "sponsor_not_eligible") // terminated
	e.wantCode(transfer(e.carol, e.f.B.IDs["svc-etl"]), "sponsor_not_eligible")
	e.wantCode(accept(e.bob, now), "not_pending")
	if err := transfer(e.carol, bob); err != nil {
		t.Fatal(err)
	}
	s := e.get(id)
	if s.Status != store.SponsorTransferPending || *s.TransferToIdentityID != bob || !s.TransferDeadline.Equal(now.AddDate(0, 0, 14)) ||
		s.SponsorIdentityID != carol {
		t.Fatalf("pending = %+v", s)
	}
	if l := e.lifecycleOf(g); l.Source != "sponsorship" || *l.SponsorID != carol {
		t.Errorf("the sponsor changed before the target accepted: %+v", l)
	}
	e.wantCode(accept(e.carol, now), "not_transfer_target")
	e.wantCode(accept(e.admin, now), "not_transfer_target")
	e.wantCode(accept(e.bob, now.AddDate(0, 0, 14)), "transfer_expired")
	// bob would exceed his own limit? no: he accepts and becomes the sponsor
	if err := accept(e.bob, now.AddDate(0, 0, 3)); err != nil {
		t.Fatal(err)
	}
	s = e.get(id)
	if s.Status != store.SponsorActive || s.SponsorIdentityID != bob || s.TransferToIdentityID != nil || s.TransferDeadline != nil {
		t.Errorf("accepted = %+v", s)
	}
	if l := e.lifecycleOf(g); *l.SponsorID != bob {
		t.Errorf("lifecycle sponsor = %d, want bob", *l.SponsorID)
	}
	e.wantCode(e.do(func(tx *store.TenantTx) error { _, err := e.svc.End(tx, e.carol, id, "not mine now", now); return err }), "not_sponsor")

	// not accepted by the deadline: the sponsorship ends, and with it the person
	e.must(func(tx *store.TenantTx) error {
		_, err := e.svc.Transfer(tx, e.bob, id, alice, "handing over", now)
		return err
	})
	e.must(func(tx *store.TenantTx) error {
		n, err := sponsorship.NeedsSweep(tx, now.AddDate(0, 0, 13))
		if n {
			t.Error("a transfer inside its deadline is due")
		}
		return err
	})
	var res2 sponsorship.SweepResult
	e.must(func(tx *store.TenantTx) (err error) { res2, err = e.svc.Sweep(tx, now.AddDate(0, 0, 14)); return err })
	if res2.TransferExpired != 1 || res2.Expired != 0 {
		t.Errorf("sweep = %+v", res2)
	}
	s = e.get(id)
	if s.Status != store.SponsorEnded || s.EndReason == nil || !strings.Contains(*s.EndReason, "transfer") {
		t.Errorf("after the deadline = %+v", s)
	}
	if l := e.lifecycleOf(g); l.EndedAt == nil {
		t.Errorf("the guest's term did not end: %+v", l)
	}
	if a := e.auditActions(); a["sponsorship.transfer_expire"] != 1 {
		t.Errorf("audit = %v", a)
	}
}

func TestSponsorship_SweepEndsAtTheEndDate(t *testing.T) {
	e := newEnv(t)
	res := e.invited(e.carol, invite("s@x.example", "visitor", day(5)))
	g := res.Guest.ID
	e.must(func(tx *store.TenantTx) error {
		_, err := e.svc.SponsorExisting(tx, e.bob, g, invite("", "visitor", day(9)), now)
		return err
	})
	sweep := func(at time.Time) (r sponsorship.SweepResult) {
		e.must(func(tx *store.TenantTx) (err error) { r, err = e.svc.Sweep(tx, at); return err })
		return r
	}
	if r := sweep(day(4)); r.Expired != 0 {
		t.Errorf("early sweep = %+v", r)
	}
	if r := sweep(day(6)); r.Expired != 1 {
		t.Errorf("first end = %+v", r)
	}
	if l := e.lifecycleOf(g); l.EndedAt != nil || !l.EndsAt.Equal(day(9)) || *l.SponsorID != e.f.B.IDs["bob"] {
		t.Errorf("one sponsorship left: %+v", l)
	}
	if r := sweep(day(10)); r.Expired != 1 {
		t.Errorf("last end = %+v", r)
	}
	if l := e.lifecycleOf(g); l.EndedAt == nil || !l.EndedAt.Equal(day(10)) {
		t.Errorf("the person's term: %+v", l)
	}
	// the lifecycle sweep finds nothing left to do
	e.must(func(tx *store.TenantTx) error {
		r, err := lifecycle.Sweep(tx, day(10))
		if r.Ended != 0 {
			t.Errorf("lifecycle sweep ended %d", r.Ended)
		}
		return err
	})
	if a := e.auditActions(); a["sponsorship.expire"] != 2 || a["lifecycle.end"] != 1 {
		t.Errorf("audit = %v", a)
	}
	if r := sweep(day(11)); r.Expired != 0 {
		t.Errorf("repeat sweep = %+v", r)
	}
}

func TestSponsorship_LifecycleEditsRefusedWhileSponsored(t *testing.T) {
	e := newEnv(t)
	res := e.invited(e.carol, invite("l@x.example", "contractor", day(30)))
	g := res.Guest.ID
	err := e.do(func(tx *store.TenantTx) error {
		_, err := lifecycle.Set(tx, g, lifecycle.Spec{WorkerType: store.WorkerVendor, SponsorID: e.carol.IdentityID, EndsAt: &[]time.Time{day(50)}[0],
			Reason: "x"}, lifecycle.Actor{Display: "Pat"}, now)
		return err
	})
	var le *lifecycle.Error
	if !errors.As(err, &le) || le.Code != "managed_by_sponsorship" || le.Status != 409 {
		t.Errorf("Set = %v", err)
	}
	err = e.do(func(tx *store.TenantTx) error {
		_, err := lifecycle.Extend(tx, g, day(50), "x", lifecycle.Actor{Display: "Pat"}, true, now)
		return err
	})
	if !errors.As(err, &le) || le.Code != "managed_by_sponsorship" {
		t.Errorf("Extend = %v", err)
	}
	// once the sponsorship has ended the lifecycle is nobody's but the ended term's
	e.must(func(tx *store.TenantTx) error {
		_, err := e.svc.End(tx, e.carol, res.Sponsorship.ID, "done", now)
		return err
	})
	err = e.do(func(tx *store.TenantTx) error {
		_, err := lifecycle.Extend(tx, g, day(50), "x", lifecycle.Actor{Display: "Pat"}, true, now)
		return err
	})
	if !errors.As(err, &le) || le.Code != "ended" {
		t.Errorf("Extend after the end = %v", err)
	}
}
