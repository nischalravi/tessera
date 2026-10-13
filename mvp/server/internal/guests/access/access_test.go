package access_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/access"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/sponsorship"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/affiliations"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/fake"
	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

var now = storetest.Now

type env struct {
	t      *testing.T
	f      *storetest.Fixture
	svc    *sponsorship.Service
	fake   *fake.Server
	srv    *httptest.Server
	eng    *provision.Engine
	sealer *seal.Sealer
	conn   string
	system string
	g1, g2 int64
	carol  sponsorship.Actor
	bob    sponsorship.Actor
	clock  time.Time
}

func newEnv(t *testing.T, o fake.Options) *env {
	t.Helper()
	f := storetest.TwoTenants(t)
	e := &env{t: t, f: f, clock: now, conn: f.B.Refs["connection:ad"], svc: sponsorship.New(storetest.IdentityKeyer(t))}
	o.Token = "tok"
	e.fake = fake.New(o)
	e.srv = httptest.NewServer(e.fake.Handler())
	t.Cleanup(e.srv.Close)
	hc, err := safehttp.New(safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	if e.sealer, err = seal.New(seal.RandomBytes(seal.KeySize)); err != nil {
		t.Fatal(err)
	}
	e.eng = &provision.Engine{DB: f.DB, Sealer: e.sealer, HTTP: hc, Clock: func() time.Time { return e.clock },
		MaxAttempts: 2, MaxVerifies: 2, Backoff: func(int) time.Duration { return 0 }}
	carol, bob := f.B.IDs["carol"], f.B.IDs["bob"]
	e.carol = sponsorship.Actor{UserID: uuid.New(), Display: "Carol", IdentityID: &carol}
	e.bob = sponsorship.Actor{UserID: uuid.New(), Display: "Bob", IdentityID: &bob}
	e.tx(func(c *store.TenantTx) error {
		cn, err := c.Connection(e.conn)
		if err != nil {
			return err
		}
		e.system = cn.System
		for _, x := range []string{"bundle-g", "bundle-h"} {
			if err := c.UpsertGroup(&store.Group{TenantID: c.Tenant(), System: e.system, ExternalID: x, Name: x}); err != nil {
				return err
			}
			g, err := c.GroupByXID(e.system, x)
			if err != nil {
				return err
			}
			if err := c.PutCatalogItem(&store.CatalogItem{ID: uuid.NewString(), GroupID: g.ID, Requestable: true, Risk: "low",
				EligibleTypes: []string{"human"}, UpdatedAt: now}); err != nil {
				return err
			}
			if x == "bundle-g" {
				e.g1 = g.ID
			} else {
				e.g2 = g.ID
			}
			e.fake.AddGroup(x, x)
		}
		return nil
	})
	return e
}

func (e *env) tx(fn func(c *store.TenantTx) error) {
	e.t.Helper()
	if err := e.f.DB.InTenant(context.Background(), e.f.B.ID, fn); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) writeBack(on bool) {
	e.t.Helper()
	id := store.NewID()
	enc, err := provision.SealToken(e.sealer, e.f.B.ID, id, "tok")
	if err != nil {
		e.t.Fatal(err)
	}
	e.tx(func(c *store.TenantTx) error {
		return c.UpsertProvTarget(&store.ProvTarget{ID: id, ConnectionID: e.conn, Kind: provision.KindSCIM, BaseURL: e.srv.URL + "/scim/v2",
			Settings: "{}", CredentialEnc: enc, WriteBack: on, CreatedBy: "admin"}, now)
	})
}

func (e *env) run() {
	e.t.Helper()
	for i := 0; i < 4; i++ {
		if _, err := e.eng.RunTenant(context.Background(), e.f.B.ID); err != nil {
			e.t.Fatal(err)
		}
	}
}

func (e *env) invite(by sponsorship.Actor, email string, days int, groups ...int64) *store.Sponsorship {
	e.t.Helper()
	var ss *store.Sponsorship
	e.tx(func(c *store.TenantTx) error {
		r, err := e.svc.Invite(c, by, sponsorship.Invite{GivenName: "Gwen", Email: email, Population: "visitor", Purpose: "talk",
			EndsAt: now.AddDate(0, 0, days), Bundle: groups}, store.ChannelSponsorInvite, "", now)
		if r != nil {
			ss = r.Sponsorship
		}
		return err
	})
	return ss
}

func (e *env) second(by sponsorship.Actor, guest int64, days int, groups ...int64) *store.Sponsorship {
	e.t.Helper()
	var ss *store.Sponsorship
	e.tx(func(c *store.TenantTx) error {
		r, err := e.svc.SponsorExisting(c, by, guest, sponsorship.Invite{Population: "contractor", Purpose: "project",
			EndsAt: now.AddDate(0, 0, days), Bundle: groups}, now)
		if r != nil {
			ss = r.Sponsorship
		}
		return err
	})
	return ss
}

// claim does what a completed claim does to the person, then its GU-12 hook.
func (e *env) claim(guest int64) {
	e.t.Helper()
	e.tx(func(c *store.TenantTx) error {
		if err := c.SetIdentityStatus(guest, "active"); err != nil {
			return err
		}
		all, err := c.Sponsorships(store.SponsorshipFilter{Guest: guest})
		if err != nil {
			return err
		}
		for _, s := range all {
			if a, err := affiliations.ForSponsorship(c, guest, s.ID); err == nil && a != nil && a.Status == store.AffPending {
				if err := c.ActivateAffiliation(a.ID); err != nil {
					return err
				}
			}
		}
		return access.Claimed(c, now, guest, 0, 1)
	})
}

func (e *env) end(by sponsorship.Actor, id string) {
	e.t.Helper()
	e.tx(func(c *store.TenantTx) error {
		_, err := e.svc.End(c, by, id, "done", now)
		return err
	})
}

func (e *env) items(sp string) (out []*store.BundleItem) {
	e.t.Helper()
	e.tx(func(c *store.TenantTx) (err error) {
		out, err = c.BundleItems(store.BundleItemFilter{Sponsorship: sp})
		return err
	})
	return out
}

// edge is the guest's membership edge of a group, nil when there is none.
func (e *env) edge(guest, group int64) (ed *store.GrantEdge) {
	e.t.Helper()
	e.tx(func(c *store.TenantTx) error {
		accts, err := c.IdentityAccounts(guest)
		if err != nil {
			return err
		}
		for _, a := range accts {
			if a.System != e.system {
				continue
			}
			if x, err := c.EdgeBetween(graph.Key("account", a.ID), graph.Key("group", group)); err == nil {
				ed = x
			} else if !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
		return nil
	})
	return ed
}

func (e *env) opsOfKind(kind string) (n int) {
	e.t.Helper()
	e.tx(func(c *store.TenantTx) error {
		ops, err := c.ProvOps(store.ProvOpFilter{})
		for _, o := range ops {
			if o.Kind == kind {
				n++
			}
		}
		return err
	})
	return n
}

func (e *env) actions() string {
	var out []string
	e.tx(func(c *store.TenantTx) error {
		evs, err := c.AuditLog(-1)
		for _, ev := range evs {
			out = append(out, ev.Action)
		}
		return err
	})
	return strings.Join(out, " ")
}

func TestBundle_DirectWhenWriteBackOff(t *testing.T) {
	e := newEnv(t, fake.Options{})
	e.writeBack(false)
	ss := e.invite(e.carol, "gwen@guest.example", 10, e.g1, e.g2)
	its := e.items(ss.ID)
	if len(its) != 2 || its[0].Status != store.BundlePending {
		t.Fatalf("before the claim: %+v", its)
	}
	if e.edge(ss.GuestIdentityID, e.g1) != nil {
		t.Fatal("access granted before the guest claimed")
	}
	e.claim(ss.GuestIdentityID)
	for _, it := range e.items(ss.ID) {
		if it.Status != store.BundleGranted || it.EdgeID == nil {
			t.Fatalf("after the claim: %+v", it)
		}
	}
	ed := e.edge(ss.GuestIdentityID, e.g1)
	if ed == nil || ed.Source != "guest_sponsorship" || ed.ExpiresAt == nil || !ed.ExpiresAt.Equal(ss.EndsAt) {
		t.Fatalf("edge = %+v, want source guest_sponsorship expiring at %v", ed, ss.EndsAt)
	}
	if n := e.opsOfKind("add_entitlement") + e.opsOfKind("create_account"); n != 0 {
		t.Errorf("%d provisioning operations with write-back off", n)
	}
	if a := e.actions(); !strings.Contains(a, "guest.bundle.plan") || !strings.Contains(a, "guest.bundle.grant") {
		t.Errorf("audit = %s", a)
	}
	e.end(e.carol, ss.ID)
	if e.edge(ss.GuestIdentityID, e.g1) != nil {
		t.Error("the edge outlived the sponsorship")
	}
	for _, it := range e.items(ss.ID) {
		if it.Status != store.BundleRemoved {
			t.Errorf("after the end: %+v", it)
		}
	}
}

func TestBundle_GrantedOnlyAfterVerify(t *testing.T) {
	e := newEnv(t, fake.Options{})
	e.writeBack(true)
	ss := e.invite(e.carol, "gwen@guest.example", 10, e.g1)
	e.claim(ss.GuestIdentityID)
	it := e.items(ss.ID)[0]
	if it.Status != store.BundlePending || it.GrantOpID == nil || it.AccountOpID == nil || e.edge(ss.GuestIdentityID, e.g1) != nil {
		t.Fatalf("after the claim, before the target: %+v", it)
	}
	e.tx(func(c *store.TenantTx) error {
		a, err := c.ProvOpByKey("guest:" + ss.ID + ":" + e.system + ":account")
		if err != nil || a.Source != provision.SourceGuest {
			t.Errorf("account op = %+v, %v", a, err)
		}
		g, err := c.ProvOpByKey("guest:" + ss.ID + ":" + itoa(e.g1) + ":add")
		if err != nil || g.Kind != "add_entitlement" {
			t.Errorf("grant op = %+v, %v", g, err)
		}
		return nil
	})
	e.run()
	it = e.items(ss.ID)[0]
	ed := e.edge(ss.GuestIdentityID, e.g1)
	if it.Status != store.BundleGranted || ed == nil || ed.Source != "guest_sponsorship" {
		t.Fatalf("after verify: %+v, edge %+v", it, ed)
	}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

// A write the target refuses, or accepts and does not apply, leaves no edge.
func TestBundle_NoEdgeWhenTheTargetDoesNotShowIt(t *testing.T) {
	for _, fault := range []string{fake.FailWrites, fake.DropWrites} {
		t.Run(fault, func(t *testing.T) {
			e := newEnv(t, fake.Options{Fault: fault})
			e.writeBack(true)
			ss := e.invite(e.carol, "gwen@guest.example", 10, e.g1)
			e.claim(ss.GuestIdentityID)
			e.run()
			it := e.items(ss.ID)[0]
			if it.Status != store.BundlePending || e.edge(ss.GuestIdentityID, e.g1) != nil {
				t.Fatalf("item = %+v with an edge after a bad write", it)
			}
			e.tx(func(c *store.TenantTx) error {
				v, err := access.Views(c, []*store.BundleItem{it})
				if err != nil || len(v) != 1 || v[0].State != access.StateFailed && v[0].State != access.StatePending {
					t.Errorf("view = %+v, %v", v, err)
				}
				return nil
			})
		})
	}
}

func TestBundle_EndsWithSponsorship(t *testing.T) {
	e := newEnv(t, fake.Options{})
	e.writeBack(true)
	ss := e.invite(e.carol, "gwen@guest.example", 10, e.g1)
	e.claim(ss.GuestIdentityID)
	e.run()
	if e.edge(ss.GuestIdentityID, e.g1) == nil {
		t.Fatal("not granted")
	}
	e.end(e.carol, ss.ID)
	if it := e.items(ss.ID)[0]; it.Status != store.BundleRemoving || it.RemoveOpID == nil || e.edge(ss.GuestIdentityID, e.g1) == nil {
		t.Fatalf("while the removal is in flight: %+v", it)
	}
	e.run()
	if it := e.items(ss.ID)[0]; it.Status != store.BundleRemoved || e.edge(ss.GuestIdentityID, e.g1) != nil {
		t.Fatalf("after the removal verified: %+v", it)
	}
	// the last sponsorship ending disables the account once, through the leaver plan
	if n := e.opsOfKind("disable_account"); n != 1 {
		t.Errorf("disable_account operations = %d, want 1", n)
	}
	if n := e.opsOfKind("remove_entitlement"); n != 1 {
		t.Errorf("remove_entitlement operations = %d, want 1 (the leaver plan leaves the bundle's edge to its own removal)", n)
	}
}

func TestBundle_RenewExtendsExpiry(t *testing.T) {
	e := newEnv(t, fake.Options{})
	e.writeBack(false)
	ss := e.invite(e.carol, "gwen@guest.example", 10, e.g1)
	e.claim(ss.GuestIdentityID)
	to := now.AddDate(0, 0, 20)
	e.tx(func(c *store.TenantTx) error {
		_, err := e.svc.Renew(c, e.carol, ss.ID, to, "more talks", now)
		return err
	})
	ed := e.edge(ss.GuestIdentityID, e.g1)
	if ed == nil || ed.ExpiresAt == nil || !ed.ExpiresAt.Equal(to) {
		t.Fatalf("edge after renew = %+v, want expiry %v", ed, to)
	}
	if it := e.items(ss.ID)[0]; !it.ExpiresAt.Equal(to) {
		t.Errorf("item expiry = %v", it.ExpiresAt)
	}
	if !strings.Contains(e.actions(), "guest.bundle.extend") {
		t.Error("no guest.bundle.extend event")
	}
}

func TestBundle_TwoSponsorshipsEndIndependently(t *testing.T) {
	for _, first := range []int{1, 2} {
		e := newEnv(t, fake.Options{})
		e.writeBack(false)
		s1 := e.invite(e.carol, "gwen@guest.example", 10, e.g1)
		e.claim(s1.GuestIdentityID)
		s2 := e.second(e.bob, s1.GuestIdentityID, 20, e.g1, e.g2)
		guest := s1.GuestIdentityID
		if e.edge(guest, e.g2) == nil {
			t.Fatal("the second bundle was not granted to an active guest")
		}
		if ed := e.edge(guest, e.g1); ed == nil || ed.ExpiresAt == nil || !ed.ExpiresAt.Equal(s2.EndsAt) {
			t.Fatalf("shared edge = %+v, want expiry of the later sponsorship %v", ed, s2.EndsAt)
		}
		if first == 1 {
			e.end(e.carol, s1.ID)
			if e.edge(guest, e.g1) == nil || e.edge(guest, e.g2) == nil {
				t.Fatal("ending the first sponsorship took the second one's access")
			}
			e.end(e.bob, s2.ID)
		} else {
			e.end(e.bob, s2.ID)
			if e.edge(guest, e.g2) != nil {
				t.Error("the ended sponsorship's own group is still granted")
			}
			ed := e.edge(guest, e.g1)
			if ed == nil || ed.ExpiresAt == nil || !ed.ExpiresAt.Equal(s1.EndsAt) {
				t.Fatalf("g1 after the second ended = %+v, want the first's expiry %v", ed, s1.EndsAt)
			}
			e.end(e.carol, s1.ID)
		}
		if e.edge(guest, e.g1) != nil || e.edge(guest, e.g2) != nil {
			t.Errorf("order %d: access left after both ended", first)
		}
	}
}

func members(t *testing.T, e *env, key string) []int64 {
	t.Helper()
	var out []int64
	e.tx(func(c *store.TenantTx) error {
		g, err := c.GroupByXID(access.RefSystem, key)
		if err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		es, err := c.EdgesBySource(store.EdgeSourceRefGroup)
		for _, ed := range es {
			if ed.Dst == graph.Key("group", g.ID) {
				_, aid, _ := graph.ParseKey(ed.Src)
				a, err := c.Account(aid)
				if err == nil && a.IdentityID != nil {
					out = append(out, *a.IdentityID)
				}
			}
		}
		return err
	})
	return out
}

func TestRefGroups_TrackAffiliations(t *testing.T) {
	e := newEnv(t, fake.Options{})
	e.writeBack(false)
	ss := e.invite(e.carol, "gwen@guest.example", 10)
	guest := ss.GuestIdentityID
	full := func() {
		e.tx(func(c *store.TenantTx) error {
			_, err := access.Recompute(c, now, "test", 0, e.svc.CanSponsor)
			return err
		})
	}
	full()
	if slices.Contains(members(t, e, access.RefGuestActive), guest) {
		t.Fatal("an invited, unclaimed guest is in ref:guest:active")
	}
	e.claim(guest)
	for _, k := range []string{access.RefGuestActive, access.RefGuestVisitor} {
		if !slices.Contains(members(t, e, k), guest) {
			t.Errorf("claimed visitor not in %s", k)
		}
	}
	if slices.Contains(members(t, e, access.RefGuestContractor), guest) || slices.Contains(members(t, e, access.RefIAL2), guest) {
		t.Error("a claimed visitor is in the contractor or IAL 2 group")
	}
	carol := e.f.B.IDs["carol"]
	if !slices.Contains(members(t, e, access.RefSponsorEligible), carol) || !slices.Contains(members(t, e, access.RefIAL2), carol) {
		t.Errorf("an employee is not in ref:sponsor:eligible and ref:ial:2")
	}
	if slices.Contains(members(t, e, access.RefSponsorEligible), guest) {
		t.Error("a guest is sponsor-eligible")
	}
	e.end(e.carol, ss.ID)
	for _, k := range []string{access.RefGuestActive, access.RefGuestVisitor} {
		if slices.Contains(members(t, e, k), guest) {
			t.Errorf("an ended guest is still in %s", k)
		}
	}
	// reference groups are Tessera-only: system tessera, kind reference, never provisioned
	e.tx(func(c *store.TenantTx) error {
		g, err := c.GroupByXID(access.RefSystem, access.RefGuestActive)
		if err != nil || g.Kind != access.RefKind || !access.IsRefGroup(g) {
			t.Errorf("group = %+v, %v", g, err)
		}
		if tg, err := provision.Route(c, access.RefSystem); err != nil || tg != nil {
			t.Errorf("a reference group has a provisioning target: %v, %v", tg, err)
		}
		need, err := access.NeedsRecompute(c, now, e.svc.CanSponsor)
		if err != nil || need {
			t.Errorf("a second recompute still has work: %v, %v", need, err)
		}
		return nil
	})
	if !strings.Contains(e.actions(), "refgroup.reconcile") {
		t.Error("no refgroup.reconcile event")
	}
}

// ---------------------------------------------------------------- guest requests

func (e *env) actor(name string, ident *int64, decider bool) requests.Actor {
	e.t.Helper()
	pu := &store.PlatformUser{DisplayName: name, IdentityID: ident, CreatedAt: now}
	e.tx(func(c *store.TenantTx) error { return c.InsertPlatformUser(pu) })
	return requests.Actor{UserID: pu.ID, Display: name, IdentityID: ident, Decider: decider}
}

// guestWithItem: a claimed guest (account in the system through a bundle of
// g1) and a catalog item for g2 open to visitors, at the given risk.
func (e *env) guestWithItem(risk string, pops []string) (guest int64, item string, g requests.Actor) {
	e.t.Helper()
	e.writeBack(false)
	ss := e.invite(e.carol, "gwen@guest.example", 10, e.g1)
	e.claim(ss.GuestIdentityID)
	owner := e.f.B.IDs["bob"]
	hours := 8.0
	e.tx(func(c *store.TenantTx) error {
		it, err := requests.PutItem(c, e.g2, requests.ItemSpec{Requestable: true, Risk: risk, OwnerIdentityID: &owner,
			EligibleTypes: []string{"human"}, Populations: pops, DefaultHours: &hours}, requests.Actor{UserID: uuid.New(), Display: "admin"}, now)
		if it != nil {
			item = it.ID
		}
		return err
	})
	gi := ss.GuestIdentityID
	return gi, item, e.actor("Gwen", &gi, false)
}

func (e *env) submit(by requests.Actor, guest int64, item string) ([]*store.RequestLine, error) {
	var lines []*store.RequestLine
	var serr error
	e.tx(func(c *store.TenantTx) error {
		_, lines, serr = requests.Submit(c, requests.Submission{Beneficiaries: []int64{guest}, Items: []string{item},
			Justification: "need it"}, by, false, now)
		return nil
	})
	return lines, serr
}

func code(err error) string {
	var re *requests.Error
	if errors.As(err, &re) {
		return re.Code
	}
	if err != nil {
		return err.Error()
	}
	return ""
}

func TestRequest_StepUpWhenIALTooLow(t *testing.T) {
	e := newEnv(t, fake.Options{})
	guest, item, by := e.guestWithItem("high", []string{"visitor"})
	if _, err := e.submit(by, guest, item); code(err) != "step_up_claim_required" {
		t.Fatalf("a guest at IAL 0 asking for a high-risk item: %v", err)
	}
	e.tx(func(c *store.TenantTx) error {
		return c.PutIdentityAssurance(&store.Assurance{IdentityID: guest, IAL: 2, AAL: 2, Source: "idv", RecordedAt: now})
	})
	if lines, err := e.submit(by, guest, item); err != nil || len(lines) != 1 {
		t.Fatalf("at IAL 2: %v, %v", lines, err)
	}
}

func TestRequest_ItemMustNameTheGuestsPopulation(t *testing.T) {
	e := newEnv(t, fake.Options{})
	guest, item, by := e.guestWithItem("low", []string{"partner"})
	if _, err := e.submit(by, guest, item); code(err) != "not_eligible" {
		t.Fatalf("an item for partners, asked by a visitor: %v", err)
	}
	e.tx(func(c *store.TenantTx) error { return c.SetCatalogPopulations(item, []string{"visitor"}) })
	if _, err := e.submit(by, guest, item); err != nil {
		t.Fatalf("an item for visitors: %v", err)
	}
}

func TestRequest_GuestApprovalGoesToSponsorFirst(t *testing.T) {
	e := newEnv(t, fake.Options{})
	guest, item, by := e.guestWithItem("low", []string{"visitor"})
	lines, err := e.submit(by, guest, item)
	if err != nil || len(lines) != 1 {
		t.Fatal(lines, err)
	}
	id := lines[0].ID
	e.tx(func(c *store.TenantTx) error {
		st, err := c.RequestStages(id)
		if err != nil || len(st) != 2 || st[0].Kind != store.StageSponsor || st[1].Kind != store.StageOwner {
			t.Fatalf("stages = %+v, %v; want sponsor then owner", st, err)
		}
		if st[0].AssigneeID == nil || *st[0].AssigneeID != *e.carol.IdentityID || st[0].Status != store.StageWaiting {
			t.Errorf("sponsor stage = %+v", st[0])
		}
		return nil
	})
	bob := e.f.B.IDs["bob"]
	owner := e.actor("Bob", &bob, false)
	sponsor := e.actor("Carol", e.carol.IdentityID, false)
	approve := func(a requests.Actor) error {
		var aerr error
		e.tx(func(c *store.TenantTx) error { _, aerr = requests.Approve(c, id, a, "ok", now); return nil })
		return aerr
	}
	if err := approve(owner); code(err) != "not_an_approver" {
		t.Errorf("the owner before the sponsor: %v", err)
	}
	if err := approve(sponsor); err != nil {
		t.Fatalf("the sponsor: %v", err)
	}
	e.tx(func(c *store.TenantTx) error {
		l, err := c.RequestLine(id)
		if err != nil || l.Status != store.RequestPending {
			t.Errorf("after the sponsor alone: %+v, %v", l, err)
		}
		return nil
	})
	if err := approve(owner); err != nil {
		t.Fatalf("the owner after the sponsor: %v", err)
	}
	e.tx(func(c *store.TenantTx) error {
		l, err := c.RequestLine(id)
		if err != nil || l.Status != store.RequestApproved {
			t.Errorf("after both: %+v, %v", l, err)
		}
		return nil
	})
}
