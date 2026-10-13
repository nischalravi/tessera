package merge_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/correlation"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/access"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/sponsorship"
	"github.com/nischalravi/tessera/mvp/server/internal/identity"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/affiliations"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/match"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/merge"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/fake"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

var now = storetest.Now

// env is tenant B of the two-tenant fixture with the identity data model
// backfilled (every person is an employee with an HR record and identifiers),
// a sponsor (carol), two reviewers, and a catalog group a bundle can name.
type env struct {
	t      *testing.T
	f      *storetest.Fixture
	svc    *sponsorship.Service
	keyer  interface{}
	carol  sponsorship.Actor
	r1, r2 merge.Actor
	bob    int64
	alice  int64
	system string
	conn   string
	g1     int64
	clock  time.Time
	fake   *fake.Server
	eng    *provision.Engine
	sealer *seal.Sealer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	f := storetest.TwoTenants(t)
	k := storetest.IdentityKeyer(t)
	e := &env{t: t, f: f, svc: sponsorship.New(k), bob: f.B.IDs["bob"], alice: f.B.IDs["alice"], conn: f.B.Refs["connection:ad"], clock: now}
	e.svc.Matcher = match.New(k)
	carol := f.B.IDs["carol"]
	e.carol = sponsorship.Actor{UserID: uuid.New(), Display: "Carol", IdentityID: &carol}
	e.tx(func(c *store.TenantTx) error {
		if _, err := identity.Backfill(c, k, now); err != nil {
			return err
		}
		for i, r := range []*merge.Actor{&e.r1, &e.r2} {
			u := &store.PlatformUser{DisplayName: []string{"Reviewer One", "Reviewer Two"}[i], CreatedAt: now}
			if err := c.InsertPlatformUser(u); err != nil {
				return err
			}
			*r = merge.Actor{UserID: u.ID.String(), Display: u.DisplayName}
		}
		cn, err := c.Connection(e.conn)
		if err != nil {
			return err
		}
		e.system = cn.System
		if err := c.UpsertGroup(&store.Group{TenantID: c.Tenant(), System: e.system, ExternalID: "bundle-g", Name: "bundle-g"}); err != nil {
			return err
		}
		g, err := c.GroupByXID(e.system, "bundle-g")
		if err != nil {
			return err
		}
		e.g1 = g.ID
		return c.PutCatalogItem(&store.CatalogItem{ID: uuid.NewString(), GroupID: g.ID, Requestable: true, Risk: "low",
			EligibleTypes: []string{"human"}, UpdatedAt: now})
	})
	return e
}

func (e *env) tx(fn func(c *store.TenantTx) error) {
	e.t.Helper()
	if err := e.f.DB.InTenant(context.Background(), e.f.B.ID, fn); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) try(fn func(c *store.TenantTx) error) error {
	return e.f.DB.InTenant(context.Background(), e.f.B.ID, fn)
}

// invite makes an invitation by carol and returns the sponsorship.
func (e *env) invite(email string, groups ...int64) *store.Sponsorship {
	e.t.Helper()
	var ss *store.Sponsorship
	e.tx(func(c *store.TenantTx) error {
		r, err := e.svc.Invite(c, e.carol, sponsorship.Invite{GivenName: "Gwen", FamilyName: "Guest", Email: email, Population: "visitor",
			Purpose: "talk", EndsAt: now.AddDate(0, 0, 10), Bundle: groups}, store.ChannelSponsorInvite, "", now)
		if r != nil {
			ss = r.Sponsorship
		}
		return err
	})
	return ss
}

// claim does what a completed claim does to the person.
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

func (e *env) identity(id int64) (i *store.Identity) {
	e.t.Helper()
	e.tx(func(c *store.TenantTx) (err error) { i, err = c.Identity(id); return })
	return i
}

// edge is the membership edge of group on any account of person, nil when there is none.
func (e *env) edge(person, group int64, system string) (ed *store.GrantEdge) {
	e.t.Helper()
	e.tx(func(c *store.TenantTx) error {
		accts, err := c.IdentityAccounts(person)
		if err != nil {
			return err
		}
		for _, a := range accts {
			if a.System != system {
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

func (e *env) refEdge(person int64, key string) (ed *store.GrantEdge) {
	e.t.Helper()
	e.tx(func(c *store.TenantTx) error {
		g, err := c.GroupByXID(access.RefSystem, key)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		} else if err != nil {
			return err
		}
		accts, err := c.IdentityAccounts(person)
		if err != nil {
			return err
		}
		for _, a := range accts {
			if x, err := c.EdgeBetween(graph.Key("account", a.ID), graph.Key("group", g.ID)); err == nil {
				ed = x
			}
		}
		return nil
	})
	return ed
}

func (e *env) items(sp string) (out []*store.BundleItem) {
	e.t.Helper()
	e.tx(func(c *store.TenantTx) (err error) {
		out, err = c.BundleItems(store.BundleItemFilter{Sponsorship: sp})
		return
	})
	return out
}

// signInLink merges as a claimant who proved the existing person's credential.
func (e *env) signInLink(guest, person int64) *merge.Outcome {
	e.t.Helper()
	var out *merge.Outcome
	e.tx(func(c *store.TenantTx) (err error) {
		out, err = merge.Request(c, merge.Input{MergedID: guest, SurvivorID: person, Reason: "link by sign-in", Basis: merge.BasisSignIn}, e.r1, now)
		return
	})
	return out
}

func code(err error) string {
	var ce *correlation.Error
	if errors.As(err, &ce) {
		return ce.Code
	}
	if err == nil {
		return ""
	}
	return "other: " + err.Error()
}

// ---------------------------------------------------------------- memberships

// A merge moves the memberships with the accounts and brings the
// Tessera-managed ones up to date through the access code (GU-12): the bundle
// items now belong to the survivor, a bundle that was waiting for the guest is
// granted to the survivor, and the reference groups follow the affiliations the
// survivor now has. (The groups engine, GR-1/GR-2, is not built; this is the
// deviation the PR notes.)
func TestMerge_MovesMembershipsThroughEngine(t *testing.T) {
	t.Run("granted bundle and reference groups follow the person", func(t *testing.T) {
		e := newEnv(t)
		ss := e.invite("gwen@guest.example", e.g1)
		guest := ss.GuestIdentityID
		e.claim(guest)
		if e.edge(guest, e.g1, e.system) == nil || e.refEdge(guest, access.RefGuestVisitor) == nil {
			t.Fatal("setup: the claimed guest has no bundle membership or reference membership")
		}
		out := e.signInLink(guest, e.bob)
		if out.Merge == nil {
			t.Fatalf("outcome %+v", out)
		}
		its := e.items(ss.ID)
		if len(its) != 1 || its[0].GuestID != e.bob || its[0].Status != store.BundleGranted {
			t.Fatalf("bundle items after the merge: %+v", its)
		}
		ed := e.edge(e.bob, e.g1, e.system)
		if ed == nil || ed.Source != store.EdgeSourceGuest || ed.ExpiresAt == nil || !ed.ExpiresAt.Equal(ss.EndsAt) {
			t.Errorf("the bundle membership is not the survivor's, with its expiry: %+v", ed)
		}
		if e.refEdge(e.bob, access.RefGuestVisitor) == nil || e.refEdge(e.bob, access.RefGuestActive) == nil {
			t.Error("the survivor did not get the reference groups of the affiliation that moved to them")
		}
		if e.refEdge(guest, access.RefGuestVisitor) != nil || e.edge(guest, e.g1, e.system) != nil {
			t.Error("the merged person still holds memberships")
		}
		if i := e.identity(guest); i.Status != store.IdentityStatusMerged {
			t.Errorf("the merged person is %s", i.Status)
		}
	})
	t.Run("a waiting bundle is granted to the survivor, directly with write-back off", func(t *testing.T) {
		e := newEnv(t)
		ss := e.invite("gwen@guest.example", e.g1)
		if e.signInLink(ss.GuestIdentityID, e.bob).Merge == nil {
			t.Fatal("not merged")
		}
		it := e.items(ss.ID)[0]
		if it.GuestID != e.bob || it.Status != store.BundleGranted || e.edge(e.bob, e.g1, e.system) == nil {
			t.Fatalf("item %+v, edge %+v", it, e.edge(e.bob, e.g1, e.system))
		}
	})
	t.Run("with write-back on it is a provisioning operation and the edge waits for the target", func(t *testing.T) {
		e := newEnv(t)
		e.writeBack()
		ss := e.invite("gwen@guest.example", e.g1)
		if e.signInLink(ss.GuestIdentityID, e.bob).Merge == nil {
			t.Fatal("not merged")
		}
		it := e.items(ss.ID)[0]
		if it.GuestID != e.bob || it.Status != store.BundlePending || it.GrantOpID == nil {
			t.Fatalf("item after the merge: %+v", it)
		}
		if e.edge(e.bob, e.g1, e.system) != nil {
			t.Fatal("an edge before the target confirmed")
		}
		e.run()
		if it = e.items(ss.ID)[0]; it.Status != store.BundleGranted || e.edge(e.bob, e.g1, e.system) == nil {
			t.Fatalf("after the target confirmed: %+v", it)
		}
	})
}

// writeBack turns on provisioning for the connection with a fake SCIM target.
func (e *env) writeBack() {
	e.t.Helper()
	e.fake = fake.New(fake.Options{Token: "tok"})
	srv := httptest.NewServer(e.fake.Handler())
	e.t.Cleanup(srv.Close)
	hc, err := safehttp.New(safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		e.t.Fatal(err)
	}
	if e.sealer, err = seal.New(seal.RandomBytes(seal.KeySize)); err != nil {
		e.t.Fatal(err)
	}
	e.eng = &provision.Engine{DB: e.f.DB, Sealer: e.sealer, HTTP: hc, Clock: func() time.Time { return now },
		MaxAttempts: 2, MaxVerifies: 2, Backoff: func(int) time.Duration { return 0 }}
	e.fake.AddGroup("bundle-g", "bundle-g")
	id := store.NewID()
	enc, err := provision.SealToken(e.sealer, e.f.B.ID, id, "tok")
	if err != nil {
		e.t.Fatal(err)
	}
	e.tx(func(c *store.TenantTx) error {
		return c.UpsertProvTarget(&store.ProvTarget{ID: id, ConnectionID: e.conn, Kind: provision.KindSCIM, BaseURL: srv.URL + "/scim/v2",
			Settings: "{}", CredentialEnc: enc, WriteBack: true, CreatedBy: "admin"}, now)
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

// ---------------------------------------------------------------- credentials

// Credentials never transfer: the merged person's users stop signing in and
// their sessions end, the survivor's users and sessions are untouched, a user
// with a role blocks the merge, and both contact channels are told.
func TestMerge_CredentialsNotTransferred(t *testing.T) {
	t.Setenv("TESSERA_ENV", "test") // authtest creates sessions only then
	e := newEnv(t)
	ss := e.invite("gwen@guest.example")
	guest := ss.GuestIdentityID
	e.claim(guest)
	gl := authtest.LoginAs(t, e.f.DB, e.f.B.ID, authtest.User{Email: "gwen@guest.example", Display: "Gwen", IdentityID: &guest}, authtest.Phr, now)
	bob := e.bob
	bl := authtest.LoginAs(t, e.f.DB, e.f.B.ID, authtest.User{Email: "bob@b.example", Display: "Bob", Roles: []auth.Role{auth.RoleViewer}, IdentityID: &bob}, authtest.Phr, now)

	// a guest who holds a role cannot be merged away: the roles come off first
	gadmin := authtest.LoginAs(t, e.f.DB, e.f.B.ID, authtest.User{Email: "g2@guest.example", Display: "G2", Roles: []auth.Role{auth.RoleViewer}, IdentityID: &guest}, authtest.Phr, now)
	err := e.try(func(c *store.TenantTx) error {
		_, err := merge.Request(c, merge.Input{MergedID: guest, SurvivorID: e.bob, Reason: "same", Basis: merge.BasisSignIn}, e.r1, now)
		return err
	})
	if code(err) != "merged_identity_signs_in" {
		t.Fatalf("a user with a role: %v", err)
	}
	if i := e.identity(guest); i.Status == store.IdentityStatusMerged {
		t.Fatal("the refused merge happened")
	}
	e.tx(func(c *store.TenantTx) error {
		rs, _ := c.RoleAssignments(gadmin.UserID)
		for _, r := range rs {
			if err := c.DeleteRoleAssignment(r.ID); err != nil {
				return err
			}
		}
		return nil
	})

	before := usersOf(t, e, e.bob)
	e.signInLink(guest, e.bob)

	e.tx(func(c *store.TenantTx) error {
		for _, l := range []authtest.Login{gl, gadmin} {
			u, err := c.PlatformUser(l.UserID)
			if err != nil || u.Status != "disabled" {
				t.Errorf("the merged person's user after the merge: %+v, %v", u, err)
			}
			s, err := c.Session(l.SessionID)
			if err != nil || s.RevokedAt == nil {
				t.Errorf("the merged person's session after the merge: %+v, %v", s, err)
			}
		}
		u, err := c.PlatformUser(bl.UserID)
		if err != nil || u.Status != "active" {
			t.Errorf("the survivor's user: %+v, %v", u, err)
		}
		s, err := c.Session(bl.SessionID)
		if err != nil || s.RevokedAt != nil {
			t.Errorf("the survivor's session: %+v, %v", s, err)
		}
		// nothing was re-pointed: the guest's users still name the guest, the survivor's still name the survivor
		for _, l := range []authtest.Login{gl, gadmin} {
			if u, _ := c.PlatformUser(l.UserID); u.IdentityID == nil || *u.IdentityID != guest {
				t.Errorf("the merged person's user was re-pointed: %+v", u)
			}
		}
		return nil
	})
	if after := usersOf(t, e, e.bob); !slices.Equal(before, after) {
		t.Errorf("the survivor's sign-in users changed: %v -> %v", before, after)
	}
	// both contact channels were told: the survivor's user (bell) and the guest's address
	e.tx(func(c *store.TenantTx) error {
		mine, err := c.Notifications(bl.UserID.String(), false, 100)
		if err != nil {
			return err
		}
		due, err := c.DueNotifications(now.Add(time.Hour), 100)
		if err != nil {
			return err
		}
		var toBob, toGuest int
		for _, n := range append(mine, due...) {
			if n.Kind != "security.alert" || !strings.Contains(n.DedupeKey, "identity.combined:") {
				continue
			}
			if n.UserID != nil && *n.UserID == bl.UserID.String() {
				toBob++
			}
			if n.Email != nil && *n.Email == "gwen@guest.example" {
				toGuest++
			}
			if strings.Contains(n.Body, "Gwen") || strings.Contains(n.Body, "Bob") {
				t.Errorf("a notification names the other person: %q", n.Body)
			}
		}
		if toBob == 0 || toGuest == 0 {
			t.Errorf("notified the survivor %d times and the merged person's address %d times", toBob, toGuest)
		}
		return nil
	})
	if !strings.Contains(actions(t, e), "identity.merge") {
		t.Error("no ledger entry")
	}
}

func usersOf(t *testing.T, e *env, id int64) (out []string) {
	t.Helper()
	e.tx(func(c *store.TenantTx) (err error) { out, err = c.UsersLinkedTo(id); return })
	slices.Sort(out)
	return out
}

func actions(t *testing.T, e *env) string {
	t.Helper()
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

// ---------------------------------------------------------------- unmerge

func TestUnmerge_RestoresMoves(t *testing.T) {
	e := newEnv(t)
	ss := e.invite("gwen@guest.example", e.g1)
	guest := ss.GuestIdentityID
	e.claim(guest)
	var before struct{ srcs, ids, affs int }
	e.tx(func(c *store.TenantTx) error {
		s, _ := c.SourceRecordsFor(guest)
		i, _ := c.IdentifiersFor(guest)
		a, _ := c.AffiliationsFor(guest)
		before.srcs, before.ids, before.affs = len(s), len(i), len(a)
		return nil
	})
	if before.srcs == 0 || before.ids == 0 || before.affs == 0 {
		t.Fatalf("setup: %+v", before)
	}
	m := e.signInLink(guest, e.bob).Merge

	// the moves are recorded, one per row, with the guest tables among them
	tables := map[string]int{}
	for _, mv := range m.Moves {
		tables[mv.Table+"."+mv.Column]++
	}
	for _, want := range []string{"identity_source_records.identity_id", "identity_identifiers.identity_id", "affiliations.identity_id",
		"sponsorships.guest_identity_id", "guest_bundle_items.guest_identity_id", "accounts.identity_id"} {
		if tables[want] == 0 {
			t.Errorf("no recorded move for %s: %v", want, tables)
		}
	}
	// something new arrives for the survivor after the merge: it stays with them and is listed
	var newAff string
	e.tx(func(c *store.TenantTx) error {
		a, err := affiliations.Add(c, affiliations.AddInput{IdentityID: e.bob, Type: store.AffVolunteer, Reason: "after the merge",
			EndsAt: ptrTime(now.AddDate(0, 0, 30)), By: e.r1.UserID}, now.Add(time.Hour))
		if err == nil {
			newAff = a.ID
		}
		return err
	})
	// and one moved row changed since: it is kept, and reported
	var res *merge.Unmerged
	e.tx(func(c *store.TenantTx) (err error) {
		res, err = merge.Unmerge(c, m.ID, "wrong person", e.r2, now.Add(2*time.Hour))
		return
	})
	if len(res.Kept) != 0 || len(res.Restored) != len(m.Moves) {
		t.Errorf("restored %d of %d moves, kept %v", len(res.Restored), len(m.Moves), res.Kept)
	}
	if !slices.ContainsFunc(res.CreatedAfter, func(l merge.Later) bool { return l.Table == "affiliations" && l.ID == newAff }) {
		t.Errorf("the survivor's new affiliation is not listed: %+v", res.CreatedAfter)
	}
	e.tx(func(c *store.TenantTx) error {
		s, _ := c.SourceRecordsFor(guest)
		i, _ := c.IdentifiersFor(guest)
		a, _ := c.AffiliationsFor(guest)
		if len(s) != before.srcs || len(i) != before.ids || len(a) != before.affs {
			t.Errorf("after the unmerge the guest has %d source records, %d identifiers, %d affiliations (was %+v)", len(s), len(i), len(a), before)
		}
		sp, _ := c.Sponsorships(store.SponsorshipFilter{Guest: guest})
		if len(sp) != 1 || sp[0].ID != ss.ID {
			t.Errorf("the sponsorship did not come back: %v", sp)
		}
		bi, _ := c.BundleItems(store.BundleItemFilter{Guest: guest})
		if len(bi) != 1 {
			t.Errorf("the bundle item did not come back: %v", bi)
		}
		mine, _ := c.AffiliationsFor(e.bob)
		if !slices.ContainsFunc(mine, func(x *store.Affiliation) bool { return x.ID == newAff }) {
			t.Error("the survivor lost the affiliation created after the merge")
		}
		return nil
	})
	if i := e.identity(guest); i.Status != "active" {
		t.Errorf("the unmerged guest is %s", i.Status)
	}
	// the reference groups follow again
	if e.refEdge(guest, access.RefGuestVisitor) == nil {
		t.Error("the guest's reference membership did not come back")
	}
	if e.refEdge(e.bob, access.RefGuestVisitor) != nil {
		t.Error("the survivor kept a guest reference membership they no longer qualify for")
	}
	if !strings.Contains(actions(t, e), "identity.unmerge") {
		t.Error("no ledger entry")
	}
}

func ptrTime(t time.Time) *time.Time { return &t }

// A merge can be undone for 180 days unless the tenant sets another window.
func TestUnmerge_WindowIsPerTenant(t *testing.T) {
	for _, tc := range []struct {
		days    int // 0: the default
		after   time.Duration
		allowed bool
	}{
		{0, 179 * 24 * time.Hour, true},
		{0, 181 * 24 * time.Hour, false},
		{30, 29 * 24 * time.Hour, true},
		{30, 31 * 24 * time.Hour, false},
		{400, 399 * 24 * time.Hour, true},
	} {
		e := newEnv(t)
		if tc.days != 0 {
			e.tx(func(c *store.TenantTx) error {
				return c.PutMatchingSettings(store.MatchingSettings{UnmergeWindowDays: tc.days}, e.r1.UserID, now)
			})
		}
		ss := e.invite("gwen@guest.example")
		m := e.signInLink(ss.GuestIdentityID, e.bob).Merge
		err := e.try(func(c *store.TenantTx) error {
			_, err := merge.Unmerge(c, m.ID, "x", e.r2, now.Add(tc.after))
			return err
		})
		if tc.allowed && err != nil || !tc.allowed && code(err) != "unmerge_window_passed" {
			t.Errorf("window %d days, %v later: %v", tc.days, tc.after, err)
		}
	}
}

// ---------------------------------------------------------------- four eyes

func TestFourEyes_WhoNeedsASecondReviewer(t *testing.T) {
	e := newEnv(t)
	g1 := e.invite("one@guest.example").GuestIdentityID
	g2 := e.invite("two@guest.example").GuestIdentityID
	e.claim(g1)
	e.claim(g2)
	assess := func(ids ...int64) (r merge.Risk) {
		e.tx(func(c *store.TenantTx) (err error) { r, err = merge.Assess(c, now, ids...); return })
		return r
	}
	if r := assess(g1, g2); len(r) != 0 {
		t.Errorf("two guests: %v", r)
	}
	if r := assess(g1, e.bob); !slices.Contains(r, merge.RiskEmployee) || !slices.Contains(r, merge.RiskIAL2) {
		t.Errorf("a guest and an employee: %v", r)
	}
	// IAL 2 recorded for a guest
	e.tx(func(c *store.TenantTx) error {
		return c.PutIdentityAssurance(&store.Assurance{IdentityID: g2, IAL: 2, AAL: 2, Source: "idv", RecordedAt: now})
	})
	if r := assess(g1, g2); !slices.Equal(r, merge.Risk{merge.RiskIAL2}) {
		t.Errorf("a guest at IAL 2: %v", r)
	}
	// privileged access: a guest in a privileged group
	g3 := e.invite("three@guest.example").GuestIdentityID
	e.claim(g3)
	if r := assess(g1, g3); len(r) != 0 {
		t.Errorf("setup: %v", r)
	}
	e.tx(func(c *store.TenantTx) error {
		if err := c.UpsertGroup(&store.Group{TenantID: c.Tenant(), System: e.system, ExternalID: "root-admins", Name: "root-admins", Privileged: true}); err != nil {
			return err
		}
		gp, err := c.GroupByXID(e.system, "root-admins")
		if err != nil {
			return err
		}
		ident, _ := c.Identity(g3)
		accts, _ := c.IdentityAccounts(g3)
		acct := (*store.Account)(nil)
		if len(accts) > 0 {
			acct = accts[0]
		} else if acct, err = ensureAcct(c, ident, e.system); err != nil {
			return err
		}
		_, err = c.InsertEdge(&store.GrantEdge{Src: graph.Key("account", acct.ID), Dst: graph.Key("group", gp.ID), Relation: "member_of",
			Source: "manual", CreatedAt: now})
		return err
	})
	if r := assess(g1, g3); !slices.Contains(r, merge.RiskPrivileged) {
		t.Errorf("a guest with privileged access: %v", r)
	}
}

func ensureAcct(c *store.TenantTx, p *store.Identity, system string) (*store.Account, error) {
	iid := p.ID
	id, err := c.InsertAccount(&store.Account{System: system, ExternalID: "x-" + p.ExternalID, IdentityID: &iid, Username: "x-" + p.ExternalID,
		Kind: "user", Status: "active", CreatedAt: &now})
	if err != nil {
		return nil, err
	}
	return c.Account(id)
}

func TestFourEyes_RequestApproveReject(t *testing.T) {
	e := newEnv(t)
	ss := e.invite("gwen@guest.example")
	guest := ss.GuestIdentityID
	var out *merge.Outcome
	e.tx(func(c *store.TenantTx) (err error) {
		out, err = merge.Request(c, merge.Input{MergedID: guest, SurvivorID: e.bob, Reason: "same person", Basis: merge.BasisReviewer}, e.r1, now)
		return
	})
	if out.Pending == nil || out.Merge != nil || len(out.Risk) == 0 {
		t.Fatalf("a merge into an employee did not wait: %+v", out)
	}
	if i := e.identity(guest); i.Status == store.IdentityStatusMerged {
		t.Fatal("applied before the second reviewer")
	}
	// the same person cannot ask twice, and the asker cannot approve
	err := e.try(func(c *store.TenantTx) error {
		_, err := merge.Request(c, merge.Input{MergedID: guest, SurvivorID: e.alice, Reason: "again", Basis: merge.BasisReviewer}, e.r2, now)
		return err
	})
	if code(err) != "request_pending" {
		t.Errorf("a second request: %v", err)
	}
	err = e.try(func(c *store.TenantTx) error { _, err := merge.Approve(c, out.Pending.ID, e.r1, now); return err })
	if code(err) != "second_reviewer_required" {
		t.Errorf("self-approval: %v", err)
	}
	// the table refuses it too, whatever the code says
	err = e.try(func(c *store.TenantTx) error {
		return c.DecideMergeRequest(out.Pending.ID, store.MergeReqApproved, e.r1.UserID, nil, nil, now)
	})
	if err == nil {
		t.Error("the schema accepted a self-approval")
	}
	if q := pending(t, e, out.Pending.ID); q.Status != store.MergeReqPending {
		t.Errorf("request after refused approvals: %s", q.Status)
	}
	// a different reviewer approves: the merge applies, with both on the record
	var ap *merge.Outcome
	e.tx(func(c *store.TenantTx) (err error) {
		ap, err = merge.Approve(c, out.Pending.ID, e.r2, now.Add(time.Minute))
		return
	})
	if ap.Merge == nil || ap.Merge.MergedBy != e.r1.UserID {
		t.Fatalf("approval: %+v", ap)
	}
	if q := pending(t, e, out.Pending.ID); q.Status != store.MergeReqApproved || q.DecidedBy == nil || *q.DecidedBy != e.r2.UserID || q.MergeID == nil || *q.MergeID != ap.Merge.ID {
		t.Errorf("request after approval: %+v", q)
	}
	if i := e.identity(guest); i.Status != store.IdentityStatusMerged {
		t.Error("not merged after approval")
	}
	err = e.try(func(c *store.TenantTx) error { _, err := merge.Approve(c, out.Pending.ID, e.r2, now); return err })
	if code(err) != "request_decided" {
		t.Errorf("approving twice: %v", err)
	}
	// rejecting, and the requester withdrawing
	for _, tc := range []struct {
		by   merge.Actor
		want string
	}{{e.r2, store.MergeReqRejected}, {e.r1, store.MergeReqCancelled}} {
		g := e.invite(tc.want + "@guest.example").GuestIdentityID
		var q *store.MergeRequest
		e.tx(func(c *store.TenantTx) error {
			o, err := merge.Request(c, merge.Input{MergedID: g, SurvivorID: e.alice, Reason: "x", Basis: merge.BasisReviewer}, e.r1, now)
			q = o.Pending
			return err
		})
		e.tx(func(c *store.TenantTx) error {
			if _, err := merge.Reject(c, q.ID, tc.by, "", now); code(err) != "reason_required" {
				t.Errorf("reject without a reason: %v", err)
			}
			r, err := merge.Reject(c, q.ID, tc.by, "not the same person", now)
			if err != nil || r.Status != tc.want {
				t.Errorf("reject by %s: %+v, %v", tc.by.Display, r, err)
			}
			return nil
		})
		if i := e.identity(g); i.Status == store.IdentityStatusMerged {
			t.Error("a rejected request merged")
		}
	}
	// and two guests with nothing risky merge at once
	a, b := e.invite("a@guest.example").GuestIdentityID, e.invite("b@guest.example").GuestIdentityID
	e.tx(func(c *store.TenantTx) error {
		o, err := merge.Request(c, merge.Input{MergedID: a, SurvivorID: b, Reason: "duplicate invitation", Basis: merge.BasisReviewer}, e.r1, now)
		if err != nil || o.Merge == nil {
			t.Errorf("two guests: %+v, %v", o, err)
		}
		return nil
	})
}

func pending(t *testing.T, e *env, id string) (q *store.MergeRequest) {
	t.Helper()
	e.tx(func(c *store.TenantTx) (err error) { q, err = c.MergeRequest(id); return })
	return q
}

// ---------------------------------------------------------------- review decisions

// a suspected match of a self-asserted invitation to an employee
func (e *env) suspected() (*store.Sponsorship, *store.MatchResult) {
	e.t.Helper()
	var email string
	e.tx(func(c *store.TenantTx) error {
		i, err := c.Identity(e.bob)
		email = strings.ToLower(*i.Email)
		return err
	})
	ss := e.invite(email)
	var row *store.MatchResult
	e.tx(func(c *store.TenantTx) error {
		rs, err := c.MatchResults(store.MatchFilter{Intake: ss.IntakeID})
		for _, r := range rs {
			if r.CandidateID != nil && *r.CandidateID == e.bob {
				row = r
			}
		}
		return err
	})
	if row == nil || row.Status != store.MatchReview {
		e.t.Fatalf("the invitation to an employee's address was not flagged: %+v", row)
	}
	return ss, row
}

// A reviewer's link into an employee needs a second reviewer and then the
// claimant's re-verification at the employee's IAL: until the claimant signs in as
// the employee nothing is linked and no access is granted (§5.5.3).
func TestMatchLink_RequiresReverification(t *testing.T) {
	e := newEnv(t)
	ss, row := e.suspected()
	guest := ss.GuestIdentityID
	var d *merge.Decided
	e.tx(func(c *store.TenantTx) (err error) {
		d, err = merge.Decide(c, row.ID, merge.DecisionLink, "same person", e.r1, merge.Hooks{}, now)
		return
	})
	if d.Outcome.Pending == nil {
		t.Fatalf("a link into an employee did not wait for a second reviewer: %+v", d.Outcome)
	}
	e.tx(func(c *store.TenantTx) (err error) {
		d.Outcome, err = merge.Approve(c, d.Outcome.Pending.ID, e.r2, now)
		return
	})
	if !d.Outcome.Reverification || d.Outcome.Merge != nil {
		t.Fatalf("approval: %+v", d.Outcome)
	}
	e.tx(func(c *store.TenantTx) error {
		r, _ := c.MatchResult(row.ID)
		if r.Status != store.MatchReverification || r.Decision == nil || *r.Decision != "link" || r.DecidedBy == nil || *r.DecidedBy != e.r1.UserID ||
			r.SecondReviewer == nil || *r.SecondReviewer != e.r2.UserID {
			t.Errorf("result = %+v", r)
		}
		return nil
	})
	if i := e.identity(guest); i.Status == store.IdentityStatusMerged {
		t.Fatal("linked without re-verification")
	}
	if !strings.Contains(actions(t, e), "identity.match.reverification_required") {
		t.Error("reverification_required is not in the ledger")
	}
	// the claimant proves it by signing in as the employee
	var ok bool
	e.tx(func(c *store.TenantTx) (err error) {
		ok, _, err = merge.LinkBySignIn(c, ss.IntakeID, e.bob, e.r1, now)
		return
	})
	if !ok {
		t.Fatal("link by sign-in refused")
	}
	if i := e.identity(guest); i.Status != store.IdentityStatusMerged {
		t.Error("not linked after the sign-in")
	}
	e.tx(func(c *store.TenantTx) error {
		rs, _ := c.MatchResults(store.MatchFilter{Intake: ss.IntakeID})
		linked := 0
		for _, r := range rs {
			if r.Status == store.MatchLinked {
				linked++
			}
			if r.Status == store.MatchReview || r.Status == store.MatchReverification {
				t.Errorf("a result is still open: %+v", r)
			}
		}
		if linked != 1 {
			t.Errorf("%d linked results", linked)
		}
		return nil
	})
}

// A candidate nobody vetted (no IAL, not an employee, no privilege) is linked by
// one reviewer, at once: there is nothing to re-verify and nobody to ask.
func TestMatchLink_NoRiskNoReverification(t *testing.T) {
	e := newEnv(t)
	const email = "dana@guest.example"
	var dana int64
	e.tx(func(c *store.TenantTx) error {
		src := "manual"
		id, err := c.InsertIdentity(&store.Identity{TenantID: c.Tenant(), ExternalID: "dana", Name: "Dana Directory", Type: "human", Status: "active",
			Source: &src, CreatedAt: now})
		if err != nil {
			return err
		}
		dana = id
		norm, mac, err := storetest.IdentityKeyer(t).Digest(c.Tenant(), store.IdentEmail, "", email)
		if err != nil {
			return err
		}
		by, at := store.VerifiedByCode, now
		return c.InsertIdentifier(&store.Identifier{ID: uuid.NewString(), IdentityID: dana, Type: store.IdentEmail, ValueNorm: norm, ValueHMAC: mac,
			VerifiedAt: &at, VerifiedBy: &by, Status: store.RecordActive, CreatedAt: now})
	})
	ss := e.invite(email, e.g1)
	var row *store.MatchResult
	e.tx(func(c *store.TenantTx) error {
		rs, err := c.MatchResults(store.MatchFilter{Intake: ss.IntakeID})
		for _, r := range rs {
			if r.CandidateID != nil && *r.CandidateID == dana {
				row = r
			}
		}
		return err
	})
	if row == nil || row.Tier != "C" {
		t.Fatalf("not flagged: %+v", row)
	}
	var d *merge.Decided
	e.tx(func(c *store.TenantTx) (err error) {
		d, err = merge.Decide(c, row.ID, merge.DecisionLink, "same person, confirmed by phone", e.r1, merge.Hooks{}, now)
		return
	})
	if d.Outcome.Merge == nil || d.Match.Status != store.MatchLinked || d.Match.SecondReviewer != nil {
		t.Fatalf("link: %+v / %+v", d.Outcome, d.Match)
	}
	e.tx(func(c *store.TenantTx) error {
		sp, _ := c.Sponsorships(store.SponsorshipFilter{Guest: dana})
		if len(sp) != 1 || sp[0].ID != ss.ID {
			t.Errorf("the sponsorship did not follow the link: %v", sp)
		}
		in, _ := c.Intake(ss.IntakeID)
		if in.InvitationStatus != store.InvitationClaimed || in.Status != store.IntakeResolved {
			t.Errorf("intake %+v", in)
		}
		a, _ := affiliations.ForSponsorship(c, dana, ss.ID)
		if a == nil || a.Status != store.AffActive {
			t.Errorf("the visitor affiliation: %+v", a)
		}
		return nil
	})
	if it := e.items(ss.ID)[0]; it.GuestID != dana || it.Status != store.BundleGranted {
		t.Errorf("bundle item %+v", it)
	}
}

func TestDecide_NewPersonAndReject(t *testing.T) {
	e := newEnv(t)
	ss, row := e.suspected()
	var rejected string
	hooks := merge.Hooks{RejectIntake: func(c *store.TenantTx, intake string, subject *int64, reason string, at time.Time) error {
		rejected = intake + "/" + reason
		return nil
	}}
	// a reason is required, an unknown decision refused
	err := e.try(func(c *store.TenantTx) error {
		_, err := merge.Decide(c, row.ID, "new_person", " ", e.r1, hooks, now)
		return err
	})
	if code(err) != "reason_required" {
		t.Errorf("no reason: %v", err)
	}
	err = e.try(func(c *store.TenantTx) error {
		_, err := merge.Decide(c, row.ID, "shrug", "x", e.r1, hooks, now)
		return err
	})
	if code(err) != "invalid_decision" {
		t.Errorf("bad decision: %v", err)
	}
	e.tx(func(c *store.TenantTx) error {
		d, err := merge.Decide(c, row.ID, merge.DecisionNewPerson, "a different Bob", e.r1, hooks, now)
		if err != nil || d.Match.Status != store.MatchNewPerson {
			t.Fatalf("new person: %+v, %v", d, err)
		}
		in, _ := c.Intake(ss.IntakeID)
		if in.Status != store.IntakeResolved {
			t.Errorf("intake %s", in.Status)
		}
		return nil
	})
	if i := e.identity(ss.GuestIdentityID); i.Status == store.IdentityStatusMerged {
		t.Error("new person merged")
	}
	err = e.try(func(c *store.TenantTx) error {
		_, err := merge.Decide(c, row.ID, "reject", "x", e.r1, hooks, now)
		return err
	})
	if code(err) != "already_decided" {
		t.Errorf("deciding twice: %v", err)
	}
	// reject on a fresh intake
	ss2, row2 := e.suspected()
	e.tx(func(c *store.TenantTx) error {
		d, err := merge.Decide(c, row2.ID, merge.DecisionReject, "looks like fraud", e.r1, hooks, now)
		if err != nil || d.Match.Status != store.MatchRejected {
			t.Fatalf("reject: %+v, %v", d, err)
		}
		in, _ := c.Intake(ss2.IntakeID)
		if in.Status != store.IntakeRejected {
			t.Errorf("intake %s", in.Status)
		}
		return nil
	})
	if rejected != ss2.IntakeID+"/looks like fraud" {
		t.Errorf("the reject hook got %q", rejected)
	}
}

func TestLinkBySignIn_OnlyACandidate(t *testing.T) {
	e := newEnv(t)
	ss, _ := e.suspected()
	e.tx(func(c *store.TenantTx) error {
		for _, who := range []int64{e.alice, 0, 999999} {
			ok, m, err := merge.LinkBySignIn(c, ss.IntakeID, who, e.r1, now)
			if err != nil || ok || m != nil {
				t.Errorf("link as %d: %v %v %v", who, ok, m, err)
			}
		}
		return nil
	})
	if i := e.identity(ss.GuestIdentityID); i.Status == store.IdentityStatusMerged {
		t.Error("linked to a non-candidate")
	}
}

// A merge never gives a person their own sponsor as a guest.
func TestMerge_SponsorConflictRefused(t *testing.T) {
	e := newEnv(t)
	ss := e.invite("gwen@guest.example")
	carol := e.f.B.IDs["carol"]
	err := e.try(func(c *store.TenantTx) error {
		_, err := merge.Request(c, merge.Input{MergedID: ss.GuestIdentityID, SurvivorID: carol, Reason: "x", Basis: merge.BasisSignIn}, e.r1, now)
		return err
	})
	if code(err) != "sponsorship_conflict" {
		t.Errorf("merging a guest into their sponsor: %v", err)
	}
}
