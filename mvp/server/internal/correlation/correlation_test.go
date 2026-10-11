package correlation_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/correlation"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// The fixture is the tiny world (connectors.Tiny) in tenant B, which has no
// sentinel: alice and bob report to carol, dave (terminated) owns svc-etl,
// and okta:<name> accounts link to each person.

type world struct {
	t     *testing.T
	f     *storetest.Fixture
	ids   map[string]int64
	actor string
}

func newWorld(t *testing.T) *world {
	t.Helper()
	f := storetest.TwoTenants(t)
	w := &world{t: t, f: f, ids: f.B.IDs}
	w.tx(func(c *store.TenantTx) error {
		u := &store.PlatformUser{DisplayName: "Reviewer", CreatedAt: storetest.Now}
		if err := c.InsertPlatformUser(u); err != nil {
			return err
		}
		w.actor = u.ID.String()
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

// sync re-runs connector discovery, as a scheduled sync would.
func (w *world) sync() {
	w.t.Helper()
	w.tx(func(c *store.TenantTx) error {
		_, err := ingest.Sync(c, storetest.Now, []connectors.Connector{connectors.Tiny{Now: storetest.Now}}, nil)
		return err
	})
}

func (w *world) accountIdentity(key string) *int64 {
	w.t.Helper()
	var id *int64
	w.tx(func(c *store.TenantTx) error {
		a, err := c.Account(w.ids[key])
		if err == nil {
			id = a.IdentityID
		}
		return err
	})
	return id
}

func (w *world) identity(name string) *store.Identity {
	w.t.Helper()
	var i *store.Identity
	w.tx(func(c *store.TenantTx) (err error) { i, err = c.Identity(w.ids[name]); return })
	return i
}

func is(p *int64, v int64) bool { return p != nil && *p == v }

func code(err error) string {
	var e *correlation.Error
	if errors.As(err, &e) {
		return e.Code
	}
	if err != nil {
		return "error: " + err.Error()
	}
	return ""
}

func TestLink_SurvivesResync(t *testing.T) {
	w := newWorld(t)
	// dave-iam is really carol's (the connector says dave's)
	w.tx(func(c *store.TenantTx) error {
		d, err := correlation.Link(c, w.ids["acct:aws:dave-iam"], w.ids["carol"], "checked with the AWS team", w.actor, storetest.Now)
		if err != nil {
			return err
		}
		if !is(d.Previous, w.ids["dave"]) || !is(d.Link.PreviousIdentityID, w.ids["dave"]) {
			t.Errorf("previous = %v / %v", d.Previous, d.Link.PreviousIdentityID)
		}
		return nil
	})
	w.sync()
	if got := w.accountIdentity("acct:aws:dave-iam"); !is(got, w.ids["carol"]) {
		t.Fatalf("after re-sync the account belongs to %v, want carol", got)
	}
	// a second decision keeps the connector's original mapping for Release
	w.tx(func(c *store.TenantTx) error {
		_, err := correlation.MarkNotPerson(c, w.ids["acct:aws:dave-iam"], "shared break-glass login", w.actor, storetest.Now)
		return err
	})
	w.sync()
	if got := w.accountIdentity("acct:aws:dave-iam"); got != nil {
		t.Fatalf("not_person account after re-sync = %v, want none", *got)
	}
	w.tx(func(c *store.TenantTx) error {
		d, err := correlation.Release(c, w.ids["acct:aws:dave-iam"])
		if err != nil {
			return err
		}
		if !is(d.Account.IdentityID, w.ids["dave"]) {
			t.Errorf("released account = %v, want dave", d.Account.IdentityID)
		}
		_, err = correlation.Release(c, w.ids["acct:aws:dave-iam"])
		if code(err) != "no_decision" {
			t.Errorf("second release = %v", err)
		}
		return nil
	})
	w.sync()
	if got := w.accountIdentity("acct:aws:dave-iam"); !is(got, w.ids["dave"]) {
		t.Errorf("after release and re-sync = %v, want dave", got)
	}
}

func TestLink_Refusals(t *testing.T) {
	w := newWorld(t)
	w.tx(func(c *store.TenantTx) error {
		cases := []struct {
			acct, ident  int64
			reason, want string
		}{
			{w.ids["acct:okta:alice"], w.ids["bob"], " ", "reason_required"},
			{w.ids["acct:okta:alice"], w.ids["svc-etl"], "x", "type_mismatch"}, // a user account, a service identity
			{999999, w.ids["bob"], "x", "account_not_found"},
			{w.ids["acct:okta:alice"], 999999, "x", "identity_not_found"},
		}
		for _, tc := range cases {
			if _, err := correlation.Link(c, tc.acct, tc.ident, tc.reason, w.actor, storetest.Now); code(err) != tc.want {
				t.Errorf("Link(%d, %d) = %v, want %s", tc.acct, tc.ident, err, tc.want)
			}
		}
		return nil
	})
}

func TestQueue_ProposesNeverLinks(t *testing.T) {
	w := newWorld(t)
	var gh, corp, svc int64
	w.tx(func(c *store.TenantTx) error {
		for _, a := range []*store.Account{
			{System: "github", ExternalID: "1", Username: "ALICE@t.example", Kind: "user", Status: "active"},
			{System: "ad", ExternalID: "2", Username: `CORP\bob`, Kind: "user", Status: "active"},
			{System: "ad", ExternalID: "3", Username: "svc-backup", Kind: "service", Status: "active"},
		} {
			if err := c.UpsertAccount(a); err != nil {
				return err
			}
		}
		accts, err := c.Accounts()
		for _, a := range accts {
			switch a.System + a.ExternalID {
			case "github1":
				gh = a.ID
			case "ad2":
				corp = a.ID
			case "ad3":
				svc = a.ID
			}
		}
		return err
	})
	w.tx(func(c *store.TenantTx) error {
		q, err := correlation.Queue(c)
		if err != nil {
			return err
		}
		got := map[int64][]correlation.Candidate{}
		for _, it := range q {
			got[it.Account.ID] = it.Candidates
		}
		if _, ok := got[svc]; ok {
			t.Error("a service account is in the person queue")
		}
		if cs := got[gh]; len(cs) != 1 || cs[0].IdentityID != w.ids["alice"] || cs[0].Rule != "email" {
			t.Errorf("github candidates = %+v", cs)
		}
		if cs := got[corp]; len(cs) != 1 || cs[0].IdentityID != w.ids["bob"] || cs[0].Rule != "email_local_part" {
			t.Errorf(`CORP\bob candidates = %+v`, cs)
		}
		if len(q) != 2 {
			t.Errorf("queue has %d items, want 2", len(q))
		}
		// proposals are not links
		a, err := c.Account(gh)
		if err != nil || a.IdentityID != nil {
			t.Errorf("queued account linked: %v %v", a, err)
		}
		_, err = correlation.MarkNotPerson(c, gh, "a test account", w.actor, storetest.Now)
		return err
	})
	w.tx(func(c *store.TenantTx) error {
		q, err := correlation.Queue(c)
		if err == nil && len(q) != 1 {
			t.Errorf("after a decision the queue has %d items, want 1", len(q))
		}
		return err
	})
}

func TestMerge_MovesAndUnmergeRestores(t *testing.T) {
	w := newWorld(t)
	carol, alice, bob := w.ids["carol"], w.ids["alice"], w.ids["bob"]
	var m *store.IdentityMerge
	w.tx(func(c *store.TenantTx) error {
		// pin carol's okta account first: the pin moves with the merge
		if _, err := correlation.Link(c, w.ids["acct:okta:carol"], carol, "verified", w.actor, storetest.Now); err != nil {
			return err
		}
		var err error
		m, err = correlation.Merge(c, "m1", carol, alice, "same person, two HR records", w.actor, storetest.Now)
		return err
	})
	// carol's account and pin, and bob's and dave's manager, move; alice's own manager
	// (carol) does not, or alice would manage herself
	want := map[string]bool{"accounts:identity_id": true, "account_links:identity_id": true, "identities:manager_id": true}
	for _, mv := range m.Moves {
		if !want[mv.Table+":"+mv.Column] {
			t.Errorf("unexpected move %+v", mv)
		}
		if mv.Table == "identities" && mv.ID == alice {
			t.Error("the survivor's own manager was moved")
		}
	}
	if len(m.Moves) != 4 {
		t.Errorf("moves = %+v, want 4", m.Moves)
	}
	if i := w.identity("carol"); i.Status != store.IdentityStatusMerged {
		t.Errorf("carol status = %s", i.Status)
	}
	if !is(w.accountIdentity("acct:okta:carol"), alice) || !is(w.identity("bob").ManagerID, alice) {
		t.Error("merge did not move carol's account and bob's manager to alice")
	}
	// a re-sync keeps the merge: the connector still names carol
	w.sync()
	if i := w.identity("carol"); i.Status != store.IdentityStatusMerged {
		t.Errorf("after re-sync carol status = %s", i.Status)
	}
	if !is(w.accountIdentity("acct:okta:carol"), alice) || !is(w.identity("bob").ManagerID, alice) {
		t.Error("re-sync moved items back to the merged identity")
	}
	// merged identities cannot take part again
	w.tx(func(c *store.TenantTx) error {
		if _, err := correlation.Merge(c, "m2", carol, bob, "x", w.actor, storetest.Now); code(err) != "identity_merged" {
			t.Errorf("merge a merged identity = %v", err)
		}
		if _, err := correlation.Link(c, w.ids["acct:okta:bob"], carol, "x", w.actor, storetest.Now); code(err) != "identity_merged" {
			t.Errorf("link to a merged identity = %v", err)
		}
		// changed since the merge: bob now reports to dave; the unmerge leaves it
		return c.SetIdentityManager(bob, &[]int64{w.ids["dave"]}[0])
	})
	var res *correlation.UnmergeResult
	w.tx(func(c *store.TenantTx) (err error) {
		res, err = correlation.Unmerge(c, "m1", "wrong match", w.actor, storetest.Now.Add(time.Hour))
		return
	})
	if len(res.Restored) != 3 || len(res.Kept) != 1 || res.Kept[0].ID != bob {
		t.Errorf("restored %+v kept %+v", res.Restored, res.Kept)
	}
	if i := w.identity("carol"); i.Status != "active" {
		t.Errorf("unmerged carol status = %s", i.Status)
	}
	if !is(w.accountIdentity("acct:okta:carol"), carol) {
		t.Error("unmerge did not return carol's account")
	}
	w.tx(func(c *store.TenantTx) error {
		if l, err := c.AccountLink(w.ids["acct:okta:carol"]); err != nil || !is(l.IdentityID, carol) {
			t.Errorf("pin after unmerge = %+v, %v", l, err)
		}
		if _, err := correlation.Unmerge(c, "m1", "again", w.actor, storetest.Now); code(err) != "already_unmerged" {
			t.Errorf("second unmerge = %v", err)
		}
		return nil
	})
}

func TestMerge_Refusals(t *testing.T) {
	w := newWorld(t)
	w.tx(func(c *store.TenantTx) error {
		// dave signs in to Tessera: his credentials never move
		dave := w.ids["dave"]
		if err := c.InsertPlatformUser(&store.PlatformUser{DisplayName: "Dave", IdentityID: &dave, CreatedAt: storetest.Now}); err != nil {
			return err
		}
		cases := []struct {
			merged, survivor int64
			want             string
		}{
			{w.ids["alice"], w.ids["alice"], "same_identity"},
			{w.ids["svc-etl"], w.ids["alice"], "type_mismatch"},
			{dave, w.ids["carol"], "merged_identity_signs_in"},
			{999999, w.ids["alice"], "identity_not_found"},
			{w.ids["bob"], 999999, "survivor_not_found"},
		}
		for _, tc := range cases {
			if _, err := correlation.Merge(c, "x", tc.merged, tc.survivor, "reason", w.actor, storetest.Now); code(err) != tc.want {
				t.Errorf("Merge(%d → %d) = %v, want %s", tc.merged, tc.survivor, err, tc.want)
			}
		}
		// the other way round is allowed: dave's sign-in stays on the survivor
		_, err := correlation.Merge(c, "ok", w.ids["carol"], dave, "reason", w.actor, storetest.Now)
		return err
	})
}

func TestUnmerge_OrderAndWindow(t *testing.T) {
	w := newWorld(t)
	w.tx(func(c *store.TenantTx) error {
		if _, err := correlation.Merge(c, "a-b", w.ids["alice"], w.ids["bob"], "dup", w.actor, storetest.Now); err != nil {
			return err
		}
		if _, err := correlation.Merge(c, "b-c", w.ids["bob"], w.ids["carol"], "dup", w.actor, storetest.Now); err != nil {
			return err
		}
		surv, err := c.MergeSurvivors()
		if err != nil || surv[w.ids["alice"]] != w.ids["carol"] {
			t.Errorf("chain survivors = %v, %v", surv, err)
		}
		if _, err := correlation.Unmerge(c, "a-b", "x", w.actor, storetest.Now); code(err) != "survivor_merged" {
			t.Errorf("unmerge under a later merge = %v", err)
		}
		late := storetest.Now.Add(correlation.UnmergeWindow + time.Minute)
		if _, err := correlation.Unmerge(c, "b-c", "x", w.actor, late); code(err) != "unmerge_window_passed" {
			t.Errorf("late unmerge = %v", err)
		}
		if _, err := correlation.Unmerge(c, "b-c", "x", w.actor, storetest.Now); err != nil {
			return err
		}
		_, err = correlation.Unmerge(c, "a-b", "x", w.actor, storetest.Now)
		return err
	})
	if !is(w.accountIdentity("acct:okta:alice"), w.ids["alice"]) {
		t.Error("alice's account did not come back after both unmerges")
	}
}
