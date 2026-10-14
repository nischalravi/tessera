package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// UAT #133: an HRIS event for an identity that does not exist is rejected, and
// an event row that already points at a missing identity cannot break the reads.
func TestHrisEventUnknownIdentity(t *testing.T) {
	st, _ := testkit.Tiny(t)
	c := client{t, testServer(t, st)}
	for _, typ := range []string{"leaver", "mover", "joiner"} {
		body := fmt.Sprintf(`{"type":%q,"identity_id":99999,"payload":{"name":"x","to_team":"eng"}}`, typ)
		rec := c.do("POST", "/api/hris/events", body)
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "unknown identity 99999") {
			t.Errorf("%s: status %d body %.200s, want 422 naming the unknown identity", typ, rec.Code, rec.Body.String())
		}
	}
	if evs := c.json("GET", "/api/hris/events", "", 200).([]any); len(evs) != 0 {
		t.Errorf("a rejected event was persisted: %v", evs)
	}

	// A row that predates the check: the list and plan endpoints must not 500.
	var badID int64
	testkit.Write(t, st, func(tx *store.TenantTx) error {
		id, err := tx.InsertHrisEvent(&store.HrisEvent{ExternalID: "evt-bad", Type: "leaver", Status: "pending",
			IdentityID: new(int64(99999)), EffectiveAt: testkit.Now})
		badID = id
		return err
	})
	if evs := c.json("GET", "/api/hris/events", "", 200).([]any); len(evs) != 1 {
		t.Errorf("events = %v", evs)
	}
	c.json("GET", fmt.Sprintf("/api/hris/events/%d/plan", badID), "", http.StatusConflict)
	c.json("POST", fmt.Sprintf("/api/hris/events/%d/execute", badID), "", http.StatusBadRequest)
}

// UAT #134: a connector sync must not undo a leaver, a revoked grant or an
// access-review revoke.
func TestSyncKeepsRemediation(t *testing.T) {
	c := newRD(t)
	var leaver, leaverEvent int64
	var revoked *store.GrantEdge
	c.read(func(tx *store.TenantTx) error {
		evs, err := tx.HrisEvents()
		if err != nil {
			return err
		}
		for _, ev := range evs {
			if ev.Type == "leaver" && ev.Status == "pending" && ev.IdentityID != nil && leaverEvent == 0 {
				leaverEvent, leaver = ev.ID, *ev.IdentityID
			}
		}
		return nil
	})
	if leaverEvent == 0 {
		t.Fatal("demo data has no pending leaver event")
	}
	// An access review (campaign created before the leaver runs) revokes one grant of a live identity...
	created := c.json("POST", "/api/reviews/campaigns", `{"name":"uat","unused_days":30}`, 200)
	camp := c.json("GET", fmt.Sprintf("/api/reviews/campaigns/%v", at(created, "id")), "", 200)
	var item map[string]any
	for _, ri := range at(camp, "review_items").([]any) {
		m := ri.(map[string]any)
		if at(m, "identity", "id") != float64(leaver) && m["edge_id"] != nil {
			item = m
			break
		}
	}
	if item == nil {
		t.Fatalf("campaign has no reviewable grant: %v", camp)
	}
	reviewEdge := c.edge(int64(item["edge_id"].(float64)))
	c.json("POST", fmt.Sprintf("/api/reviews/items/%v/decision", item["id"]), `{"decision":"revoke"}`, 200)
	// ...a least-privilege revoke removes another, and the leaver plan runs.
	var other *store.GrantEdge
	c.read(func(tx *store.TenantTx) error {
		edges, err := tx.Edges()
		if err != nil {
			return err
		}
		for _, e := range edges {
			if e.Source == "connector" && e.ID != reviewEdge.ID && strings.HasPrefix(e.Dst, "group:") {
				other = e
				break
			}
		}
		return nil
	})
	revoked = other
	c.json("POST", "/api/least-privilege/revoke", fmt.Sprintf(`{"edge_id": %d, "dry_run": false}`, revoked.ID), 200)
	c.json("POST", fmt.Sprintf("/api/hris/events/%d/execute", leaverEvent), "", 200)

	c.json("POST", "/api/connectors/sync", "", 200)

	c.read(func(tx *store.TenantTx) error {
		ident, err := tx.Identity(leaver)
		if err != nil {
			t.Fatal(err)
		}
		if ident.Status != "terminated" || ident.TerminatedAt == nil {
			t.Errorf("sync revived the leaver: status %q terminated_at %v", ident.Status, ident.TerminatedAt)
		}
		accts, err := tx.IdentityAccounts(leaver)
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range accts {
			if a.Status != "disabled" {
				t.Errorf("sync re-enabled %s:%s (%s)", a.System, a.Username, a.Status)
			}
			edges, err := tx.EdgesFrom(fmt.Sprintf("account:%d", a.ID))
			if err != nil {
				t.Fatal(err)
			}
			if len(edges) != 0 {
				t.Errorf("sync re-created %d grants for the leaver's account %s:%s", len(edges), a.System, a.Username)
			}
		}
		for name, e := range map[string]*store.GrantEdge{"least-privilege": revoked, "review": reviewEdge} {
			if _, err := tx.EdgeBetween(e.Src, e.Dst); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("sync restored the %s-revoked grant %s -> %s (err %v)", name, e.Src, e.Dst, err)
			}
		}
		return nil
	})
}

func (c rdClient) edge(id int64) *store.GrantEdge {
	c.t.Helper()
	return testkit.Get(c.t, c.st, func(tx *store.TenantTx) (*store.GrantEdge, error) { return tx.Edge(id) })
}

// UAT #135: simulating a time-boxed JIT grant (duration_hours) must not report
// the standing-admin violation that a permanent grant would.
func TestSimulateJitGrantIsNotStanding(t *testing.T) {
	st, ids := testkit.Tiny(t)
	c := client{t, testServer(t, st)}
	edge := func(extra string) string {
		return fmt.Sprintf(`{"add_edges":[{"src":"account:%d","dst":"group:%d"%s}]}`, ids["acct:okta:alice"], ids["group:okta:platform"], extra)
	}
	standing := c.json("POST", "/api/simulate", edge(""), 200)
	if n := at(standing, "summary", "violations_introduced"); n != 1.0 {
		t.Fatalf("permanent grant introduced %v violations, want 1", n)
	}
	timeBoxed := c.json("POST", "/api/simulate", edge(`,"duration_hours":4`), 200)
	if n := at(timeBoxed, "summary", "violations_introduced"); n != 0.0 {
		t.Errorf("time-boxed grant introduced %v violations, want 0", n)
	}
	if n := at(timeBoxed, "summary", "permissions_added"); n != at(standing, "summary", "permissions_added") {
		t.Errorf("permissions_added = %v, want the same as the permanent grant", n)
	}
	c.json("POST", "/api/simulate", edge(`,"duration_hours":0`), http.StatusBadRequest)
}
