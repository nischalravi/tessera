package api

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/pit"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Group change events and point-in-time history (issue #46, GR-3). The test
// server's clock is frozen at storetest.Now, so every change happens at that
// instant; the time dimension is covered in internal/groups/pit.

func TestGroupsPITAPI(t *testing.T) {
	c, f := newGrp(t)
	alice, bob := f.B.IDs["alice"], f.B.IDs["bob"]
	app := c.folder("", "app")
	team := c.group(app, "team")
	c.member(team, alice)
	c.member(team, bob)
	c.call("DELETE", fmt.Sprintf("/api/groups/%s/members/%d", team, bob), "", 200)

	now := storetest.Now
	q := func(path string, params map[string]string) string {
		v := url.Values{}
		for k, val := range params {
			v.Set(k, val)
		}
		return path + "?" + v.Encode()
	}
	members := "/api/groups/" + team + "/members"

	// as of now: alice, not bob
	got := c.call("GET", q(members, map[string]string{"as_of": now.Format(time.RFC3339)}), "", 200)
	items := got["items"].([]any)
	if got["filter"] != "effective" || got["total"] != float64(1) || len(items) != 1 || got["as_of"] == nil {
		t.Fatalf("as_of now = %v", got)
	}
	if it := items[0].(map[string]any); it["identity_id"] != float64(alice) || it["end_at"] != nil || it["name"] == "" || it["start_at"] == nil {
		t.Errorf("as_of item = %v", it)
	}
	if g, _ := got["group"].(map[string]any); g["name"] != "app:team" || g["status"] != "active" {
		t.Errorf("group snapshot = %v", got["group"])
	}
	// an hour earlier the group did not exist
	got = c.call("GET", q(members, map[string]string{"as_of": now.Add(-time.Hour).Format(time.RFC3339)}), "", 200)
	if got["total"] != float64(0) || got["group"] != nil || len(got["items"].([]any)) != 0 {
		t.Errorf("as_of before the group = %v", got)
	}
	// between: bob joined and left inside the window, so both appear (all at the frozen instant: bob's interval is empty)
	got = c.call("GET", q(members, map[string]string{"between": now.Add(-time.Hour).Format(time.RFC3339) + "," + now.Format(time.RFC3339)}), "", 200)
	if got["total"] != float64(1) || got["from"] == nil || got["to"] == nil {
		t.Errorf("between = %v", got)
	}
	// direct rows: alice's row is open, bob's interval is closed (empty at the frozen instant)
	got = c.call("GET", q(members, map[string]string{"as_of": now.Format(time.RFC3339), "filter": "direct"}), "", 200)
	if got["filter"] != "direct" || got["total"] != float64(1) {
		t.Errorf("direct as_of = %v", got)
	}
	if it := got["items"].([]any)[0].(map[string]any); it["type"] != "identity" || it["source"] != "api" {
		t.Errorf("direct item = %v", it)
	}
	// the plain read is unchanged
	if plain := c.call("GET", members, "", 200); plain["filter"] != "direct" || plain["total"] != float64(1) {
		t.Errorf("plain read = %v", plain)
	}

	// refusals
	for _, qs := range []map[string]string{
		{"as_of": "yesterday"},
		{"as_of": now.Add(time.Hour).Format(time.RFC3339)},
		{"as_of": now.Format(time.RFC3339), "between": now.Format(time.RFC3339) + "," + now.Format(time.RFC3339)},
		{"between": now.Format(time.RFC3339)},
		{"between": now.Format(time.RFC3339) + "," + now.Add(-time.Hour).Format(time.RFC3339)},
		{"between": now.Add(-400*24*time.Hour).Format(time.RFC3339) + "," + now.Format(time.RFC3339)},
		{"as_of": now.Format(time.RFC3339), "filter": "everyone"},
		{"as_of": now.Format(time.RFC3339), "limit": "0"},
	} {
		if rec := c.do("GET", q(members, qs), ""); rec.Code != 422 {
			t.Errorf("GET %v = %d %.120s, want 422", qs, rec.Code, rec.Body.String())
		}
	}
	if rec := c.do("GET", q("/api/groups/00000000-0000-4000-8000-000000000000/members", map[string]string{"as_of": now.Format(time.RFC3339)}), ""); rec.Code != 404 {
		t.Errorf("as_of of an unknown group = %d", rec.Code)
	}

	// a deleted group keeps its history
	c.call("DELETE", "/api/groups/"+team, "", 200)
	got = c.call("GET", q(members, map[string]string{"as_of": now.Format(time.RFC3339)}), "", 200)
	if g, _ := got["group"].(map[string]any); g["status"] != "deleted" || got["total"] != float64(0) {
		t.Errorf("as_of after the delete = %v", got)
	}

	// digests: none yet; write one (the job does this at 00:05) and read it back
	if got := c.call("GET", "/api/groups/pit/digests", "", 200); len(got["items"].([]any)) != 0 {
		t.Errorf("digests = %v", got)
	}
	if got := c.call("GET", "/api/groups/pit/verify", "", 200); got["ok"] != true || len(got["days"].([]any)) != 0 {
		t.Errorf("verify without digests = %v", got)
	}
	var d *store.PitDigest
	err := f.DB.InTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		var err error
		d, _, err = pit.WriteDigest(tx, pit.Day(now), now.Add(24*time.Hour))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	got = c.call("GET", "/api/groups/pit/digests", "", 200)
	if it := got["items"].([]any)[0].(map[string]any); it["day"] != pit.Day(now) || it["merkle_root"] != d.MerkleRoot ||
		it["algorithm"] != "rfc6962-sha256" || it["event_count"] != float64(d.EventCount) {
		t.Errorf("digest = %v", it)
	}
	got = c.call("GET", "/api/groups/pit/verify?day="+pit.Day(now), "", 200)
	if v := got["days"].([]any)[0].(map[string]any); got["ok"] != true || v["status"] != "ok" {
		t.Errorf("verify = %v", got)
	}
	if got := c.call("GET", "/api/groups/pit/verify?day=2020-01-01", "", 200); got["days"].([]any)[0].(map[string]any)["status"] != "no_digest" {
		t.Errorf("verify of an undigested day = %v", got)
	}
	if rec := c.do("GET", "/api/groups/pit/verify?day=soon", ""); rec.Code != 422 {
		t.Errorf("verify of a bad day = %d", rec.Code)
	}

	// rebuild: the whole tenant, one group, an unknown group, a malformed id
	if got := c.call("POST", "/api/groups/pit/rebuild", "", 200); got["group_id"] != nil || got["events_replayed"].(float64) < 5 {
		t.Errorf("rebuild = %v", got)
	}
	if got := c.call("POST", "/api/groups/pit/rebuild", `{"group_id":"`+team+`"}`, 200); got["group_id"] != team || got["events_replayed"].(float64) < 3 {
		t.Errorf("rebuild of a group = %v", got)
	}
	c.call("POST", "/api/groups/pit/rebuild", `{"group_id":"00000000-0000-4000-8000-000000000000"}`, 404)
	c.call("POST", "/api/groups/pit/rebuild", `{"group_id":"nope"}`, 422)
	c.call("POST", "/api/groups/pit/rebuild", `{"group":"x"}`, 422)
	// the rebuilds are audited, and the answer to a PIT read did not change
	f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		evs, err := tx.AuditEvents(store.AuditFilter{Action: pit.ActionRebuild})
		if err != nil || len(evs) != 2 {
			t.Errorf("rebuild audit events = %d, %v; want 2", len(evs), err)
		}
		return nil
	})
	got = c.call("GET", q(members, map[string]string{"as_of": now.Format(time.RFC3339)}), "", 200)
	if g, _ := got["group"].(map[string]any); g["status"] != "deleted" {
		t.Errorf("as_of after the rebuilds = %v", got)
	}
}

// TestGroupsPITTenantIsolation: another tenant's group looks nonexistent to a
// PIT read and to a rebuild, and a rebuild in one tenant leaves the other's
// history alone.
func TestGroupsPITTenantIsolation(t *testing.T) {
	f := storetest.TwoTenants(t)
	a := grpClient{client{t, isolationServer(t, f, f.A.ID).Handler()}}
	b := grpClient{client{t, isolationServer(t, f, f.B.ID).Handler()}}
	ag := a.group(a.folder("", "app"), "admins")
	a.member(ag, f.A.IDs["alice"])
	b.group(b.folder("", "app"), "mine")
	at := storetest.Now.Format(time.RFC3339)
	b.call("GET", "/api/groups/"+ag+"/members?as_of="+url.QueryEscape(at), "", 404)
	b.call("GET", "/api/groups/"+ag+"/members?between="+url.QueryEscape(at+","+at), "", 404)
	b.call("POST", "/api/groups/pit/rebuild", `{"group_id":"`+ag+`"}`, 404)
	b.call("POST", "/api/groups/pit/rebuild", "", 200)
	if got := a.call("GET", "/api/groups/"+ag+"/members?as_of="+url.QueryEscape(at), "", 200); got["total"] != float64(1) {
		t.Errorf("A's history after B's rebuild = %v", got)
	}
	err := f.DB.InTenant(context.Background(), f.A.ID, func(tx *store.TenantTx) error {
		_, _, err := pit.WriteDigest(tx, pit.Day(storetest.Now), storetest.Now.Add(24*time.Hour))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := b.call("GET", "/api/groups/pit/digests", "", 200); len(got["items"].([]any)) != 0 {
		t.Errorf("B sees A's digests: %v", got)
	}
	if got := a.call("GET", "/api/groups/pit/digests", "", 200); len(got["items"].([]any)) != 1 {
		t.Errorf("A's digests: %v", got)
	}
}

func TestGroupsPITRoutesRequireTenantAdmin(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	for _, role := range []auth.Role{auth.RoleViewer, auth.RoleOperator, auth.RoleAuditor, auth.RolePolicyAdmin} {
		l := signIn(t, f.DB, f.B.ID, authtest.User{Email: string(role) + "@b.example", Roles: []auth.Role{role}}, authtest.Phr, storetest.Now)
		for _, tc := range [][3]string{
			{"GET", "/api/groups/pit/digests", ""}, {"GET", "/api/groups/pit/verify", ""},
			{"POST", "/api/groups/pit/rebuild", ""},
		} {
			if rec := serve(h, authed(l, tc[0], tc[1], tc[2])); rec.Code != http.StatusForbidden {
				t.Errorf("%s %s %s = %d, want 403", role, tc[0], tc[1], rec.Code)
			}
		}
	}
}
