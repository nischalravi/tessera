package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func planItems(v any) []map[string]any {
	var out []map[string]any
	for _, x := range arr(obj(v)["items"]) {
		out = append(out, obj(x))
	}
	return out
}

// TestBreachAPI_EndToEnd drives vendor breach response through HTTP: the
// inventory of what is tied to a vendor, a plan, the run (rotation queued and
// the worker running it), verification by re-read, the manual items a person
// attests, the completion report and the evidence export.
func TestBreachAPI_EndToEnd(t *testing.T) {
	a := newRotAPI(t)
	a.call("PUT", "/api/rotation/adapters/sim", `{"type":"fake"}`, 201)
	a.call("PUT", "/api/rotation/policies", `{"kind":"access_key","max_age_days":90,"grace_hours":0,"adapter":"sim","destination":"sim","dest_path":"kv/{system}/{name}"}`, 200)
	a.call("POST", "/api/rotation/jobs/"+a.f.B.Refs["rot:job"]+"/cancel", `{}`, 200) // the fixture's pending job

	// the inventory is a dry run: it lists, it changes nothing
	inv, _ := a.call("POST", "/api/breach/inventory", `{"vendor":"AWS"}`, 200)
	if obj(inv)["vendor"] != "aws" || obj(inv)["total"].(float64) < 1 {
		t.Fatalf("inventory %v", inv)
	}
	var rotate int
	for _, c := range arr(obj(inv)["credentials"]) {
		if obj(c)["kind"] == "secret" && obj(c)["action"] == "rotate" {
			rotate++
		}
	}
	if rotate != 1 {
		t.Errorf("%d secrets to rotate in %v", rotate, inv)
	}
	a.call("POST", "/api/breach/inventory", `{"vendor":"bad/vendor"}`, 422)
	a.call("POST", "/api/breach/inventory", `{"vendor":"aws","extra":1}`, 422)
	pl, _ := a.call("GET", "/api/breach/plans", "", 200)
	if len(arr(obj(pl)["plans"])) != 0 {
		t.Fatalf("the inventory created a plan: %v", pl)
	}

	// a plan needs a reason and a vendor that has credentials
	a.call("POST", "/api/breach/plans", `{"vendor":"aws","reason":"short"}`, 422)
	a.call("POST", "/api/breach/plans", `{"vendor":"no-such-vendor","reason":"Vendor breach notice"}`, 404)
	created, _ := a.call("POST", "/api/breach/plans", `{"vendor":"aws","reason":"Vendor breach notice 21 Oct"}`, 201)
	id := obj(created)["id"].(string)
	if obj(created)["status"] != "planned" || len(planItems(created)) < 1 {
		t.Fatalf("created %v", created)
	}
	a.call("POST", "/api/breach/plans/"+id+"/verify", `{}`, 200)
	got, _ := a.call("GET", "/api/breach/plans/"+id, "", 200)
	if obj(obj(got)["report"])["complete"] != false || obj(got)["status"] != "planned" {
		t.Errorf("a plan nobody ran is complete: %v", got)
	}
	a.call("POST", "/api/breach/plans/"+id+"/items/"+planItems(got)[0]["id"].(string)+"/attest", `{"note":"did it by hand now"}`, 409) // not running

	// run: the rotation is queued once, no matter how often the run is repeated
	run, raw := a.call("POST", "/api/breach/plans/"+id+"/run", `{}`, 200)
	plan := obj(obj(run)["plan"])
	if plan["status"] != "running" || plan["rotation_run_id"] == nil {
		t.Fatalf("run %s", raw)
	}
	bulk := plan["rotation_run_id"]
	run, _ = a.call("POST", "/api/breach/plans/"+id+"/run", `{}`, 200)
	if obj(obj(run)["plan"])["rotation_run_id"] != bulk {
		t.Errorf("a second run queued another rotation")
	}
	bulks, _ := a.call("GET", "/api/rotation/bulk", "", 200)
	if len(arr(bulks)) != 2 { // the fixture's and this plan's
		t.Errorf("%d rotation runs", len(arr(bulks)))
	}

	// the worker rotates; a re-read verifies; the request alone never does
	var secretItem map[string]any
	for _, it := range planItems(obj(run)["plan"]) {
		if it["kind"] == "secret" && it["action"] == "rotate" {
			secretItem = it
		}
	}
	if secretItem == nil || secretItem["state"] == "verified" {
		t.Fatalf("secret item before the worker ran: %v", secretItem)
	}
	a.runEngine(6)
	v, _ := a.call("POST", "/api/breach/plans/"+id+"/verify", `{}`, 200)
	for _, it := range planItems(v) {
		if it["id"] == secretItem["id"] && (it["state"] != "verified" || it["verification"] == nil) {
			t.Errorf("rotated secret item: %v", it)
		}
	}

	// whatever is left is manual: attesting needs a second admin (issue #538)
	admin2 := grpClient{client{a.t, signIn(a.t, a.f.DB, a.f.B.ID, authtest.User{Email: "admin2@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}},
		authtest.Phr, storetest.Now).Handler(a.srv.Handler())}}
	otherTenant := grpClient{client{a.t, signIn(a.t, a.f.DB, a.f.A.ID, authtest.User{Email: "admin@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}},
		authtest.Phr, storetest.Now).Handler(a.srv.Handler())}}
	requester := grpClient{client{a.t, a.h}}
	attested := 0
	for _, it := range planItems(v) {
		if it["state"] == "verified" {
			continue
		}
		if it["action"] != "manual" {
			t.Fatalf("an open item that is not manual: %v", it)
		}
		item := "/api/breach/plans/" + id + "/items/" + it["id"].(string) + "/attest"
		a.call("POST", item, `{"note":"short"}`, 422)
		// the attest route no longer closes the item: it names the change a second admin must approve
		got, _ := a.call("POST", item, `{"note":"disabled in the vendor console"}`, 409)
		if errCode(obj(got)) != "two_admin_change_required" || obj(got)["change_type"] != "breach.item.attest" {
			t.Fatalf("attest answered %v", got)
		}
		body := `{"type":"breach.item.attest","payload":{"plan_id":"` + id + `","item_id":"` + it["id"].(string) + `","note":"disabled in the vendor console"}}`
		itemDetail := func() string {
			pv, _ := a.call("GET", "/api/breach/plans/"+id, "", 200)
			for _, x := range planItems(pv) {
				if x["id"] == it["id"] {
					d, _ := x["detail"].(string)
					return d
				}
			}
			t.Fatalf("item %v vanished", it["id"])
			return ""
		}
		if attested == 0 {
			// a rejected request puts the item back in progress with a clear text (issue #547)
			rej := requester.call("POST", "/api/admin/change-requests", body, 201)
			if d := itemDetail(); d != "attestation requested; a second admin must approve it" {
				t.Errorf("detail while requested = %q", d)
			}
			admin2.call("POST", "/api/admin/change-requests/"+rej["id"].(string)+"/reject", "{}", 200)
			if d := itemDetail(); !strings.Contains(d, "not approved") || strings.Contains(d, "must approve") {
				t.Errorf("detail after rejection = %q", d)
			}
		}
		ch := requester.call("POST", "/api/admin/change-requests", body, 201)
		if d := itemDetail(); d != "attestation requested; a second admin must approve it" {
			t.Errorf("detail while requested = %q", d)
		}
		if ch["status"] != "pending_approval" || ch["two_person"] != true {
			t.Fatalf("attest request = %v", ch)
		}
		requester.call("POST", "/api/admin/change-requests", body, 409) // one open request per item
		// the item is in progress and the plan open until a second admin approves
		pv, _ := a.call("GET", "/api/breach/plans/"+id, "", 200)
		for _, x := range planItems(pv) {
			if x["id"] == it["id"] && (x["state"] != "in_progress" || x["attested_by"] != nil) {
				t.Errorf("item while the request waits: %v", x)
			}
		}
		// the requester cannot approve; another tenant's admin cannot see the request; a second admin can
		approve := "/api/admin/change-requests/" + ch["id"].(string) + "/approve"
		ph := `{"payload_hash":"` + ch["payload_hash"].(string) + `"}`
		if got := requester.call("POST", approve, ph, 403); errCode(got) != "self_approval_refused" {
			t.Errorf("self approval = %v", got)
		}
		otherTenant.call("POST", approve, ph, 404)
		admin2.call("POST", approve, ph, 200)
		attested++
		v, _ = a.call("GET", "/api/breach/plans/"+id, "", 200)
		for _, x := range planItems(v) {
			if x["id"] == it["id"] && (x["state"] != "attested" || !strings.Contains(x["attested_by"].(string), "approved by")) {
				t.Errorf("item after approval: %v", x)
			}
			if x["id"] == it["id"] {
				d, _ := x["detail"].(string)
				if !strings.HasPrefix(d, "attested by ") || !strings.Contains(d, ", approved by ") ||
					!strings.HasSuffix(d, ": disabled in the vendor console") || strings.Contains(d, "must approve") {
					t.Errorf("detail after approval = %q", d)
				}
			}
		}
	}
	if attested == 0 {
		t.Fatal("no manual item to attest")
	}
	if obj(v)["status"] != "completed" || obj(obj(v)["report"])["complete"] != true || obj(v)["completed_at"] == nil {
		t.Fatalf("plan after every item was verified or attested: %v", v)
	}
	a.call("POST", "/api/breach/plans/"+id+"/run", `{}`, 409) // completed plans are final
	a.call("GET", "/api/breach/plans/00000000-0000-4000-8000-000000000000", "", 404)
	a.call("GET", "/api/breach/plans/not-an-id", "", 404)

	// the evidence export: a hashed JSON download naming the rotation jobs
	rec := serveOnce(a.h, "GET", "/api/breach/plans/"+id+"/evidence", "")
	if rec.Code != 200 || rec.Header().Get("X-Tessera-Evidence-SHA256") == "" ||
		!strings.Contains(rec.Header().Get("Content-Disposition"), "attachment") ||
		!strings.Contains(rec.Body.String(), `"rotation_jobs"`) || !strings.Contains(rec.Body.String(), `"old_credential_re_read"`) {
		t.Errorf("evidence: %d %v %.600s", rec.Code, rec.Header(), rec.Body)
	}
	var ev struct {
		Evidence struct {
			Attestations []struct {
				Status      string `json:"status"`
				RequestedBy string `json:"requested_by"`
				ApprovedBy  string `json:"approved_by"`
			} `json:"attestations"`
		} `json:"evidence"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ev); err != nil || len(ev.Evidence.Attestations) != attested+1 { // plus the one rejected request
		t.Fatalf("evidence attestations = %+v, %v", ev.Evidence.Attestations, err)
	}
	for _, at := range ev.Evidence.Attestations {
		if at.Status == "rejected" {
			continue
		}
		if at.Status != "applied" || at.RequestedBy == "" || at.ApprovedBy == "" || at.RequestedBy == at.ApprovedBy {
			t.Errorf("attestation evidence must name two different admins: %+v", at)
		}
	}
	if strings.Contains(rec.Body.String(), "secret_enc") {
		t.Error("the evidence carries sealed material")
	}

	// every change is in the audit ledger
	acts := strings.Join(a.actions(), " ")
	for _, want := range []string{"breach.plan.created", "breach.plan.started", "breach.plan.verified", "breach.plan.completed", "rotation.bulk.executed", "admin.change.submitted", "admin.change.approved", "breach.item.attested"} {
		if !strings.Contains(acts, want) {
			t.Errorf("no %s event in %s", want, acts)
		}
	}
}

// Another tenant never sees, runs, verifies or exports a plan.
func TestBreachAPI_CrossTenant(t *testing.T) {
	a := newRotAPI(t)
	created, _ := a.call("POST", "/api/breach/plans", `{"vendor":"aws","reason":"Vendor breach notice 21 Oct"}`, 201)
	id := obj(created)["id"].(string)
	item := planItems(created)[0]["id"].(string)
	hA := asAdmin(t, a.srv, a.f.DB, a.f.A.ID, storetest.Now).Handler()
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/api/breach/plans/" + id, ""},
		{"GET", "/api/breach/plans/" + id + "/evidence", ""},
		{"POST", "/api/breach/plans/" + id + "/run", `{}`},
		{"POST", "/api/breach/plans/" + id + "/verify", `{}`},
		{"POST", "/api/breach/plans/" + id + "/items/" + item + "/attest", `{"note":"not my plan, not my call"}`},
	} {
		if rec := serveOnce(hA, c.method, c.path, c.body); rec.Code != 404 {
			t.Errorf("%s %s as tenant A: %d %.200s", c.method, c.path, rec.Code, rec.Body)
		}
	}
	rec := serveOnce(hA, "GET", "/api/breach/plans", "")
	if rec.Code != 200 || strings.Contains(rec.Body.String(), id) {
		t.Errorf("tenant A lists tenant B's plan: %d %s", rec.Code, rec.Body)
	}
}
