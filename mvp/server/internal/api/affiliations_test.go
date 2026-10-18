package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func decodeAffs(t *testing.T, rec *httptest.ResponseRecorder) personAffiliationsView {
	t.Helper()
	var v personAffiliationsView
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &v) != nil {
		t.Fatalf("affiliations: %d %s", rec.Code, rec.Body)
	}
	return v
}

func TestAffiliationsAPI_ReadAddEnd(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	alice := f.B.IDs["alice"]
	l := policyAdmin(t, f, f.B.ID, "pa@b.example")
	path := fmt.Sprintf("/api/identities/%d/affiliations", alice)

	v := decodeAffs(t, corrDo(h, l, "GET", path, ""))
	if v.IdentityID != alice || v.LifecycleState != "active" || len(v.Affiliations) != 2 {
		t.Fatalf("initial: %+v", v)
	}
	hr := false
	for _, a := range v.Affiliations {
		hr = hr || a.Type == "employee" && a.Source == "hris" && a.Effective == "active" && a.SourceRef != nil
	}
	if !hr {
		t.Errorf("no active HR employee affiliation in %+v", v.Affiliations)
	}

	// identifiers: values and how they were verified, never the hash
	rec := corrDo(h, l, "GET", fmt.Sprintf("/api/identities/%d/identifiers", alice), "")
	var xs []identifierView
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &xs) != nil || len(xs) == 0 {
		t.Fatalf("identifiers: %d %s", rec.Code, rec.Body)
	}
	types := map[string]identifierView{}
	for _, x := range xs {
		types[x.Type] = x
	}
	if e := types["email"]; e.Value == nil || !strings.Contains(*e.Value, "@") || e.VerifiedBy == nil || *e.VerifiedBy != "authoritative_source" ||
		e.SourceSystem == nil || *e.SourceSystem != "hris" {
		t.Errorf("email identifier %+v", e)
	}
	if strings.Contains(rec.Body.String(), "hmac") {
		t.Errorf("identifier response carries a hash: %s", rec.Body)
	}

	// add a visitor
	end := storetest.Now.AddDate(0, 0, 10).Format(time.RFC3339)
	rec = corrDo(h, l, "POST", path, `{"type":"guest_visitor","org_unit":"Visitor Services","ends_at":"`+end+`","reason":"conference"}`)
	var added affiliationView
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &added) != nil || added.Source != "manual" || added.Effective != "active" ||
		added.Population == nil || *added.Population != "guest" {
		t.Fatalf("add: %d %s", rec.Code, rec.Body)
	}
	if v := decodeAffs(t, corrDo(h, l, "GET", path, "")); len(v.Affiliations) != 3 {
		t.Errorf("after add: %d affiliations", len(v.Affiliations))
	}

	// refusals have a stable code and change nothing
	for name, tc := range map[string]struct{ body, code string }{
		"authoritative type": {`{"type":"employee","reason":"x"}`, "type_not_manual"},
		"no end":             {`{"type":"contractor","reason":"x"}`, "end_required"},
		"no reason":          {`{"type":"alum"}`, "invalid_reason"},
		"too long":           {`{"type":"guest_visitor","ends_at":"` + storetest.Now.AddDate(0, 0, 90).Format(time.RFC3339) + `","reason":"x"}`, "exceeds_maximum"},
		"unknown population": {`{"type":"alum","population":"nope","reason":"x"}`, "unknown_population"},
	} {
		rec := corrDo(h, l, "POST", path, tc.body)
		if rec.Code != 422 || !strings.Contains(rec.Body.String(), `"`+tc.code+`"`) {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	if rec := corrDo(h, l, "POST", path, `{"type":"alum","reason":"x","extra":1}`); rec.Code != 422 {
		t.Errorf("unknown field: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(h, l, "POST", fmt.Sprintf("/api/identities/%d/affiliations", 987654), `{"type":"alum","reason":"x"}`); rec.Code != 404 {
		t.Errorf("unknown person: %d %s", rec.Code, rec.Body)
	}

	// end it, then again
	endPath := "/api/affiliations/" + added.ID + "/end"
	rec = corrDo(h, l, "POST", endPath, `{"reason":"left early"}`)
	var ended affiliationView
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &ended) != nil || ended.Status != "ended" || ended.EndedAt == nil ||
		ended.EndReason == nil || *ended.EndReason != "left early" {
		t.Fatalf("end: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(h, l, "POST", endPath, `{"reason":"again"}`); rec.Code != 409 || !strings.Contains(rec.Body.String(), "already_ended") {
		t.Errorf("second end: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(h, l, "POST", endPath, `{}`); rec.Code != 422 {
		t.Errorf("end without reason: %d %s", rec.Code, rec.Body)
	}

	acts := auditActions(t, f, f.B.ID)
	for _, a := range []string{"identity.affiliation.add", "identity.affiliation.end"} {
		if acts[a] != 1 {
			t.Errorf("audit %s = %d, want 1 (%v)", a, acts[a], acts)
		}
	}
}

// Ending every affiliation moves a person to expired; a person merged away
// reads as merged and cannot gain affiliations.
func TestAffiliationsAPI_DerivedStateAndMerged(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	l := policyAdmin(t, f, f.B.ID, "pa@b.example")
	bob := f.B.IDs["bob"]
	path := fmt.Sprintf("/api/identities/%d/affiliations", bob)

	v := decodeAffs(t, corrDo(h, l, "GET", path, ""))
	if len(v.Affiliations) != 1 || v.LifecycleState != "active" {
		t.Fatalf("bob: %+v", v)
	}
	// bob's only affiliation is from the HR feed: an administrator may not end it
	hr := v.Affiliations[0].ID
	if rec := corrDo(h, l, "POST", "/api/affiliations/"+hr+"/end", `{"reason":"left"}`); rec.Code != 422 || !strings.Contains(rec.Body.String(), "type_not_manual") {
		t.Fatalf("end HR affiliation: %d %s", rec.Code, rec.Body)
	}
	// the HR feed ends it (GU-4 will do this through ingest)
	if err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.EndAffiliation(hr, store.AffEnded, storetest.Now, nil, "left")
	}); err != nil {
		t.Fatal(err)
	}
	if v := decodeAffs(t, corrDo(h, l, "GET", path, "")); v.LifecycleState != "expired" {
		t.Errorf("after ending the last affiliation: %s", v.LifecycleState)
	}
	carol := f.B.IDs["carol"]
	if rec := corrDo(h, l, "POST", fmt.Sprintf("/api/identities/%d/merge", carol), fmt.Sprintf(`{"into":%d,"reason":"dup"}`, f.B.IDs["alice"])); rec.Code != 200 {
		t.Fatalf("merge: %d %s", rec.Code, rec.Body)
	}
	if v := decodeAffs(t, corrDo(h, l, "GET", fmt.Sprintf("/api/identities/%d/affiliations", carol), "")); v.LifecycleState != "merged" {
		t.Errorf("merged identity reads %s", v.LifecycleState)
	}
	rec := corrDo(h, l, "POST", fmt.Sprintf("/api/identities/%d/affiliations", carol), `{"type":"alum","reason":"x"}`)
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "identity_merged") {
		t.Errorf("add to merged: %d %s", rec.Code, rec.Body)
	}
}

func TestAffiliationsAPI_NeedsPermissionAndStepUp(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	alice := f.B.IDs["alice"]
	add := func(l authtest.Login) *httptest.ResponseRecorder {
		return corrDo(h, l, "POST", fmt.Sprintf("/api/identities/%d/affiliations", alice), `{"type":"alum","reason":"x"}`)
	}
	end := func(l authtest.Login) *httptest.ResponseRecorder {
		return corrDo(h, l, "POST", "/api/affiliations/"+f.B.Refs["affiliation:guest"]+"/end", `{"reason":"x"}`)
	}
	for _, role := range []auth.Role{auth.RoleViewer, auth.RoleOperator, auth.RoleAuditor, auth.RoleTenantAdmin} {
		l := signIn(t, f.DB, f.B.ID, authtest.User{Email: string(role) + "@b.example", Roles: []auth.Role{role}}, authtest.Phr, storetest.Now)
		if rec := add(l); rec.Code != 403 {
			t.Errorf("%s add: %d", role, rec.Code)
		}
		if rec := end(l); rec.Code != 403 {
			t.Errorf("%s end: %d", role, rec.Code)
		}
		// every role that can read the directory (graph.read) can read a person's affiliations
		if rec := corrDo(h, l, "GET", fmt.Sprintf("/api/identities/%d/affiliations", alice), ""); rec.Code != 200 {
			t.Errorf("%s read: %d", role, rec.Code)
		}
	}
	stale := signIn(t, f.DB, f.B.ID, authtest.User{Email: "stale@b.example", Roles: []auth.Role{auth.RolePolicyAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}, storetest.Now)
	for name, rec := range map[string]*httptest.ResponseRecorder{"add": add(stale), "end": end(stale)} {
		if rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
			t.Errorf("stale %s: %d %s", name, rec.Code, rec.Body)
		}
	}
	// nothing changed
	if got := auditActions(t, f, f.B.ID); got["identity.affiliation.add"]+got["identity.affiliation.end"] != 0 {
		t.Errorf("refused requests wrote domain events: %v", got)
	}
}

// Tenant B cannot read, add to or end tenant A's rows: A's ids answer exactly
// like missing ones, and A is left untouched.
func TestAffiliationsAPI_CrossTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	lb := policyAdmin(t, f, f.B.ID, "pa@b.example")
	before := storetest.Dump(t, f.DB, f.A.ID)
	var aAffs []*store.Affiliation
	if err := f.DB.ReadTenant(t.Context(), f.A.ID, func(c *store.TenantTx) (err error) { aAffs, err = c.Affiliations(); return }); err != nil {
		t.Fatal(err)
	}
	if len(aAffs) == 0 {
		t.Fatal("tenant A has no affiliations")
	}
	for _, a := range aAffs {
		cross := corrDo(h, lb, "POST", "/api/affiliations/"+a.ID+"/end", `{"reason":"x"}`)
		missing := corrDo(h, lb, "POST", "/api/affiliations/00000000-0000-4000-8000-00000000dead/end", `{"reason":"x"}`)
		if cross.Code != 404 || cross.Body.String() != missing.Body.String() {
			t.Errorf("B ending A's affiliation: %d %s (missing: %s)", cross.Code, cross.Body, missing.Body)
		}
	}
	rec := corrDo(h, lb, "GET", fmt.Sprintf("/api/identities/%d/affiliations", f.B.IDs["alice"]), "")
	for _, a := range aAffs {
		if strings.Contains(rec.Body.String(), a.ID) {
			t.Error("B lists A's affiliation")
		}
	}
	if after := storetest.Dump(t, f.DB, f.A.ID); after != before {
		t.Error("B's requests changed tenant A")
	}
	var stillActive bool
	if err := f.DB.ReadTenant(t.Context(), f.A.ID, func(c *store.TenantTx) error {
		a, err := c.Affiliation(f.A.Refs["affiliation:guest"])
		stillActive = err == nil && a.Status == store.AffActive
		return err
	}); err != nil || !stillActive {
		t.Errorf("A's guest affiliation is no longer active (%v)", err)
	}
}
