package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/sponsorship"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// seedSponsorships adds one active visitor sponsorship to each tenant (alice
// sponsored by carol; tenant A's purpose carries the sentinel) and returns the
// ids.
func seedSponsorships(t testing.TB, f *storetest.Fixture) map[tenancy.ID]string {
	t.Helper()
	out := map[tenancy.ID]string{}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		purpose := "conference"
		if tn.ID == f.A.ID {
			purpose += " " + storetest.Sentinel
		}
		id, intake, sponsor := uuid.NewString(), uuid.NewString(), tn.IDs["carol"]
		if err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			if err := c.InsertIntake(&store.IntakeRecord{ID: intake, Channel: store.ChannelSponsorInvite, MatchMode: store.MatchSelfAsserted,
				SponsorIdentityID: &sponsor, Status: store.IntakeReceived, InvitationStatus: store.InvitationReady, CreatedAt: storetest.Now}); err != nil {
				return err
			}
			return c.InsertSponsorship(&store.Sponsorship{ID: id, GuestIdentityID: tn.IDs["alice"], IntakeID: intake, SponsorIdentityID: sponsor,
				Population: store.PopVisitor, Purpose: purpose, AccessBundle: "[]", RequiredAAL: 2, StartsAt: storetest.Now,
				EndsAt: storetest.Now.AddDate(0, 0, 10), Status: store.SponsorActive, PolicyVersion: "v-seed",
				CreatedAt: storetest.Now, UpdatedAt: storetest.Now})
		}); err != nil {
			t.Fatal(err)
		}
		out[tn.ID] = id
	}
	return out
}

func guestsDo(t *testing.T, h http.Handler, l authtest.Login, method, path, body string, want int) []byte {
	t.Helper()
	rec := reqDo(h, l, method, path, body)
	if rec.Code != want {
		t.Fatalf("%s %s: %d (want %d): %s", method, path, rec.Code, want, rec.Body)
	}
	return rec.Body.Bytes()
}

func guestsJSON[T any](t *testing.T, h http.Handler, l authtest.Login, method, path, body string, want int) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(guestsDo(t, h, l, method, path, body, want), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

type guestList struct {
	Rows           []sponsorshipView `json:"rows"`
	Populations    []populationView  `json:"populations"`
	PolicyVersion  string            `json:"policy_version"`
	CanSponsor     bool              `json:"can_sponsor"`
	CanReadAll     bool              `json:"can_read_all"`
	CanApprove     bool              `json:"can_approve"`
	MaxInvitesADay int               `json:"max_invites_per_day"`
}

func inviteJSON(email, pop string, ends time.Time, extra string) string {
	return fmt.Sprintf(`{"given_name":"Gwen","family_name":"Guest","email":%q,"population":%q,"purpose":"conference talk","ends_at":%q%s}`,
		email, pop, ends.Format(time.RFC3339), extra)
}

func TestGuestsAPI_Flow(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	b := f.B.IDs
	carol := reqLogin(t, f, "carol@b.example", []auth.Role{auth.RoleViewer}, "carol")
	bob := reqLogin(t, f, "bob@b.example", []auth.Role{auth.RoleViewer}, "bob")
	alice := reqLogin(t, f, "alice@b.example", []auth.Role{auth.RoleViewer}, "alice")
	admin := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	auditor := reqLogin(t, f, "aud@b.example", []auth.Role{auth.RoleAuditor}, "")
	nobody := reqLogin(t, f, "nobody@b.example", []auth.Role{auth.RoleViewer}, "")
	d := func(n int) time.Time { return storetest.Now.AddDate(0, 0, n) }

	// the sponsor's page: settings by population, the policy version, what the user may do
	l := guestsJSON[guestList](t, h, carol, "GET", "/api/guests", "", 200)
	pops := map[string]populationView{}
	for _, p := range l.Populations {
		pops[p.Key] = p
	}
	if len(l.Rows) != 0 || !l.CanSponsor || l.CanReadAll || l.CanApprove || l.PolicyVersion == "" || l.MaxInvitesADay != 50 ||
		pops["visitor"].MaxDays != 30 || pops["contractor"].MaxDays != 365 || pops["contractor"].DefaultIAL != 1 ||
		pops["visitor"].MaxActive != 50 || !pops["contractor"].NeedsReview || pops["partner"].MaxDays != 365 {
		t.Fatalf("list = %+v", l)
	}
	if l := guestsJSON[guestList](t, h, nobody, "GET", "/api/guests", "", 200); l.CanSponsor || len(l.Rows) != 0 {
		t.Errorf("a sign-in with no person: %+v", l)
	}

	// invite
	rec := reqDo(h, carol, "POST", "/api/guests/invitations", inviteJSON("gwen@guest.example", "visitor", d(10), ""))
	var inv sponsorshipView
	if rec.Code != 201 || json.Unmarshal(rec.Body.Bytes(), &inv) != nil || inv.Status != "active" || inv.State != "ending" ||
		inv.Guest.Status != "invited" || inv.Guest.Email == nil || inv.Invitation != "ready" || inv.PolicyVersion != l.PolicyVersion ||
		!inv.CanEnd || !inv.CanRenew || !inv.CanTransfer || inv.CanApprove || len(inv.Events) != 1 || inv.Sponsor.ID != b["carol"] ||
		inv.DaysLeft == nil || *inv.DaysLeft != 10 || len(inv.Bundle) != 0 {
		t.Fatalf("invite: %d %s", rec.Code, rec.Body)
	}
	id := inv.ID
	// the guest has an affiliation and a lifecycle; the lifecycle API refuses to edit it
	var life lifecycleView
	if err := json.Unmarshal(guestsDo(t, h, admin, "GET", fmt.Sprintf("/api/identities/%d/lifecycle", inv.Guest.ID), "", 200), &life); err != nil ||
		life.WorkerType != "guest" || life.Sponsor == nil || life.Sponsor.ID != b["carol"] || life.Source != "sponsorship" {
		t.Errorf("lifecycle = %+v, %v", life, err)
	}
	put := fmt.Sprintf(`{"worker_type":"vendor","sponsor_identity_id":%d,"ends_at":%q,"reason":"x"}`, b["carol"], d(20).Format(time.RFC3339))
	if rec := reqDo(h, admin, "PUT", fmt.Sprintf("/api/identities/%d/lifecycle", inv.Guest.ID), put); rec.Code != 409 || !strings.Contains(rec.Body.String(), "managed_by_sponsorship") {
		t.Errorf("PUT lifecycle: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, carol, "POST", fmt.Sprintf("/api/identities/%d/lifecycle/extend", inv.Guest.ID), fmt.Sprintf(`{"ends_at":%q,"reason":"x"}`, d(20).Format(time.RFC3339))); rec.Code != 409 || !strings.Contains(rec.Body.String(), "managed_by_sponsorship") {
		t.Errorf("extend lifecycle: %d %s", rec.Code, rec.Body)
	}
	if affs := decodeAffs(t, reqDo(h, admin, "GET", fmt.Sprintf("/api/identities/%d/affiliations", inv.Guest.ID), "")); len(affs.Affiliations) != 1 ||
		affs.Affiliations[0].Source != "sponsorship" || affs.Affiliations[0].Type != "guest_visitor" {
		t.Errorf("affiliations = %+v", affs)
	}

	// what each person sees
	if l := guestsJSON[guestList](t, h, carol, "GET", "/api/guests?sponsor=me", "", 200); len(l.Rows) != 1 || l.Rows[0].ID != id {
		t.Errorf("carol's guests = %+v", l.Rows)
	}
	if l := guestsJSON[guestList](t, h, bob, "GET", "/api/guests", "", 200); len(l.Rows) != 0 {
		t.Errorf("bob sees carol's guest: %+v", l.Rows)
	}
	guestsDo(t, h, bob, "GET", "/api/guests?sponsor=all", "", 403)
	if l := guestsJSON[guestList](t, h, auditor, "GET", "/api/guests?sponsor=all&state=active&population=visitor", "", 200); len(l.Rows) != 1 || !l.CanReadAll {
		t.Errorf("auditor's guests = %+v", l)
	}
	if l := guestsJSON[guestList](t, h, auditor, "GET", "/api/guests?sponsor=all&state=ended", "", 200); len(l.Rows) != 0 {
		t.Errorf("filter by state: %+v", l.Rows)
	}
	for _, q := range []string{"sponsor=everyone", "state=bogus", "population=student"} {
		guestsDo(t, h, carol, "GET", "/api/guests?"+q, "", 422)
	}
	guestsDo(t, h, bob, "GET", "/api/sponsorships/"+id, "", 404) // not theirs: looks missing
	guestsDo(t, h, alice, "GET", "/api/sponsorships/"+id, "", 404)
	if v := guestsJSON[sponsorshipView](t, h, auditor, "GET", "/api/sponsorships/"+id, "", 200); v.ID != id || v.CanEnd || v.CanRenew || len(v.Events) != 1 {
		t.Errorf("auditor's view = %+v", v)
	}
	guestsDo(t, h, bob, "POST", "/api/sponsorships/"+id+"/end", `{"reason":"mine now"}`, 404)
	guestsDo(t, h, auditor, "POST", "/api/sponsorships/"+id+"/end", `{"reason":"x"}`, 403) // sees it, may not end it
	guestsDo(t, h, carol, "GET", "/api/sponsorships/approvals", "", 403)

	// the policy says no, with a stable code
	for name, tc := range map[string]struct {
		body, code string
		status     int
	}{
		"self":             {inviteJSON("Carol@T.example", "visitor", d(5), ""), "cannot_sponsor_self", 422},
		"too long":         {inviteJSON("a@x.example", "visitor", d(31), ""), "exceeds_max_duration", 422},
		"no end":           {`{"given_name":"G","email":"a@x.example","population":"visitor","purpose":"x"}`, "invalid_dates", 422},
		"unknown field":    {`{"given_name":"G","email":"a@x.example","population":"visitor","purpose":"x","ends_at":"2026-10-12T00:00:00Z","role":"admin"}`, "invalid_body", 422},
		"uncataloged item": {inviteJSON("a@x.example", "visitor", d(5), fmt.Sprintf(`,"bundle":[%d]`, b["group:okta:eng"])), "bundle_item_not_requestable", 422},
		"bad email":        {inviteJSON("nope", "visitor", d(5), ""), "invalid_email", 422},
	} {
		if rec := reqDo(h, carol, "POST", "/api/guests/invitations", tc.body); rec.Code != tc.status || !strings.Contains(rec.Body.String(), `"`+tc.code+`"`) {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	// a sign-in with no person cannot sponsor; the same answer whatever the email is
	if rec := reqDo(h, nobody, "POST", "/api/guests/invitations", inviteJSON("x@x.example", "visitor", d(5), "")); rec.Code != 422 || !strings.Contains(rec.Body.String(), "sponsor_identity_required") {
		t.Errorf("no person: %d %s", rec.Code, rec.Body)
	}
	// an address we know is accepted exactly like one we do not
	a := reqDo(h, carol, "POST", "/api/guests/invitations", inviteJSON("alice@t.example", "visitor", d(5), ""))
	z := reqDo(h, carol, "POST", "/api/guests/invitations", inviteJSON("zed@x.example", "visitor", d(5), ""))
	var av, zv sponsorshipView
	if a.Code != 201 || z.Code != 201 || json.Unmarshal(a.Body.Bytes(), &av) != nil || json.Unmarshal(z.Body.Bytes(), &zv) != nil ||
		av.Guest.ID == b["alice"] || av.Guest.Status != zv.Guest.Status || av.Status != zv.Status {
		t.Errorf("known vs unknown address: %d %s / %d %s", a.Code, a.Body, z.Code, z.Body)
	}

	// renew, then transfer to bob, who accepts
	guestsDo(t, h, carol, "POST", "/api/sponsorships/"+id+"/renew", fmt.Sprintf(`{"ends_at":%q,"justification":" "}`, d(20).Format(time.RFC3339)), 422)
	guestsDo(t, h, carol, "POST", "/api/sponsorships/"+id+"/renew", fmt.Sprintf(`{"ends_at":%q,"justification":"too long"}`, d(40).Format(time.RFC3339)), 422)
	v := guestsJSON[sponsorshipView](t, h, carol, "POST", "/api/sponsorships/"+id+"/renew", fmt.Sprintf(`{"ends_at":%q,"justification":"extended talk"}`, d(20).Format(time.RFC3339)), 200)
	if !v.EndsAt.Equal(d(20)) || len(v.Events) != 2 || v.Events[1].Event != "renewed" {
		t.Errorf("renewed = %+v", v)
	}
	guestsDo(t, h, carol, "POST", "/api/sponsorships/"+id+"/transfer", fmt.Sprintf(`{"to_identity_id":%d,"reason":"x"}`, b["dave"]), 422)
	v = guestsJSON[sponsorshipView](t, h, carol, "POST", "/api/sponsorships/"+id+"/transfer", fmt.Sprintf(`{"to_identity_id":%d,"reason":"I am leaving"}`, b["bob"]), 200)
	if v.Status != "transfer_pending" || v.TransferTo == nil || v.TransferTo.ID != b["bob"] || v.TransferDeadline == nil || v.CanAcceptTransfer {
		t.Errorf("transfer = %+v", v)
	}
	if l := guestsJSON[guestList](t, h, bob, "GET", "/api/guests", "", 200); len(l.Rows) != 1 || !l.Rows[0].CanAcceptTransfer || l.Rows[0].CanEnd {
		t.Errorf("bob's offers = %+v", l.Rows)
	}
	guestsDo(t, h, carol, "POST", "/api/sponsorships/"+id+"/accept-transfer", `{}`, 403)
	v = guestsJSON[sponsorshipView](t, h, bob, "POST", "/api/sponsorships/"+id+"/accept-transfer", `{}`, 200)
	if v.Status != "active" || v.Sponsor.ID != b["bob"] || v.TransferTo != nil || !v.CanEnd {
		t.Errorf("accepted = %+v", v)
	}
	guestsDo(t, h, carol, "GET", "/api/sponsorships/"+id, "", 404) // no longer hers
	// bob ends it: the invited guest has no other sponsorship, so the person ends
	v = guestsJSON[sponsorshipView](t, h, bob, "POST", "/api/sponsorships/"+id+"/end", `{"reason":"talk is over"}`, 200)
	if v.Status != "ended" || v.EndedAt == nil || v.CanEnd {
		t.Errorf("ended = %+v", v)
	}
	guestsDo(t, h, bob, "POST", "/api/sponsorships/"+id+"/end", `{"reason":"again"}`, 409)

	// a contractor with a privileged bundle waits for a second approver
	prod := b["group:aws:ProdAdmin"]
	if err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.PutCatalogItem(&store.CatalogItem{ID: uuid.NewString(), GroupID: prod, Requestable: true, Risk: "medium",
			EligibleTypes: []string{"human"}, UpdatedAt: storetest.Now})
	}); err != nil {
		t.Fatal(err)
	}
	con := guestsJSON[sponsorshipView](t, h, carol, "POST", "/api/guests/invitations",
		inviteJSON("con@x.example", "contractor", d(90), fmt.Sprintf(`,"bundle":[%d]`, prod)), 201)
	if con.Status != "pending_approval" || con.RequiredIAL != 2 || len(con.Bundle) != 1 || !con.Bundle[0].Privileged || con.CanApprove {
		t.Fatalf("contractor = %+v", con)
	}
	guestsDo(t, h, carol, "POST", "/api/sponsorships/"+con.ID+"/approve", `{}`, 403)
	guestsDo(t, h, admin, "GET", fmt.Sprintf("/api/identities/%d/lifecycle", con.Guest.ID), "", 200)
	if rows := guestsJSON[[]sponsorshipView](t, h, admin, "GET", "/api/sponsorships/approvals", "", 200); len(rows) != 1 || rows[0].ID != con.ID || !rows[0].CanApprove {
		t.Errorf("approvals = %+v", rows)
	}
	guestsDo(t, h, admin, "POST", "/api/sponsorships/"+con.ID+"/reject", `{}`, 422)
	v = guestsJSON[sponsorshipView](t, h, admin, "POST", "/api/sponsorships/"+con.ID+"/approve", `{}`, 200)
	if v.Status != "active" || v.ApprovedBy == nil || v.ApprovedBy.DisplayName == "" {
		t.Errorf("approved = %+v", v)
	}
	if rows := guestsJSON[[]sponsorshipView](t, h, admin, "GET", "/api/sponsorships/approvals", "", 200); len(rows) != 0 {
		t.Errorf("approvals after = %+v", rows)
	}
	// ... and a second one is rejected
	rej := guestsJSON[sponsorshipView](t, h, carol, "POST", "/api/guests/invitations",
		inviteJSON("con2@x.example", "contractor", d(90), fmt.Sprintf(`,"bundle":[%d]`, prod)), 201)
	v = guestsJSON[sponsorshipView](t, h, admin, "POST", "/api/sponsorships/"+rej.ID+"/reject", `{"reason":"no budget"}`, 200)
	if v.Status != "rejected" || v.EndReason == nil {
		t.Errorf("rejected = %+v", v)
	}

	// the audit ledger has every change
	acts := reqAuditActions(t, f, f.B.ID)
	for a, n := range map[string]int{"sponsorship.create": 5, "sponsorship.renew": 1, "sponsorship.transfer": 1, "sponsorship.accept_transfer": 1,
		"sponsorship.end": 1, "sponsorship.approve": 1, "sponsorship.reject": 1} {
		if acts[a] != n {
			t.Errorf("audit %s = %d, want %d", a, acts[a], n)
		}
	}
}

func TestGuestsAPI_BulkInvite(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	carol := reqLogin(t, f, "carol@b.example", []auth.Role{auth.RoleViewer}, "carol")
	end := storetest.Now.AddDate(0, 0, 10).Format("2006-01-02")
	csv := "email,given_name,family_name,population,starts_at,ends_at,purpose\n" +
		"a@x.example,A,One,visitor,," + end + ",workshop\n" +
		"carol@t.example,C,Self,visitor,," + end + ",workshop\n" +
		"b@x.example,B,Two,visitor,,2099-01-01,workshop\n"
	body := func(dry bool) string {
		b, _ := json.Marshal(map[string]any{"csv": csv, "dry_run": dry})
		return string(b)
	}
	dry := guestsJSON[sponsorship.BulkResult](t, h, carol, "POST", "/api/guests/invitations/bulk", body(true), 200)
	if !dry.DryRun || dry.WouldCreate != 1 || dry.Refused != 2 || dry.Rows[1].Code != "cannot_sponsor_self" || dry.Rows[2].Code != "exceeds_max_duration" ||
		dry.PolicyVersion == "" || dry.Rows[0].Status != "ok" {
		t.Errorf("dry run = %+v", dry)
	}
	if l := guestsJSON[guestList](t, h, carol, "GET", "/api/guests", "", 200); len(l.Rows) != 0 {
		t.Error("the dry run wrote")
	}
	run := guestsJSON[sponsorship.BulkResult](t, h, carol, "POST", "/api/guests/invitations/bulk", body(false), 201)
	if run.DryRun || run.Created != 1 || run.Refused != 2 || run.Rows[0].Status != "created" || run.Rows[0].SponsorshipID == "" {
		t.Errorf("run = %+v", run)
	}
	if l := guestsJSON[guestList](t, h, carol, "GET", "/api/guests", "", 200); len(l.Rows) != 1 {
		t.Errorf("rows = %+v", l.Rows)
	}
	for name, b := range map[string]string{"empty file": `{"csv":""}`, "bad header": `{"csv":"a,b\n1,2\n"}`, "no body": ``, "unknown field": `{"csv":"x","owner":1}`} {
		if rec := reqDo(h, carol, "POST", "/api/guests/invitations/bulk", b); rec.Code != 422 && rec.Code != 400 {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	acts := reqAuditActions(t, f, f.B.ID)
	if acts["sponsorship.bulk_preview"] != 1 || acts["sponsorship.bulk_invite"] != 1 || acts["sponsorship.create"] != 1 {
		t.Errorf("audit = %v", acts)
	}
}

// Every change needs a fresh phishing-resistant sign-in.
func TestGuestsAPI_StepUp(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	id := f.B.IDs["carol"]
	stale := signIn(t, f.DB, f.B.ID, authtest.User{Email: "carol@b.example", Roles: []auth.Role{auth.RoleViewer}, IdentityID: &id},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}, storetest.Now)
	seeded := seedSponsorships(t, f)[f.B.ID]
	for _, c := range []struct{ method, path, body string }{
		{"POST", "/api/guests/invitations", inviteJSON("a@x.example", "visitor", storetest.Now.AddDate(0, 0, 5), "")},
		{"POST", "/api/guests/invitations/bulk", `{"csv":"x","dry_run":true}`},
		{"POST", "/api/sponsorships/" + seeded + "/end", `{"reason":"x"}`},
		{"POST", "/api/sponsorships/" + seeded + "/renew", `{}`},
		{"POST", "/api/sponsorships/" + seeded + "/transfer", `{}`},
		{"POST", "/api/sponsorships/" + seeded + "/accept-transfer", `{}`},
	} {
		if rec := reqDo(h, stale, c.method, c.path, c.body); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
			t.Errorf("%s %s: %d %s", c.method, c.path, rec.Code, rec.Body)
		}
	}
	// reads do not need it
	guestsDo(t, h, stale, "GET", "/api/guests", "", 200)
	guestsDo(t, h, stale, "GET", "/api/sponsorships/"+seeded, "", 200)
}

// Tenant B reaches none of tenant A's sponsorships: A's id answers as one that does not exist.
func TestSponsorshipsAPI_CrossTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedSponsorships(t, f)
	h := newIsolationServer(f).Handler()
	carol := reqLogin(t, f, "carol@b.example", []auth.Role{auth.RoleViewer}, "carol")
	admin := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	missing := uuid.NewString()
	before := storetest.Dump(t, f.DB, f.A.ID)
	beforeSp := sponsorshipDump(t, f, f.A.ID)
	for name, tc := range map[string]struct {
		method, suffix, body string
		login                authtest.Login
	}{
		"get":             {"GET", "", "", carol},
		"get as admin":    {"GET", "", "", admin},
		"approve":         {"POST", "/approve", `{}`, admin},
		"reject":          {"POST", "/reject", `{"reason":"x"}`, admin},
		"renew":           {"POST", "/renew", `{"ends_at":"2026-10-12T00:00:00Z","justification":"x"}`, carol},
		"end":             {"POST", "/end", `{"reason":"x"}`, carol},
		"end as admin":    {"POST", "/end", `{"reason":"x"}`, admin},
		"transfer":        {"POST", "/transfer", fmt.Sprintf(`{"to_identity_id":%d,"reason":"x"}`, f.B.IDs["bob"]), carol},
		"accept transfer": {"POST", "/accept-transfer", `{}`, carol},
	} {
		t.Run(name, func(t *testing.T) {
			cross := reqDo(h, tc.login, tc.method, "/api/sponsorships/"+ids[f.A.ID]+tc.suffix, tc.body)
			none := reqDo(h, tc.login, tc.method, "/api/sponsorships/"+missing+tc.suffix, tc.body)
			if cross.Code != 404 || cross.Code != none.Code ||
				strings.ReplaceAll(cross.Body.String(), ids[f.A.ID], "<id>") != strings.ReplaceAll(none.Body.String(), missing, "<id>") {
				t.Errorf("A's id: %d %s\nmissing: %d %s", cross.Code, cross.Body, none.Code, none.Body)
			}
			if leaks(cross.Body.String()) {
				t.Error("leaks tenant A data")
			}
		})
	}
	// ids in a body: A's person or A's group look like ones that do not exist
	own := ids[f.B.ID]
	for name, tc := range map[string]func(id int64) (path, body string){
		"transfer to": func(id int64) (string, string) {
			return "/api/sponsorships/" + own + "/transfer", fmt.Sprintf(`{"to_identity_id":%d,"reason":"x"}`, id)
		},
		"bundle": func(id int64) (string, string) {
			return "/api/guests/invitations", fmt.Sprintf(`{"given_name":"G","email":"g@x.example","population":"visitor","purpose":"x","ends_at":"2026-10-12T00:00:00Z","bundle":[%d]}`, id)
		},
	} {
		t.Run(name, func(t *testing.T) {
			key := "bob"
			if name == "bundle" {
				key = "group:aws:ProdAdmin"
			}
			ap, ab := tc(f.A.IDs[key])
			mp, mb := tc(missingID)
			cross, none := reqDo(h, carol, "POST", ap, ab), reqDo(h, carol, "POST", mp, mb)
			if cross.Code != 422 || cross.Code != none.Code || cross.Body.String() != none.Body.String() || leaks(cross.Body.String()) {
				t.Errorf("A's id: %d %s\nmissing: %d %s", cross.Code, cross.Body, none.Code, none.Body)
			}
		})
	}
	// the lists show B's own only
	l := guestsJSON[guestList](t, h, admin, "GET", "/api/guests?sponsor=all", "", 200)
	if len(l.Rows) != 1 || l.Rows[0].ID != ids[f.B.ID] || leaks(fmt.Sprint(l)) {
		t.Errorf("B's guests = %+v", l.Rows)
	}
	if rows := guestsJSON[[]sponsorshipView](t, h, admin, "GET", "/api/sponsorships/approvals", "", 200); len(rows) != 0 {
		t.Errorf("approvals = %+v", rows)
	}
	if storetest.Dump(t, f.DB, f.A.ID) != before || sponsorshipDump(t, f, f.A.ID) != beforeSp {
		t.Error("calls made as tenant B changed tenant A")
	}
}

func sponsorshipDump(t *testing.T, f *storetest.Fixture, tn tenancy.ID) string {
	t.Helper()
	var out string
	if err := f.DB.ReadTenant(context.Background(), tn, func(c *store.TenantTx) error {
		ss, err := c.Sponsorships(store.SponsorshipFilter{})
		for _, s := range ss {
			evs, _ := c.SponsorshipEvents(s.ID)
			b, _ := json.Marshal([]any{s, evs})
			out += string(b)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}
