package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	guestlife "github.com/nischalravi/tessera/mvp/server/internal/guests/lifecycle"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

type glOverview struct {
	Buckets  []string       `json:"buckets"`
	Counts   map[string]int `json:"counts"`
	Settings glSettingsView `json:"settings"`
}

type glTasks struct {
	Tasks []guestlife.Item `json:"tasks"`
}

// Overview, drill-down lists and the lifecycle settings: who may read and change what.
func TestGuestLifecycleAPI_OverviewItemsSettingsRBAC(t *testing.T) {
	f := storetest.TwoTenants(t)
	seedSponsorships(t, f) // alice sponsored by carol, ends in 10 days, in both tenants
	h := newIsolationServer(f).Handler()
	admin := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	auditor := reqLogin(t, f, "aud@b.example", []auth.Role{auth.RoleAuditor}, "")
	viewer := reqLogin(t, f, "v@b.example", []auth.Role{auth.RoleViewer}, "")
	tenantAdmin := reqLogin(t, f, "ta@b.example", []auth.Role{auth.RoleTenantAdmin}, "")

	o := guestsJSON[glOverview](t, h, auditor, "GET", "/api/guest-lifecycle", "", 200)
	if o.Counts["expiring_30"] != 1 || o.Counts["expiring_14"] != 1 || o.Counts["expiring_3"] != 0 || o.Counts["stepup_required"] != 0 ||
		o.Counts["pending_transfer"] != 0 || len(o.Buckets) != 12 {
		t.Errorf("overview = %+v", o)
	}
	st := o.Settings
	if fmt.Sprint(st.SponsorReminderDays) != "[30 14 3]" || st.GuestReminderDays != 14 || st.TransferDeadlineDays != 14 || st.OnSponsorDeparture != "end" ||
		st.ConversionDualStatus != "end" || st.GraceDays["visitor"] != 0 || st.GraceDays["contractor"] != 30 || st.RetentionDays != 2555 ||
		st.RetentionDaysVisitor != 365 || st.KeepRematchHashes {
		t.Errorf("default settings = %+v", st)
	}
	type items struct {
		Bucket string           `json:"bucket"`
		Items  []guestlife.Item `json:"items"`
	}
	it := guestsJSON[items](t, h, auditor, "GET", "/api/guest-lifecycle/items?bucket=expiring_14", "", 200)
	if len(it.Items) != 1 || it.Items[0].Guest.ID != f.B.IDs["alice"] || it.Items[0].Sponsor == nil || it.Items[0].Sponsor.ID != f.B.IDs["carol"] ||
		it.Items[0].DaysLeft == nil || *it.Items[0].DaysLeft != 10 {
		t.Errorf("items = %+v", it)
	}
	if it := guestsJSON[items](t, h, auditor, "GET", "/api/guest-lifecycle/items?bucket=expiring_3", "", 200); len(it.Items) != 0 {
		t.Errorf("expiring_3 = %+v", it)
	}
	guestsDo(t, h, auditor, "GET", "/api/guest-lifecycle/items?bucket=nonsense", "", 422)
	// reads need guests.read; settings need guest_lifecycle.configure
	guestsDo(t, h, viewer, "GET", "/api/guest-lifecycle", "", 403)
	guestsDo(t, h, viewer, "GET", "/api/guest-lifecycle/items", "", 403)
	guestsDo(t, h, auditor, "GET", "/api/admin/guest-lifecycle", "", 403)
	guestsDo(t, h, tenantAdmin, "GET", "/api/admin/guest-lifecycle", "", 403)
	guestsDo(t, h, admin, "GET", "/api/admin/guest-lifecycle", "", 200)
	body := `{"sponsor_reminder_days":[45,10,2],"guest_reminder_days":7,"transfer_deadline_days":21,"on_sponsor_departure":"suspend",` +
		`"conversion_dual_status":"sponsor_confirms","grace_days":{"visitor":1,"contractor":60,"volunteer":30,"partner":30},` +
		`"retention_days":3650,"retention_days_visitor":180,"keep_rematch_hashes":true}`
	guestsDo(t, h, auditor, "PUT", "/api/admin/guest-lifecycle", body, 403)
	for name, bad := range map[string]string{
		"no days":      strings.Replace(body, "[45,10,2]", "[0]", 1),
		"too many":     strings.Replace(body, "[45,10,2]", "[1,2,3,4,5,6]", 1),
		"departure":    strings.Replace(body, `"suspend"`, `"delete"`, 1),
		"dual":         strings.Replace(body, `"sponsor_confirms"`, `"maybe"`, 1),
		"grace":        strings.Replace(body, `"partner":30`, `"partner":400`, 1),
		"missing pop":  strings.Replace(body, `"partner":30`, `"other":30`, 1),
		"retention":    strings.Replace(body, `3650`, `0`, 1),
		"unknown key":  strings.Replace(body, `{"sponsor`, `{"extra":1,"sponsor`, 1),
		"deadline":     strings.Replace(body, `"transfer_deadline_days":21`, `"transfer_deadline_days":0`, 1),
		"guest remind": strings.Replace(body, `"guest_reminder_days":7`, `"guest_reminder_days":-1`, 1),
	} {
		if rec := reqDo(h, admin, "PUT", "/api/admin/guest-lifecycle", bad); rec.Code != 422 && rec.Code != 400 {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	got := guestsJSON[glSettingsView](t, h, admin, "PUT", "/api/admin/guest-lifecycle", body, 200)
	if fmt.Sprint(got.SponsorReminderDays) != "[45 10 2]" || got.OnSponsorDeparture != "suspend" || got.GraceDays["contractor"] != 60 ||
		!got.KeepRematchHashes || got.UpdatedAt == nil {
		t.Errorf("saved = %+v", got)
	}
	if a := auditActions(t, f, f.B.ID); a["guestlife.settings.update"] != 1 {
		t.Errorf("audit = %v", a)
	}
	// the settings are tenant B's alone
	if other := guestsJSON[glSettingsView](t, h, signInA(t, f, auth.RolePolicyAdmin), "GET", "/api/admin/guest-lifecycle", "", 200); other.GuestReminderDays != 14 {
		t.Errorf("tenant A's settings changed: %+v", other)
	}
	// the new reminder days take effect on the counts (a 45-day threshold changes nothing about "expiring" buckets)
	if o := guestsJSON[glOverview](t, h, auditor, "GET", "/api/guest-lifecycle", "", 200); o.Settings.OnSponsorDeparture != "suspend" {
		t.Errorf("overview settings = %+v", o.Settings)
	}
}

func signInA(t *testing.T, f *storetest.Fixture, role auth.Role) authtest.Login {
	t.Helper()
	return signIn(t, f.DB, f.A.ID, authtest.User{Email: "pa@a.example", Roles: []auth.Role{role}}, authtest.Phr, storetest.Now)
}

// Every change needs a fresh phishing-resistant sign-in.
func TestGuestLifecycleAPI_StepUp(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	stale := signIn(t, f.DB, f.B.ID, authtest.User{Email: "pa@b.example", Roles: []auth.Role{auth.RolePolicyAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}, storetest.Now)
	for _, c := range []struct{ method, path, body string }{
		{"PUT", "/api/admin/guest-lifecycle", `{}`},
		{"POST", "/api/guest-lifecycle/tasks/" + uuid.NewString() + "/resolve", `{"action":"accept"}`},
	} {
		if rec := reqDo(h, stale, c.method, c.path, c.body); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
			t.Errorf("%s %s: %d %s", c.method, c.path, rec.Code, rec.Body)
		}
	}
	guestsDo(t, h, stale, "GET", "/api/guest-lifecycle/tasks", "", 200)
	guestsDo(t, h, stale, "GET", "/api/admin/guest-lifecycle", "", 200)
}

// A leaver event for a sponsor opens a transfer task per sponsorship; the sponsor's
// manager and the sponsor admins see it, anyone else does not, and accepting moves it.
func TestGuestLifecycleAPI_SponsorLeaverTaskThroughHRIS(t *testing.T) {
	f := storetest.TwoTenants(t)
	seeded := seedSponsorships(t, f)[f.B.ID]
	h := newIsolationServer(f).Handler()
	b := f.B.IDs
	// nobody's identity on purpose (reqLogin links policy admins, approver_unlinked #443)
	admin := signIn(t, f.DB, f.B.ID, authtest.User{Email: "pa@b.example", Roles: []auth.Role{auth.RolePolicyAdmin}}, authtest.Phr, storetest.Now)
	bobAdmin := reqLogin(t, f, "bobadmin@b.example", []auth.Role{auth.RolePolicyAdmin}, "bob") // an approver who is also an eligible sponsor
	aliceUser := reqLogin(t, f, "alice@b.example", []auth.Role{auth.RoleViewer}, "alice")
	var ev int64
	carol := b["carol"]
	if err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) (err error) {
		ev, err = c.InsertHrisEvent(&store.HrisEvent{ExternalID: "evt-carol", Type: "leaver", IdentityID: &carol,
			Payload: ojson.Object{{Key: "reason", Value: "left"}}, EffectiveAt: storetest.Now, Status: "pending"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	guestsDo(t, h, admin, "POST", fmt.Sprintf("/api/hris/events/%d/execute", ev), `{}`, 200)
	if a := auditActions(t, f, f.B.ID); a["guestlife.transfer_task.open"] != 1 || a["jml.leaver"] != 1 {
		t.Errorf("audit = %v", a)
	}
	ts := guestsJSON[glTasks](t, h, admin, "GET", "/api/guest-lifecycle/tasks", "", 200)
	if len(ts.Tasks) != 1 || ts.Tasks[0].TaskKind != "sponsor_transfer" || ts.Tasks[0].SponsorshipID != seeded || ts.Tasks[0].Trigger != "leaver" ||
		!ts.Tasks[0].CanAct || ts.Tasks[0].Sponsor == nil || ts.Tasks[0].Sponsor.ID != carol || ts.Tasks[0].Deadline == nil ||
		!ts.Tasks[0].Deadline.Equal(storetest.Now.AddDate(0, 0, 10)) { // the sponsorship ends in 10 days, before the 14-day deadline
		t.Fatalf("tasks = %+v", ts)
	}
	task := ts.Tasks[0].TaskID
	if ts := guestsJSON[glTasks](t, h, aliceUser, "GET", "/api/guest-lifecycle/tasks", "", 200); len(ts.Tasks) != 0 {
		t.Errorf("a person who may not decide sees %+v", ts)
	}
	guestsDo(t, h, aliceUser, "POST", "/api/guest-lifecycle/tasks/"+task+"/resolve", `{"action":"accept"}`, 404)
	guestsDo(t, h, admin, "POST", "/api/guest-lifecycle/tasks/"+task+"/resolve", `{"action":"bogus"}`, 422)
	guestsDo(t, h, admin, "POST", "/api/guest-lifecycle/tasks/"+task+"/resolve", `{"action":"accept","x":1}`, 422)
	// an admin who is nobody's identity cannot take a sponsorship over: they ask someone who can sponsor
	guestsDo(t, h, admin, "POST", "/api/guest-lifecycle/tasks/"+task+"/resolve", `{"action":"accept"}`, 422)
	res := guestsJSON[struct {
		Status  string  `json:"status"`
		Outcome *string `json:"outcome"`
	}](t, h, bobAdmin, "POST", "/api/guest-lifecycle/tasks/"+task+"/resolve", `{"action":"accept"}`, 200)
	if res.Status != "done" || res.Outcome == nil || *res.Outcome != "transferred" {
		t.Errorf("resolved = %+v", res)
	}
	sp := guestsJSON[sponsorshipView](t, h, admin, "GET", "/api/sponsorships/"+seeded, "", 200)
	if sp.Sponsor.ID != b["bob"] || sp.Status != "active" {
		t.Errorf("sponsorship = %+v", sp)
	}
	guestsDo(t, h, bobAdmin, "POST", "/api/guest-lifecycle/tasks/"+task+"/resolve", `{"action":"accept"}`, 409)
	if o := guestsJSON[glOverview](t, h, admin, "GET", "/api/guest-lifecycle", "", 200); o.Counts["pending_transfer"] != 0 {
		t.Errorf("counts = %+v", o.Counts)
	}
}

var renewLinkRE = regexp.MustCompile(`/renew#t=([A-Za-z0-9_-]{43})`)

func (e *claimEnv) renewalRequest(slug, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/public/t/"+slug+"/guest/renewal-request", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", claimOrigin)
	return serve(e.h, req)
}

// The guest's reminder carries a one-time link; using it opens a task for the
// sponsor, and every answer of the public route is the same.
func TestGuestLifecycleAPI_RenewalRequestEndToEnd(t *testing.T) {
	e := newClaimEnv(t, claimOpts{})
	inv := e.invite("gwen@guest.example", "contractor")
	guest := inv.Guest.ID
	if err := e.db.InTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		if err := tx.SetIdentityStatus(guest, "active"); err != nil {
			return err
		}
		if err := tx.PutIdentityAssurance(&store.Assurance{IdentityID: guest, IAL: 1, AAL: 2, Source: "claim", RecordedAt: e.clk.now()}); err != nil {
			return err
		}
		affs, err := tx.AffiliationsFor(guest)
		for _, a := range affs {
			if a.Status == store.AffPending {
				if err := tx.ActivateAffiliation(a.ID); err != nil {
					return err
				}
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// the sweep sends the reminders: the sponsor's, and the guest's with the link
	var sent guestlife.RemindResult
	if err := e.db.InTenant(context.Background(), e.tenant, func(tx *store.TenantTx) (err error) {
		sent, err = e.srv.guestLife.Remind(tx, e.clk.now())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if sent.Sponsor != 1 || sent.Guest != 1 {
		t.Fatalf("reminders = %+v", sent)
	}
	e.dispatch()
	var token string
	for _, m := range e.mail.all() {
		if m.To == "gwen@guest.example" {
			if x := renewLinkRE.FindStringSubmatch(m.Body); x != nil {
				token = x[1]
			}
		}
	}
	if token == "" {
		t.Fatalf("the guest's reminder holds no renewal link: %+v", e.mail.all())
	}
	if strings.Contains(e.logs.String(), token) {
		t.Error("the renewal token is in the logs")
	}
	// a second sweep sends nothing again
	if err := e.db.InTenant(context.Background(), e.tenant, func(tx *store.TenantTx) (err error) {
		sent, err = e.srv.guestLife.Remind(tx, e.clk.now())
		return err
	}); err != nil || sent.Sponsor != 0 || sent.Guest != 0 {
		t.Errorf("second sweep = %+v, %v", sent, err)
	}
	good := e.renewalRequest(e.slug, `{"token":"`+token+`"}`)
	bad := e.renewalRequest(e.slug, `{"token":"`+strings.Repeat("A", 43)+`"}`)
	short := e.renewalRequest(e.slug, `{"token":"x"}`)
	unknown := e.renewalRequest("no-such-tenant", `{"token":"`+token+`"}`)
	replay := e.renewalRequest(e.slug, `{"token":"`+token+`"}`)
	for name, rec := range map[string]*httptest.ResponseRecorder{"good": good, "bad": bad, "short": short, "unknown tenant": unknown, "replay": replay} {
		if rec.Code != http.StatusAccepted || rec.Body.String() != good.Body.String() || rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s answers %d %s", name, rec.Code, rec.Body)
		}
	}
	if !strings.Contains(good.Body.String(), `"received"`) {
		t.Errorf("body = %s", good.Body)
	}
	// a wrong origin is refused like every claim POST
	req := httptest.NewRequest("POST", "/public/t/"+e.slug+"/guest/renewal-request", strings.NewReader(`{"token":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	if rec := serve(e.h, req); rec.Code != http.StatusForbidden {
		t.Errorf("a foreign origin: %d", rec.Code)
	}
	ts := guestsJSON[glTasks](t, e.h, e.sponsor, "GET", "/api/guest-lifecycle/tasks", "", 200)
	if len(ts.Tasks) != 1 || ts.Tasks[0].TaskKind != "renewal_request" || ts.Tasks[0].Guest.ID != guest || !ts.Tasks[0].CanAct {
		t.Fatalf("the sponsor's tasks = %+v", ts)
	}
	// the sponsor renews through the usual route: the request is done
	renew := fmt.Sprintf(`{"ends_at":%q,"justification":"asked to stay"}`, e.clk.now().AddDate(0, 0, 40).Format(time.RFC3339))
	guestsDo(t, e.h, e.sponsor, "POST", "/api/sponsorships/"+inv.ID+"/renew", renew, 200)
	if ts := guestsJSON[glTasks](t, e.h, e.sponsor, "GET", "/api/guest-lifecycle/tasks", "", 200); len(ts.Tasks) != 0 {
		t.Errorf("tasks after the renewal = %+v", ts)
	}
	if a := e.actions(); a["guestlife.renewal_requested"] != 1 || a["guestlife.reminder"] != 2 {
		t.Errorf("audit = %v", a)
	}
}

func (e *claimEnv) actions() map[string]int {
	out := map[string]int{}
	if err := e.db.ReadTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		evs, err := tx.AuditLog(-1)
		for _, ev := range evs {
			out[ev.Action]++
		}
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
	return out
}

// A held renewal is shown on the sponsorship: the access did not extend.
func TestGuestLifecycleAPI_RenewalHeldForStepUp(t *testing.T) {
	f := storetest.TwoTenants(t)
	seeded := seedSponsorships(t, f)[f.B.ID]
	h := newIsolationServer(f).Handler()
	carol := reqLogin(t, f, "carol@b.example", []auth.Role{auth.RoleViewer}, "carol")
	admin := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	if err := f.DB.InTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		gp, err := tx.GuestPopulation("guest")
		if err != nil {
			return err
		}
		gp.DefaultIAL = 2
		return tx.PutGuestPopulation(gp)
	}); err != nil {
		t.Fatal(err)
	}
	to := storetest.Now.AddDate(0, 0, 25)
	v := guestsJSON[sponsorshipView](t, h, carol, "POST", "/api/sponsorships/"+seeded+"/renew",
		fmt.Sprintf(`{"ends_at":%q,"justification":"again"}`, to.Format(time.RFC3339)), 200)
	if v.Stepup == nil || v.Stepup.RequiredIAL != 2 || !v.Stepup.RequestedEndsAt.Equal(to) || !v.EndsAt.Equal(storetest.Now.AddDate(0, 0, 10)) {
		t.Fatalf("held renewal = %+v", v)
	}
	if o := guestsJSON[glOverview](t, h, admin, "GET", "/api/guest-lifecycle", "", 200); o.Counts["stepup_required"] != 1 {
		t.Errorf("counts = %v", o.Counts)
	}
	type items struct {
		Items []guestlife.Item `json:"items"`
	}
	if it := guestsJSON[items](t, h, admin, "GET", "/api/guest-lifecycle/items?bucket=stepup_required", "", 200); len(it.Items) != 1 || it.Items[0].RequiredIAL != 2 {
		t.Errorf("stepup items = %+v", it)
	}
}

// Tenant B reaches none of tenant A's tasks: A's id answers as one that does not exist.
func TestGuestLifecycleAPI_CrossTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedSponsorships(t, f)
	task := uuid.NewString()
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(tx *store.TenantTx) error {
		dl := storetest.Now.AddDate(0, 0, 3)
		return tx.InsertLifecycleTask(&store.LifecycleTask{ID: task, Kind: store.TaskSponsorTransfer, SponsorshipID: ids[f.A.ID],
			SubjectIdentityID: f.A.IDs["carol"], Trigger: store.TaskTriggerLeaver, Deadline: &dl, CreatedAt: storetest.Now})
	}); err != nil {
		t.Fatal(err)
	}
	h := newIsolationServer(f).Handler()
	admin := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "bob")
	before := storetest.Dump(t, f.DB, f.A.ID)
	missing := uuid.NewString()
	for _, action := range []string{"accept", "decline", "keep", "confirm", "dismiss"} {
		body := fmt.Sprintf(`{"action":%q}`, action)
		cross := reqDo(h, admin, "POST", "/api/guest-lifecycle/tasks/"+task+"/resolve", body)
		none := reqDo(h, admin, "POST", "/api/guest-lifecycle/tasks/"+missing+"/resolve", body)
		if cross.Code != 404 || cross.Code != none.Code ||
			strings.ReplaceAll(cross.Body.String(), task, "<id>") != strings.ReplaceAll(none.Body.String(), missing, "<id>") || leaks(cross.Body.String()) {
			t.Errorf("%s: A's id: %d %s\nmissing: %d %s", action, cross.Code, cross.Body, none.Code, none.Body)
		}
	}
	// B's lists show none of A's rows
	for _, path := range []string{"/api/guest-lifecycle/tasks", "/api/guest-lifecycle/items?bucket=pending_transfer", "/api/guest-lifecycle"} {
		rec := reqDo(h, admin, "GET", path, "")
		if rec.Code != 200 || leaks(rec.Body.String()) || strings.Contains(rec.Body.String(), task) {
			t.Errorf("GET %s: %d %s", path, rec.Code, rec.Body)
		}
	}
	if o := guestsJSON[glOverview](t, h, admin, "GET", "/api/guest-lifecycle", "", 200); o.Counts["pending_transfer"] != 0 {
		t.Errorf("tenant A's task is counted in B: %v", o.Counts)
	}
	if after := storetest.Dump(t, f.DB, f.A.ID); after != before {
		t.Error("calls from B changed A")
	}
}
