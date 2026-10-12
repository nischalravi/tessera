package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

type inboxBody struct {
	Unread int `json:"unread"`
	Items  []struct {
		ID      string  `json:"id"`
		Kind    string  `json:"kind"`
		Subject string  `json:"subject"`
		Link    string  `json:"link"`
		ReadAt  *string `json:"read_at"`
	} `json:"items"`
}

func getInbox(t *testing.T, h http.Handler, l authtest.Login, q string) inboxBody {
	t.Helper()
	rec := reqDo(h, l, "GET", "/api/notifications"+q, "")
	if rec.Code != 200 {
		t.Fatalf("inbox: %d %s", rec.Code, rec.Body)
	}
	var b inboxBody
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	return b
}

// The request flow shows up in the bell: the decider hears a request needs
// them, the requester hears it was approved, each can mark only their own
// notifications read, and the audit ledger records it.
func TestNotificationsAPI_RequestFlowAndInbox(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	admin := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	alice := reqLogin(t, f, "alice@b.example", []auth.Role{auth.RoleViewer}, "alice")

	rec := reqDo(h, admin, "PUT", fmt.Sprintf("/api/catalog/items/%d", f.B.IDs["group:okta:platform"]), `{"requestable":true,"risk":"medium"}`)
	var item catalogEntry
	_ = json.Unmarshal(rec.Body.Bytes(), &item)
	if rec.Code != 200 || item.ID == nil {
		t.Fatalf("put item: %d %s", rec.Code, rec.Body)
	}
	if b := getInbox(t, h, admin, ""); b.Unread != 0 || len(b.Items) != 0 {
		t.Fatalf("a fresh inbox = %+v", b)
	}
	rec = reqDo(h, alice, "POST", "/api/requests",
		fmt.Sprintf(`{"beneficiary_ids":[%d],"catalog_item_ids":["%s"],"justification":"platform rotation"}`, f.B.IDs["alice"], *item.ID))
	var sub struct {
		Lines []lineView `json:"lines"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &sub)
	if rec.Code != 201 || len(sub.Lines) != 1 {
		t.Fatalf("submit: %d %s", rec.Code, rec.Body)
	}
	b := getInbox(t, h, admin, "")
	if b.Unread != 1 || len(b.Items) != 1 || b.Items[0].Kind != notify.KindApprovalNeeded || b.Items[0].Link != "/inbox" {
		t.Fatalf("the decider's inbox = %+v", b)
	}
	if b := getInbox(t, h, alice, ""); len(b.Items) != 0 {
		t.Errorf("the requester was told her own request needs approval: %+v", b)
	}
	if rec := reqDo(h, admin, "POST", "/api/requests/"+sub.Lines[0].ID+"/approve", `{}`); rec.Code != 200 {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body)
	}
	ab := getInbox(t, h, alice, "?unread=1")
	if ab.Unread != 1 || len(ab.Items) != 1 || ab.Items[0].Kind != notify.KindRequestApproved {
		t.Fatalf("the requester's inbox = %+v", ab)
	}

	// the decider names the requester's notification: ignored, it stays unread
	rec = reqDo(h, admin, "POST", "/api/notifications/read", fmt.Sprintf(`{"ids":["%s"]}`, ab.Items[0].ID))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"marked":0`) {
		t.Errorf("marking another user's notification: %d %s", rec.Code, rec.Body)
	}
	if getInbox(t, h, alice, "").Unread != 1 {
		t.Error("another user marked alice's notification read")
	}
	rec = reqDo(h, alice, "POST", "/api/notifications/read", fmt.Sprintf(`{"ids":["%s"]}`, ab.Items[0].ID))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"marked":1`) || !strings.Contains(rec.Body.String(), `"unread":0`) {
		t.Errorf("mark read: %d %s", rec.Code, rec.Body)
	}
	if b := getInbox(t, h, alice, "?unread=1"); len(b.Items) != 0 {
		t.Errorf("unread after marking = %+v", b)
	}
	if rec := reqDo(h, admin, "POST", "/api/notifications/read", `{"all":true}`); rec.Code != 200 || getInbox(t, h, admin, "").Unread != 0 {
		t.Errorf("mark all: %d %s", rec.Code, rec.Body)
	}
	for _, body := range []string{``, `{}`, `{"ids":[]}`, `{"ids":["a"],"x":1}`} {
		if rec := reqDo(h, alice, "POST", "/api/notifications/read", body); rec.Code < 400 || rec.Code >= 500 {
			t.Errorf("read body %q: %d %s", body, rec.Code, rec.Body)
		}
	}
	for _, q := range []string{"?limit=0", "?limit=x", "?limit=100000"} {
		if rec := reqDo(h, alice, "GET", "/api/notifications"+q, ""); rec.Code != 422 {
			t.Errorf("GET %s: %d", q, rec.Code)
		}
	}
	got := reqAuditActions(t, f, f.B.ID)
	if got["notification.read"] != 2 { // alice's one, the admin's all (the ignored call changed nothing)
		t.Errorf("notification.read events = %d, want 2 (%v)", got["notification.read"], got)
	}
}

func TestNotificationsAPI_Preferences(t *testing.T) {
	f := storetest.TwoTenants(t)
	srv := newIsolationServer(f)
	srv.cfg.EmailMode = config.MailDev
	h := srv.Handler()
	alice := reqLogin(t, f, "alice@b.example", []auth.Role{auth.RoleViewer}, "alice")
	pat := reqLogin(t, f, "pat@b.example", []auth.Role{auth.RoleOperator}, "")

	type view struct {
		EmailAvailable bool `json:"email_available"`
		DevSink        bool `json:"email_dev_sink"`
		Kinds          []struct {
			Kind      string `json:"kind"`
			Mandatory bool   `json:"mandatory"`
			Channel   string `json:"channel"`
			Default   string `json:"default"`
		} `json:"kinds"`
	}
	get := func(l authtest.Login) (v view) {
		rec := reqDo(h, l, "GET", "/api/notifications/preferences", "")
		if rec.Code != 200 {
			t.Fatalf("prefs: %d %s", rec.Code, rec.Body)
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &v)
		return v
	}
	channel := func(v view, kind string) string {
		for _, k := range v.Kinds {
			if k.Kind == kind {
				return k.Channel
			}
		}
		return "?"
	}
	v := get(alice)
	if !v.EmailAvailable || !v.DevSink || len(v.Kinds) != len(notify.Kinds) || channel(v, notify.KindRequestApproved) != notify.ChannelInApp {
		t.Fatalf("defaults = %+v", v)
	}
	rec := reqDo(h, alice, "PUT", "/api/notifications/preferences", `{"prefs":{"request.approved":"digest","review.reminder":"off"}}`)
	if rec.Code != 200 {
		t.Fatalf("put: %d %s", rec.Code, rec.Body)
	}
	v = get(alice)
	if channel(v, notify.KindRequestApproved) != "digest" || channel(v, notify.KindReviewReminder) != "off" {
		t.Errorf("saved = %+v", v)
	}
	if channel(get(pat), notify.KindRequestApproved) != notify.ChannelInApp {
		t.Error("alice's preference is another user's")
	}
	for name, body := range map[string]string{
		"security cannot be off": `{"prefs":{"security.alert":"off"}}`,
		"unknown kind":           `{"prefs":{"nope":"off"}}`,
		"unknown channel":        `{"prefs":{"request.approved":"sms"}}`,
		"empty":                  `{"prefs":{}}`,
	} {
		if rec := reqDo(h, alice, "PUT", "/api/notifications/preferences", body); rec.Code != 422 {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	if !strings.Contains(reqDo(h, alice, "PUT", "/api/notifications/preferences", `{"prefs":{"security.alert":"off"}}`).Body.String(), "kind_mandatory") {
		t.Error("the refusal does not say why")
	}
	if got := reqAuditActions(t, f, f.B.ID); got["notification.prefs.put"] != 1 {
		t.Errorf("prefs audit events = %d, want 1", got["notification.prefs.put"])
	}
	srv.cfg.EmailMode = config.MailOff
	if v := get(alice); v.EmailAvailable {
		t.Error("email reported available with email off")
	}
}

// Tenant B cannot read, count or mark tenant A's notifications.
func TestNotificationsAPI_CrossTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	ua := signIn(t, f.DB, f.A.ID, authtest.User{Email: "a1@a.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, storetest.Now)
	var aID string
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		rows, err := notify.Plan(c, storetest.Now, notify.Message{Kind: notify.KindRequestApproved, Key: "x", Subject: "A's secret " + storetest.Sentinel, Body: "b"},
			notify.Recipient{UserID: ua.UserID.String()})
		if err != nil || len(rows) != 1 {
			t.Fatalf("plan = %v, %v", rows, err)
		}
		aID = rows[0].ID
		_, err = notify.Write(c, rows)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if b := getInbox(t, h, ua, ""); b.Unread != 1 || len(b.Items) != 1 {
		t.Fatalf("A's own inbox = %+v", b)
	}
	admin := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	rec := reqDo(h, admin, "GET", "/api/notifications", "")
	if leaks(rec.Body.String()) || strings.Contains(rec.Body.String(), aID) {
		t.Errorf("B's inbox leaks A: %s", rec.Body)
	}
	cross := reqDo(h, admin, "POST", "/api/notifications/read", fmt.Sprintf(`{"ids":["%s"]}`, aID))
	missing := reqDo(h, admin, "POST", "/api/notifications/read", `{"ids":["00000000-0000-4000-8000-00000000dead"]}`)
	if cross.Code != 200 || cross.Body.String() != missing.Body.String() {
		t.Errorf("marking A's id: %d %s, a missing id: %s", cross.Code, cross.Body, missing.Body)
	}
	if b := getInbox(t, h, ua, ""); b.Unread != 1 {
		t.Error("B marked A's notification read")
	}
}

// seedEmailMessage writes a notification and its delivery record (with one
// deferred attempt) in a tenant and returns the message id.
func seedEmailMessage(t testing.TB, f *storetest.Fixture, tenant storetest.Tenant, status string) string {
	t.Helper()
	var id string
	if err := f.DB.InTenant(context.Background(), tenant.ID, func(c *store.TenantTx) error {
		u := &store.PlatformUser{DisplayName: "Recipient", CreatedAt: storetest.Now}
		if err := c.InsertPlatformUser(u); err != nil {
			return err
		}
		uid, email, now := u.ID.String(), "to@"+tenant.Slug+".example", storetest.Now
		nid := "n-" + uid
		if _, err := c.InsertNotification(&store.Notification{ID: nid, UserID: &uid, Email: &email, Kind: notify.KindApprovalNeeded,
			Subject: "subject " + tenant.Slug, Body: "b", DedupeKey: nid, InApp: true, CreatedAt: now, Delivery: store.DeliveryDead}); err != nil {
			return err
		}
		id = "m-" + uid
		if err := c.EnsureEmailMessage(&store.EmailMessage{ID: id, NotificationID: nid, Kind: notify.KindApprovalNeeded, Recipient: email,
			Subject: "subject " + tenant.Slug, CreatedAt: now}); err != nil {
			return err
		}
		m, err := c.EmailMessage(id)
		if err != nil {
			return err
		}
		m.Status, m.AttemptCount, m.UpdatedAt = status, 1, now
		m.Attempts = json.RawMessage(`[{"outcome":"deferred","steps":[{"command":"RCPT TO:<` + email + `>","reply":"4.3.0 later","code":451,"enhanced":"4.3.0"}]}]`)
		return c.SaveEmailMessage(m)
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestEmailAPI_ListDetailRetryAndPermissions(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	tadmin := reqLogin(t, f, "ta@b.example", []auth.Role{auth.RoleTenantAdmin}, "")
	auditor := reqLogin(t, f, "au@b.example", []auth.Role{auth.RoleAuditor}, "")
	viewer := reqLogin(t, f, "v@b.example", []auth.Role{auth.RoleViewer}, "")
	deferred := seedEmailMessage(t, f, f.B, store.EmailDeferred)
	accepted := seedEmailMessage(t, f, f.B, store.EmailAccepted)

	for _, who := range []authtest.Login{tadmin, auditor} {
		rec := reqDo(h, who, "GET", "/api/email/messages", "")
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), deferred) || !strings.Contains(rec.Body.String(), accepted) {
			t.Fatalf("list: %d %s", rec.Code, rec.Body)
		}
		if strings.Contains(rec.Body.String(), `"attempts"`) {
			t.Error("the list carries transcripts")
		}
	}
	if rec := reqDo(h, viewer, "GET", "/api/email/messages", ""); rec.Code != 403 {
		t.Errorf("a viewer listed the delivery log: %d", rec.Code)
	}
	var list struct {
		Messages []struct{ ID, Status string } `json:"messages"`
	}
	rec := reqDo(h, tadmin, "GET", "/api/email/messages?status=deferred&kind=request.approval_needed&recipient=TO@TENANT-B", "")
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if rec.Code != 200 || len(list.Messages) != 1 || list.Messages[0].ID != deferred {
		t.Errorf("filtered list: %d %s", rec.Code, rec.Body)
	}
	for _, q := range []string{"?status=nope", "?limit=0", "?limit=9999"} {
		if rec := reqDo(h, tadmin, "GET", "/api/email/messages"+q, ""); rec.Code != 422 {
			t.Errorf("GET %s: %d", q, rec.Code)
		}
	}
	rec = reqDo(h, auditor, "GET", "/api/email/messages/"+deferred, "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"code":451`) || !strings.Contains(rec.Body.String(), `"enhanced":"4.3.0"`) ||
		!strings.Contains(rec.Body.String(), `"retryable":true`) {
		t.Errorf("detail: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, tadmin, "GET", "/api/email/messages/"+accepted, ""); !strings.Contains(rec.Body.String(), `"retryable":false`) {
		t.Errorf("accepted detail: %s", rec.Body)
	}
	// retry needs email.manage
	if rec := reqDo(h, auditor, "POST", "/api/email/messages/"+deferred+"/retry", `{}`); rec.Code != 403 {
		t.Errorf("an auditor retried: %d", rec.Code)
	}
	if rec := reqDo(h, tadmin, "POST", "/api/email/messages/"+accepted+"/retry", `{}`); rec.Code != 409 || !strings.Contains(rec.Body.String(), "not_retryable") {
		t.Errorf("retry of an accepted message: %d %s", rec.Code, rec.Body)
	}
	rec = reqDo(h, tadmin, "POST", "/api/email/messages/"+deferred+"/retry", `{}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"status":"queued"`) {
		t.Fatalf("retry: %d %s", rec.Code, rec.Body)
	}
	if got := reqAuditActions(t, f, f.B.ID); got["email.message.retry"] != 1 {
		t.Errorf("retry audit events = %d", got["email.message.retry"])
	}
}

func TestEmailAPI_CrossTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	aMsg := seedEmailMessage(t, f, f.A, store.EmailDeferred)
	admin := reqLogin(t, f, "ta@b.example", []auth.Role{auth.RoleTenantAdmin}, "")
	if rec := reqDo(h, admin, "GET", "/api/email/messages", ""); leaks(rec.Body.String()) || strings.Contains(rec.Body.String(), aMsg) || strings.Contains(rec.Body.String(), "@tenant-a.example") {
		t.Errorf("B's list leaks A: %s", rec.Body)
	}
	missing := "00000000-0000-4000-8000-00000000dead"
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/api/email/messages/%s", ""}, {"POST", "/api/email/messages/%s/retry", `{}`},
	} {
		cross := reqDo(h, admin, c.method, fmt.Sprintf(c.path, aMsg), c.body)
		gone := reqDo(h, admin, c.method, fmt.Sprintf(c.path, missing), c.body)
		if cross.Code != 404 || strings.ReplaceAll(cross.Body.String(), aMsg, "<id>") != strings.ReplaceAll(gone.Body.String(), missing, "<id>") {
			t.Errorf("%s %s: A's id %d %s, missing %d %s", c.method, c.path, cross.Code, cross.Body, gone.Code, gone.Body)
		}
	}
	// A's message is untouched
	aAdmin := signIn(t, f.DB, f.A.ID, authtest.User{Email: "ta@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	if rec := reqDo(h, aAdmin, "GET", "/api/email/messages/"+aMsg, ""); !strings.Contains(rec.Body.String(), `"status":"deferred"`) {
		t.Errorf("A's message changed: %s", rec.Body)
	}
}
