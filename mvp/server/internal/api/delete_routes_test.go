package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/alerts"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/siem"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Issue #963: DELETE routes for alert channels, SIEM sinks, group loaders and connections. Each needs the
// create permission and a fresh sign-in, refuses a row that is still enabled, audits in the same transaction
// and removes the sealed credential with the row.

func deleteAuditCount(t *testing.T, db *store.DB, tn tenancy.ID, action string) int {
	t.Helper()
	n := 0
	if err := db.ReadTenant(context.Background(), tn, func(tx *store.TenantTx) error {
		evs, err := tx.AuditEvents(store.AuditFilter{})
		for _, e := range evs {
			if e.Action == action {
				n++
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func deleteStaleLogin(t *testing.T, f *storetest.Fixture, tn tenancy.ID, role auth.Role) authtest.Login {
	t.Helper()
	return signIn(t, f.DB, tn, authtest.User{Email: "stale@b.example", Roles: []auth.Role{role}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}, storetest.Now)
}

// TestDeleteAlertChannelAPI: a channel is how security alerts reach people, so disabling it, deleting it, sending it
// to other recipients and raising its min_severity are two-admin change requests (issue #968). The routes answer 409
// two_admin_change_required, the requester cannot approve their own request, and an approved one is applied and audited
// (with the change id) in the same transaction.
func TestDeleteAlertChannelAPI(t *testing.T) {
	e := newPrivEnv(t)
	sealer, err := seal.New(seal.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	e.srv.cfg.Alerts = &alerts.Service{DB: e.f.DB, Sealer: sealer, Mail: alerts.LogMailer{}}
	admin2 := e.as("admin2", []auth.Role{auth.RoleTenantAdmin}, nil)
	op := e.as("op", []auth.Role{auth.RoleOperator}, nil)
	stale := deleteStaleLogin(t, e.f, e.f.B.ID, auth.RoleTenantAdmin)
	h := e.srv.Handler()

	hook := e.admin.call("POST", "/api/alerts/channels", `{"name":"Hook","kind":"webhook","target":"https://hooks.slack.com/services/T0/B0/x","min_severity":"high"}`, 201)
	mail := e.admin.call("POST", "/api/alerts/channels", `{"name":"Mail","kind":"email","target":"soc@b.example","min_severity":"medium"}`, 201)
	hid, mid := hook["id"].(string), mail["id"].(string)
	chanOf := func(id string) (*store.AlertChannel, error) {
		var c *store.AlertChannel
		err := e.f.DB.ReadTenant(context.Background(), e.f.B.ID, func(tx *store.TenantTx) error {
			var err error
			c, err = tx.AlertChannel(id)
			return err
		})
		return c, err
	}
	if c, err := chanOf(hid); err != nil || len(c.SecretSealed) == 0 {
		t.Fatalf("the webhook has no sealed secret to delete: %v", err)
	}
	file := func(c grpClient, typ, payload string, want int) map[string]any {
		return c.call("POST", "/api/admin/change-requests", `{"type":"`+typ+`","payload":`+payload+`}`, want)
	}

	// access control on the route
	if rec := op.do("DELETE", "/api/alerts/channels/"+hid, ""); rec.Code != 403 {
		t.Errorf("operator: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(h, stale, "DELETE", "/api/alerts/channels/"+hid, ""); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Errorf("stale sign-in: %d %s", rec.Code, rec.Body)
	}
	e.admin.call("DELETE", "/api/alerts/channels/nope", "", 404)

	// one admin can do none of the four
	for _, c := range []struct{ name, method, path, body, typ string }{
		{"delete", "DELETE", "/api/alerts/channels/" + hid, "", "alerts.channel.delete"},
		{"disable", "PUT", "/api/alerts/channels/" + hid, `{"name":"Hook","enabled":false}`, "alerts.channel.disable"},
		{"recipients", "PUT", "/api/alerts/channels/" + mid, `{"name":"Mail","target":"other@b.example"}`, "alerts.channel.target"},
		{"min_severity", "PUT", "/api/alerts/channels/" + mid, `{"name":"Mail","min_severity":"critical"}`, "alerts.channel.severity"},
		{"webhook url", "PUT", "/api/alerts/channels/" + hid, `{"name":"Hook","target":"https://hooks.slack.com/services/T0/B0/y"}`, "config.proposal"},
	} {
		got := e.admin.call(c.method, c.path, c.body, 409)
		if errCode(got) != "two_admin_change_required" || got["change_type"] != c.typ {
			t.Errorf("%s: %v", c.name, got)
		}
	}
	if c, err := chanOf(hid); err != nil || !c.Enabled || c.Target != "https://hooks.slack.com/services/T0/B0/x" {
		t.Fatalf("one admin changed the webhook: %+v %v", c, err)
	}
	if c, err := chanOf(mid); err != nil || c.Target != "soc@b.example" || c.MinSeverity != "medium" {
		t.Fatalf("one admin changed the email channel: %+v %v", c, err)
	}

	// what stays a single-admin change: rename, lower min_severity, same recipients in another spelling
	e.admin.call("PUT", "/api/alerts/channels/"+mid, `{"name":"Mail 2","target":" soc@b.example ","min_severity":"low"}`, 200)

	// each request must name a real, changing object
	file(e.admin, "alerts.channel.disable", `{"channel_id":"nope"}`, 422)
	file(e.admin, "alerts.channel.target", `{"channel_id":"`+mid+`","target":"soc@b.example"}`, 422)
	file(e.admin, "alerts.channel.target", `{"channel_id":"`+mid+`","target":"not an address"}`, 422)
	file(e.admin, "alerts.channel.target", `{"channel_id":"`+hid+`","target":"https://hooks.slack.com/services/T0/B0/y"}`, 422) // webhook URLs go by proposal
	file(e.admin, "alerts.channel.severity", `{"channel_id":"`+mid+`","min_severity":"low"}`, 422)
	file(e.admin, "alerts.channel.severity", `{"channel_id":"`+mid+`","min_severity":"bogus"}`, 422)

	// disable
	ch := file(e.admin, "alerts.channel.disable", `{"channel_id":"`+hid+`"}`, 201)
	if ch["status"] != "pending_approval" || ch["two_person"] != true {
		t.Fatalf("disable request = %v", ch)
	}
	if c, _ := chanOf(hid); !c.Enabled {
		t.Fatal("the channel went off before the approval")
	}
	approveChange(t, admin2, e.admin, ch)
	if c, err := chanOf(hid); err != nil || c.Enabled {
		t.Fatalf("after the approved disable: %+v %v", c, err)
	}
	if n := deleteAuditCount(t, e.f.DB, e.f.B.ID, "alert.channel.disabled"); n != 1 {
		t.Errorf("alert.channel.disabled audited %d times", n)
	}
	file(e.admin, "alerts.channel.disable", `{"channel_id":"`+hid+`"}`, 422) // already off
	e.admin.call("PUT", "/api/alerts/channels/"+hid, `{"name":"Hook","enabled":false}`, 200)

	// recipients and min_severity
	ch = file(e.admin, "alerts.channel.target", `{"channel_id":"`+mid+`","target":"a@b.example, b@b.example"}`, 201)
	approveChange(t, admin2, e.admin, ch)
	if c, _ := chanOf(mid); c.Target != "a@b.example, b@b.example" {
		t.Errorf("recipients after the approved change: %q", c.Target)
	}
	ch = file(e.admin, "alerts.channel.severity", `{"channel_id":"`+mid+`","min_severity":"critical"}`, 201)
	approveChange(t, admin2, e.admin, ch)
	if c, _ := chanOf(mid); c.MinSeverity != "critical" {
		t.Errorf("min_severity after the approved change: %q", c.MinSeverity)
	}
	if n := deleteAuditCount(t, e.f.DB, e.f.B.ID, "alert.channel.updated"); n < 4 {
		t.Errorf("alert.channel.updated audited %d times", n)
	}

	// delete: enabled or not; the sealed secret goes with the row
	ch = file(e.admin, "alerts.channel.delete", `{"channel_id":"`+hid+`"}`, 201)
	if _, err := chanOf(hid); err != nil {
		t.Fatalf("the channel went before the approval: %v", err)
	}
	approveChange(t, admin2, e.admin, ch)
	if _, err := chanOf(hid); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("channel and its sealed secret remain: %v", err)
	}
	ch = file(e.admin, "alerts.channel.delete", `{"channel_id":"`+mid+`"}`, 201) // still enabled
	approveChange(t, admin2, e.admin, ch)
	if _, err := chanOf(mid); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("enabled channel remains: %v", err)
	}
	if n := deleteAuditCount(t, e.f.DB, e.f.B.ID, "alert.channel.deleted"); n != 2 {
		t.Errorf("alert.channel.deleted audited %d times", n)
	}
}

func TestDeleteAlertChannelAPI_CrossTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := alertsServer(t, f)
	now := storetest.Now
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(tx *store.TenantTx) error {
		return tx.InsertAlertChannel(&store.AlertChannel{ID: "chan-a", Name: "A", Kind: "email", Target: "a@a.example", MinSeverity: "low",
			CreatedAt: now, UpdatedAt: now})
	}); err != nil {
		t.Fatal(err)
	}
	admin := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, now)
	before := storetest.Dump(t, f.DB, f.A.ID)
	got, want := alertsDo(h, admin, "DELETE", "/api/alerts/channels/chan-a", ""), alertsDo(h, admin, "DELETE", "/api/alerts/channels/nope", "")
	if got.Code != 404 || got.Body.String() != want.Body.String() {
		t.Errorf("cross-tenant: %d %s; missing: %d %s", got.Code, got.Body, want.Code, want.Body)
	}
	if storetest.Dump(t, f.DB, f.A.ID) != before {
		t.Error("tenant A changed")
	}
}

// TestAlertChannelChangeRequests_CrossTenant: another tenant's channel answers like a missing id for every alert
// channel change request and for the PUT, and is untouched (issue #968).
func TestAlertChannelChangeRequests_CrossTenant(t *testing.T) {
	e := newPrivEnv(t)
	now := storetest.Now
	if err := e.f.DB.InTenant(context.Background(), e.f.A.ID, func(tx *store.TenantTx) error {
		return tx.InsertAlertChannel(&store.AlertChannel{ID: "chan-a", Name: "A", Kind: "email", Target: "a@a.example", MinSeverity: "low",
			Enabled: true, CreatedAt: now, UpdatedAt: now})
	}); err != nil {
		t.Fatal(err)
	}
	before := storetest.Dump(t, e.f.DB, e.f.A.ID)
	e.admin.call("PUT", "/api/alerts/channels/chan-a", `{"name":"A","enabled":false}`, 404)
	for _, c := range []struct{ typ, payload string }{
		{"alerts.channel.disable", `{"channel_id":"chan-a"}`},
		{"alerts.channel.delete", `{"channel_id":"chan-a"}`},
		{"alerts.channel.target", `{"channel_id":"chan-a","target":"x@b.example"}`},
		{"alerts.channel.severity", `{"channel_id":"chan-a","min_severity":"critical"}`},
	} {
		e.admin.call("POST", "/api/admin/change-requests", `{"type":"`+c.typ+`","payload":`+c.payload+`}`, 422)
	}
	if storetest.Dump(t, e.f.DB, e.f.A.ID) != before {
		t.Error("tenant A changed")
	}
}

// TestAlertChannelChangeRequests_StaleSelfAndSecrets (issue #968 review): a request is checked again when approved, so one
// the tenant has moved past applies nothing; the requester is refused with self_approval_refused; a recipient list the
// apply would refuse is refused when filed; and a webhook URL's token is never stored, echoed or audited on the way to
// the 409.
func TestAlertChannelChangeRequests_StaleSelfAndSecrets(t *testing.T) {
	e := newPrivEnv(t)
	sealer, err := seal.New(seal.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	e.srv.cfg.Alerts = &alerts.Service{DB: e.f.DB, Sealer: sealer, Mail: alerts.LogMailer{}}
	admin2 := e.as("admin2", []auth.Role{auth.RoleTenantAdmin}, nil)
	file := func(typ, payload string, want int) map[string]any {
		return e.admin.call("POST", "/api/admin/change-requests", `{"type":"`+typ+`","payload":`+payload+`}`, want)
	}
	approveURL := func(ch map[string]any) (string, string) {
		return "/api/admin/change-requests/" + ch["id"].(string) + "/approve", `{"payload_hash":"` + ch["payload_hash"].(string) + `"}`
	}
	chanOf := func(id string) (*store.AlertChannel, error) {
		var c *store.AlertChannel
		err := e.f.DB.ReadTenant(context.Background(), e.f.B.ID, func(tx *store.TenantTx) error {
			var err error
			c, err = tx.AlertChannel(id)
			return err
		})
		return c, err
	}
	mail := e.admin.call("POST", "/api/alerts/channels", `{"name":"Mail","kind":"email","target":"soc@b.example","min_severity":"low"}`, 201)
	mid := mail["id"].(string)

	// self-approval is refused by name, not merely not 200
	ch := file("alerts.channel.severity", `{"channel_id":"`+mid+`","min_severity":"medium"}`, 201)
	u, body := approveURL(ch)
	if got := e.admin.call("POST", u, body, 403); errCode(got) != "self_approval_refused" {
		t.Errorf("self-approval: %v", got)
	}

	// stale severity: another approved raise overtakes it, so approving the first would lower min_severity
	ch2 := file("alerts.channel.severity", `{"channel_id":"`+mid+`","min_severity":"critical"}`, 201)
	approveChange(t, admin2, e.admin, ch2)
	admin2.call("POST", u, body, 422)
	if c, _ := chanOf(mid); c.MinSeverity != "critical" {
		t.Errorf("a stale raise changed min_severity to %q", c.MinSeverity)
	}

	// more recipients than the apply allows: refused when filed, not left to fail on approval
	many := make([]string, alerts.MaxRecipients+1)
	for i := range many {
		many[i] = "r" + strconv.Itoa(i) + "@b.example"
	}
	file("alerts.channel.target", `{"channel_id":"`+mid+`","target":"`+strings.Join(many, ", ")+`"}`, 422)

	// stale target and disable: the channel is deleted before they are approved
	tgt := file("alerts.channel.target", `{"channel_id":"`+mid+`","target":"new@b.example"}`, 201)
	dis := file("alerts.channel.disable", `{"channel_id":"`+mid+`"}`, 201)
	del := file("alerts.channel.delete", `{"channel_id":"`+mid+`"}`, 201)
	approveChange(t, admin2, e.admin, del)
	for _, c := range []map[string]any{tgt, dis} {
		u, body := approveURL(c)
		admin2.call("POST", u, body, 422)
	}
	if _, err := chanOf(mid); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a stale request brought the channel back: %v", err)
	}
	if n := deleteAuditCount(t, e.f.DB, e.f.B.ID, "alert.channel.disabled"); n != 0 {
		t.Errorf("a stale disable was audited as applied (%d)", n)
	}

	// a webhook URL: the 409 does not echo it, no request holds it, no audit event records it
	const token = "SECRETtok3n9f8e7d"
	hook := e.admin.call("POST", "/api/alerts/channels", `{"name":"Hook","kind":"webhook","target":"https://hooks.slack.com/services/T0/B0/x","min_severity":"high"}`, 201)
	hid := hook["id"].(string)
	rec := e.admin.do("PUT", "/api/alerts/channels/"+hid, `{"name":"Hook","target":"https://hooks.slack.com/services/T0/B0/`+token+`"}`)
	if rec.Code != 409 || strings.Contains(rec.Body.String(), token) || !strings.Contains(rec.Body.String(), "alerts.channel.delete") {
		t.Errorf("webhook retarget: %d %s", rec.Code, rec.Body)
	}
	rec = e.admin.do("POST", "/api/admin/change-requests", `{"type":"alerts.channel.target","payload":{"channel_id":"`+hid+`","target":"https://hooks.slack.com/services/T0/B0/`+token+`"}}`)
	if rec.Code != 422 || strings.Contains(rec.Body.String(), token) {
		t.Errorf("webhook target request: %d %s", rec.Code, rec.Body)
	}
	if rec := e.admin.do("GET", "/api/admin/change-requests", ""); strings.Contains(rec.Body.String(), token) {
		t.Error("a change request holds the webhook token")
	}
	if err := e.f.DB.ReadTenant(context.Background(), e.f.B.ID, func(tx *store.TenantTx) error {
		evs, err := tx.AuditEvents(store.AuditFilter{})
		for _, ev := range evs {
			if strings.Contains(string(ev.Detail), token) || strings.Contains(string(ev.HTTP), token) {
				t.Errorf("audit event %s records the webhook token", ev.Action)
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// TestDeleteSiemSinkAPI: deleting or disabling a sink stops its audit export, so each is a two-admin change request
// (siem.sink.delete, siem.sink.disable), as narrowing its filter is. The DELETE and the PUT that turns it off answer
// 409 two_admin_change_required; the requester cannot approve their own request.
func TestDeleteSiemSinkAPI(t *testing.T) {
	e := newPrivEnv(t)
	sealer, err := seal.New(seal.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	e.srv.cfg.Siem = &siem.Service{DB: e.f.DB, Sealer: sealer,
		NewSender: func(*store.SiemSink, string, string) (siem.Sender, error) { return &okSender{}, nil }}
	admin2 := e.as("admin2", []auth.Role{auth.RoleTenantAdmin}, nil)
	au := e.as("auditor", []auth.Role{auth.RoleAuditor}, nil)
	stale := deleteStaleLogin(t, e.f, e.f.B.ID, auth.RoleTenantAdmin)
	h := e.srv.Handler()

	v := e.admin.call("POST", "/api/siem/sinks", `{"name":"Splunk","kind":"webhook","format":"json","target":"https://splunk.example:8088/c","flavor":"hec","token":"hec-123"}`, 201)
	id := v["id"].(string)
	path := "/api/siem/sinks/" + id
	sinkOf := func() (*store.SiemSink, error) {
		var k *store.SiemSink
		err := e.f.DB.ReadTenant(context.Background(), e.f.B.ID, func(tx *store.TenantTx) error {
			var err error
			k, err = tx.SiemSink(id)
			return err
		})
		return k, err
	}
	if k, err := sinkOf(); err != nil || len(k.SecretSealed) == 0 {
		t.Fatalf("the sink has no sealed token to delete: %v", err)
	}

	if rec := au.do("DELETE", path, ""); rec.Code != 403 {
		t.Errorf("auditor: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(h, stale, "DELETE", path, ""); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Errorf("stale sign-in: %d %s", rec.Code, rec.Body)
	}
	e.admin.call("DELETE", "/api/siem/sinks/nope", "", 404)

	// one admin can neither disable nor delete the sink
	got := e.admin.call("PUT", path, `{"name":"Splunk","enabled":false}`, 409)
	if errCode(got) != "two_admin_change_required" || got["change_type"] != "siem.sink.disable" {
		t.Errorf("disable at the PUT: %v", got)
	}
	got = e.admin.call("DELETE", path, "", 409)
	if errCode(got) != "two_admin_change_required" || got["change_type"] != "siem.sink.delete" {
		t.Errorf("delete: %v", got)
	}
	if k, err := sinkOf(); err != nil || !k.Enabled {
		t.Fatalf("one admin changed the sink: %+v %v", k, err)
	}

	// disabling takes a second admin; enabling again is one
	e.admin.call("POST", "/api/admin/change-requests", `{"type":"siem.sink.disable","payload":{"sink_id":"nope"}}`, 422)
	ch := e.admin.call("POST", "/api/admin/change-requests", `{"type":"siem.sink.disable","payload":{"sink_id":"`+id+`"}}`, 201)
	if ch["status"] != "pending_approval" || ch["two_person"] != true {
		t.Fatalf("disable request = %v", ch)
	}
	approveChange(t, admin2, e.admin, ch)
	if k, err := sinkOf(); err != nil || k.Enabled {
		t.Fatalf("after the approved disable: %+v %v", k, err)
	}
	if n := deleteAuditCount(t, e.f.DB, e.f.B.ID, "siem.sink.disabled"); n != 1 {
		t.Errorf("siem.sink.disabled audited %d times", n)
	}
	e.admin.call("POST", "/api/admin/change-requests", `{"type":"siem.sink.disable","payload":{"sink_id":"`+id+`"}}`, 422) // already off
	e.admin.call("PUT", path, `{"name":"Splunk","enabled":false}`, 200)                                                    // keeps it off
	e.admin.call("PUT", path, `{"name":"Splunk","enabled":true}`, 200)

	// deleting takes a second admin too, enabled or not; the sealed token and the dead letters go with the row
	if err := e.f.DB.InTenant(context.Background(), e.f.B.ID, func(tx *store.TenantTx) error {
		k, err := tx.SiemSink(id)
		if err != nil {
			return err
		}
		return tx.DeadLetterSiemBatch(&store.SiemDeadLetter{ID: "dl-1", SinkID: id, FromSeq: k.CursorSeq + 1, ToSeq: k.CursorSeq + 1,
			Events: 1, Error: "rejected", CreatedAt: storetest.Now})
	}); err != nil {
		t.Fatal(err)
	}
	ch = e.admin.call("POST", "/api/admin/change-requests", `{"type":"siem.sink.delete","payload":{"sink_id":"`+id+`"}}`, 201)
	if ch["status"] != "pending_approval" || ch["two_person"] != true {
		t.Fatalf("delete request = %v", ch)
	}
	if _, err := sinkOf(); err != nil {
		t.Fatalf("the sink went before the approval: %v", err)
	}
	approveChange(t, admin2, e.admin, ch)
	if _, err := sinkOf(); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("sink and its sealed token remain: %v", err)
	}
	var dead []*store.SiemDeadLetter
	_ = e.f.DB.ReadTenant(context.Background(), e.f.B.ID, func(tx *store.TenantTx) error {
		dead, _ = tx.SiemDeadLetters(id)
		return nil
	})
	if len(dead) != 0 {
		t.Errorf("dead letters remain: %d", len(dead))
	}
	if n := deleteAuditCount(t, e.f.DB, e.f.B.ID, "siem.sink.deleted"); n != 1 {
		t.Errorf("siem.sink.deleted audited %d times", n)
	}

	// another tenant's sink answers like a missing id, at the route and as a request, and is untouched
	other := seedSiemSink(t, e.f.DB, e.f.A.ID, "a")
	before := storetest.Dump(t, e.f.DB, e.f.A.ID)
	e.admin.call("DELETE", "/api/siem/sinks/"+other, "", http.StatusNotFound)
	e.admin.call("POST", "/api/admin/change-requests", `{"type":"siem.sink.delete","payload":{"sink_id":"`+other+`"}}`, 422)
	e.admin.call("POST", "/api/admin/change-requests", `{"type":"siem.sink.disable","payload":{"sink_id":"`+other+`"}}`, 422)
	if storetest.Dump(t, e.f.DB, e.f.A.ID) != before {
		t.Error("tenant A changed")
	}
}

func TestDeleteGroupLoaderAPI(t *testing.T) {
	e, dir := newLoaderEnv(t)
	writeLoaderFile(t, dir, "people.csv", "id\nalice\nbob\n")
	app := e.admin.folder("", "app")
	id := e.admin.call("POST", "/api/groups/loaders", csvLoaderBody("Staff", app, "people.csv", "staff", ""), 201)["id"].(string)
	path := "/api/groups/loaders/" + id
	// give it a sealed credential and an unresolved-subject row to prove they go with it
	if err := e.f.DB.InTenant(context.Background(), e.f.B.ID, func(tx *store.TenantTx) error {
		l, err := tx.GrpLoader(id)
		if err != nil {
			return err
		}
		l.SecretEnc = []byte("sealed-blob")
		l.UpdatedAt = storetest.Now
		if err := tx.UpdateGrpLoader(l); err != nil {
			return err
		}
		return tx.UpsertGrpLoaderUnresolved(&store.GrpLoaderUnresolved{LoaderID: id, Source: "csv", Identifier: "ghost",
			FirstSeen: storetest.Now, LastSeen: storetest.Now, Groups: "[]"})
	}); err != nil {
		t.Fatal(err)
	}

	op := e.user("op", "bob")
	denied403 := op.do("DELETE", path, "")
	if denied403.Code != 403 {
		t.Errorf("operator: %d %s", denied403.Code, denied403.Body)
	}
	l := deleteStaleLogin(t, e.f, e.f.B.ID, auth.RoleTenantAdmin)
	if rec := (client{t, l.Handler(e.srv.Handler())}).do("DELETE", path, ""); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Errorf("stale sign-in: %d %s", rec.Code, rec.Body)
	}
	if rec := e.admin.do("DELETE", path, ""); rec.Code != 409 || !strings.Contains(rec.Body.String(), "loader_not_disabled") {
		t.Errorf("enabled loader: %d %s", rec.Code, rec.Body)
	}
	e.admin.call("DELETE", "/api/groups/loaders/00000000-0000-4000-8000-00000000dead", "", 404)

	// another tenant's loader is a 404 and stays as it was
	other := signIn(t, e.f.DB, e.f.A.ID, authtest.User{Email: "ta@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	before := storetest.Dump(t, e.f.DB, e.f.B.ID)
	if rec := (client{t, other.Handler(e.srv.Handler())}).do("DELETE", path, ""); rec.Code != 404 {
		t.Errorf("cross-tenant: %d %s", rec.Code, rec.Body)
	}
	if storetest.Dump(t, e.f.DB, e.f.B.ID) != before {
		t.Error("tenant B changed")
	}

	e.admin.call("PATCH", path, `{"status":"disabled"}`, 200)
	if got := e.admin.call("DELETE", path, "", 200); got["deleted"] != true || got["id"] != id {
		t.Errorf("delete = %v", got)
	}
	e.admin.call("GET", path, "", 404)
	if err := e.f.DB.ReadTenant(context.Background(), e.f.B.ID, func(tx *store.TenantTx) error {
		if _, err := tx.GrpLoader(id); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("loader and its sealed credential remain: %v", err)
		}
		if n, err := tx.GrpLoaderUnresolvedCount(id); err != nil || n != 0 {
			t.Errorf("unresolved subjects remain: %d %v", n, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if n := deleteAuditCount(t, e.f.DB, e.f.B.ID, "groups.loader.deleted"); n != 1 {
		t.Errorf("groups.loader.deleted audited %d times", n)
	}
}

// A loader that still manages groups is refused: its groups would name a loader that no longer exists.
func TestDeleteGroupLoaderAPI_ManagesGroups(t *testing.T) {
	e, dir := newLoaderEnv(t)
	writeLoaderFile(t, dir, "people.csv", "id\nalice\nbob\n")
	app := e.admin.folder("", "app")
	id := e.admin.call("POST", "/api/groups/loaders", csvLoaderBody("Staff", app, "people.csv", "staff", ""), 201)["id"].(string)
	e.admin.call("POST", "/api/groups/loaders/"+id+"/run", `{}`, 200)
	e.admin.call("PATCH", "/api/groups/loaders/"+id, `{"status":"disabled"}`, 200)
	if rec := e.admin.do("DELETE", "/api/groups/loaders/"+id, ""); rec.Code != 409 || !strings.Contains(rec.Body.String(), "loader_has_groups") {
		t.Errorf("loader with groups: %d %s", rec.Code, rec.Body)
	}
}

func TestDeleteConnectionAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	now := storetest.Now
	ad := f.B.Refs["connection:ad"]
	path := "/api/connections/" + ad
	admin := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, now)
	op := signIn(t, f.DB, f.B.ID, authtest.User{Email: "op@b.example", Roles: []auth.Role{auth.RoleOperator}}, authtest.Phr, now)
	stale := deleteStaleLogin(t, f, f.B.ID, auth.RoleTenantAdmin)
	write := func(fn func(tx *store.TenantTx) error) {
		t.Helper()
		if err := f.DB.InTenant(context.Background(), f.B.ID, fn); err != nil {
			t.Fatal(err)
		}
	}

	if rec := corrDo(h, op, "DELETE", path, ""); rec.Code != 403 {
		t.Errorf("operator: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(h, stale, "DELETE", path, ""); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Errorf("stale sign-in: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(h, admin, "DELETE", path, ""); rec.Code != 409 || !strings.Contains(rec.Body.String(), "connection_not_retired") {
		t.Errorf("active connection: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(h, admin, "DELETE", "/api/connections/"+missingUUID, ""); rec.Code != 404 {
		t.Errorf("unknown id: %d %s", rec.Code, rec.Body)
	}
	// tenant A cannot see B's connection
	adminA := signIn(t, f.DB, f.A.ID, authtest.User{Email: "ta@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, now)
	beforeB := storetest.Dump(t, f.DB, f.B.ID)
	if rec := corrDo(h, adminA, "DELETE", path, ""); rec.Code != 404 {
		t.Errorf("cross-tenant: %d %s", rec.Code, rec.Body)
	}
	if storetest.Dump(t, f.DB, f.B.ID) != beforeB {
		t.Error("tenant B changed")
	}
	if rec := corrDo(h, admin, "POST", path+"/retire", `{"confirm":true}`); rec.Code != 200 {
		t.Fatalf("retire: %d %s", rec.Code, rec.Body)
	}

	// a provisioning op in flight, then a running job, each refuse with their own code
	write(func(tx *store.TenantTx) error {
		if err := tx.InsertProvOp(&store.ProvOp{ID: "op-1", ConnectionID: ad, Kind: "disable_account", TargetRef: "x", Payload: "{}",
			Source: "test", IdempotencyKey: "k-1", RequestedBy: "test"}, now); err != nil {
			return err
		}
		return tx.InsertJobRun(&store.JobRun{ID: "job-1", Kind: "sync", Trigger: "manual", Status: "running", ConnectionID: &ad,
			Actor: "test", StartedAt: now})
	})
	if rec := corrDo(h, admin, "DELETE", path, ""); rec.Code != 409 || !strings.Contains(rec.Body.String(), "connection_syncing") {
		t.Errorf("running sync: %d %s", rec.Code, rec.Body)
	}
	write(func(tx *store.TenantTx) error { return tx.FinishJobRun("job-1", "succeeded", now, nil, nil) })
	if rec := corrDo(h, admin, "DELETE", path, ""); rec.Code != 409 || !strings.Contains(rec.Body.String(), "connection_has_pending_ops") {
		t.Errorf("pending op: %d %s", rec.Code, rec.Body)
	}
	write(func(tx *store.TenantTx) error {
		return tx.SetProvOpState("op-1", "queued", store.ProvOpState{Status: "cancelled", NextAttemptAt: now, CompletedAt: &now}, now)
	})
	// a sealed credential that must go with the connection
	write(func(tx *store.TenantTx) error {
		return tx.PutCredential(&store.Credential{ConnectionID: ad, Purpose: "containment", Sealed: []byte("sealed-blob"), UpdatedBy: "test", UpdatedAt: now})
	})

	beforeA := storetest.Dump(t, f.DB, f.A.ID)
	if rec := corrDo(h, admin, "DELETE", path, ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"deleted":true`) {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	if storetest.Dump(t, f.DB, f.A.ID) != beforeA {
		t.Error("tenant A changed")
	}
	if rec := corrDo(h, admin, "GET", path, ""); rec.Code != 404 {
		t.Errorf("deleted connection still reads: %d", rec.Code)
	}
	if rec := corrDo(h, admin, "DELETE", path, ""); rec.Code != 404 {
		t.Errorf("second delete: %d %s", rec.Code, rec.Body)
	}
	_ = f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		if _, err := tx.Credential(ad, "containment", ""); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("sealed credential remains: %v", err)
		}
		if revs, err := tx.Revisions(ad); err != nil || len(revs) != 0 {
			t.Errorf("revisions remain: %d %v", len(revs), err)
		}
		if _, err := tx.ProvOp("op-1"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("provisioning op remains: %v", err)
		}
		if conns, err := tx.Connections(); err != nil || len(conns) != 1 {
			t.Errorf("the tenant's other connection is gone: %d %v", len(conns), err)
		}
		return nil
	})
	if n := deleteAuditCount(t, f.DB, f.B.ID, "connection.deleted"); n != 1 {
		t.Errorf("connection.deleted audited %d times", n)
	}
}

// A retired connection that still owns synced objects is refused, and nothing it synced is removed.
func TestDeleteConnectionAPI_OwnsSyncedObjects(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	okta := f.B.Refs["connection"]
	admin := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	if rec := corrDo(h, admin, "POST", "/api/connections/"+okta+"/retire", `{"confirm":true}`); rec.Code != 200 {
		t.Fatalf("retire: %d %s", rec.Code, rec.Body)
	}
	counts := func() (n int, conn bool) {
		_ = f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
			n, _ = tx.CountAccounts()
			_, err := tx.Connection(okta)
			conn = err == nil
			return nil
		})
		return
	}
	accounts, _ := counts()
	rec := corrDo(h, admin, "DELETE", "/api/connections/"+okta, "")
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "connection_has_synced_objects") {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	if n, conn := counts(); n != accounts || accounts == 0 || !conn {
		t.Errorf("a refused delete changed the tenant: %d accounts (was %d), connection kept %v", n, accounts, conn)
	}
}
