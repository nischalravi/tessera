package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/alerts"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/worker"
)

func errCode(m map[string]any) any {
	if c, ok := m["code"]; ok {
		return c
	}
	return m["error"]
}

// approveChange has the second admin approve a pending change request.
func approveChange(t *testing.T, second grpClient, requester grpClient, ch map[string]any) {
	t.Helper()
	approve := "/api/admin/change-requests/" + ch["id"].(string) + "/approve"
	body := fmt.Sprintf(`{"payload_hash":%q}`, ch["payload_hash"])
	if rec := requester.do("POST", approve, body); rec.Code == 200 {
		t.Errorf("the requester approved their own change: %s", rec.Body)
	}
	second.call("POST", approve, body, 200)
}

// TestSiemAPI_IncludeHTTPAndRetarget (issue #520): a PUT that omits include_http keeps it, turning it off and moving
// the sink to another origin each need a second admin, and rewind needs a step-up.
func TestSiemAPI_IncludeHTTPAndRetarget(t *testing.T) {
	e := newPrivEnv(t)
	admin2 := e.as("admin2", []auth.Role{auth.RoleTenantAdmin}, nil)
	sink := e.admin.call("POST", "/api/siem/sinks", `{"name":"splunk","kind":"webhook","format":"json","flavor":"json","include_http":true,"target":"https://a.example.com/services/collector"}`, 201)
	id := sink["id"].(string)
	if sink["include_http"] != true {
		t.Fatalf("created include_http = %v", sink["include_http"])
	}
	// a rename that omits include_http keeps it on
	got := e.admin.call("PUT", "/api/siem/sinks/"+id, `{"name":"splunk-prod","enabled":true}`, 200)
	if got["include_http"] != true || got["name"] != "splunk-prod" {
		t.Errorf("rename = %v", got)
	}
	// true to false is refused at the PUT and is a two-admin request
	got = e.admin.call("PUT", "/api/siem/sinks/"+id, `{"name":"splunk-prod","include_http":false}`, 409)
	if errCode(got) != "two_admin_change_required" {
		t.Errorf("include_http off at the PUT: %v", got)
	}
	ch := e.admin.call("POST", "/api/admin/change-requests", fmt.Sprintf(`{"type":"siem.sink.filter","payload":{"sink_id":%q,"include_http":false}}`, id), 201)
	if ch["status"] != "pending_approval" || ch["two_person"] != true {
		t.Fatalf("include_http off request = %v", ch)
	}
	approveChange(t, admin2, e.admin, ch)
	e.admin.call("PUT", "/api/siem/sinks/"+id, `{"name":"splunk-prod"}`, 200) // keeps it off
	list := e.admin.do("GET", "/api/siem/sinks", "")
	if !strings.Contains(list.Body.String(), `"include_http":false`) {
		t.Errorf("include_http after approval: %s", list.Body)
	}
	// turning it on is one admin
	if got = e.admin.call("PUT", "/api/siem/sinks/"+id, `{"name":"splunk-prod","include_http":true}`, 200); got["include_http"] != true {
		t.Errorf("include_http on = %v", got)
	}
	// a payload with neither setting, or the same settings, is refused
	e.admin.call("POST", "/api/admin/change-requests", fmt.Sprintf(`{"type":"siem.sink.filter","payload":{"sink_id":%q}}`, id), 422)
	e.admin.call("POST", "/api/admin/change-requests", fmt.Sprintf(`{"type":"siem.sink.filter","payload":{"sink_id":%q,"include_http":true}}`, id), 422)

	// the same origin with another path is still one admin
	e.admin.call("PUT", "/api/siem/sinks/"+id, `{"name":"splunk-prod","target":"https://a.example.com/services/collector/event"}`, 200)
	// another origin is refused at the PUT, with or without a token
	for _, body := range []string{`{"name":"splunk-prod","target":"https://b.example.com/services/collector","token":"tok-b"}`,
		`{"name":"splunk-prod","target":"https://a.example.com:8443/x"}`} {
		got = e.admin.call("PUT", "/api/siem/sinks/"+id, body, 409)
		if errCode(got) != "two_admin_change_required" || got["change_type"] != "siem.sink.target" {
			t.Errorf("retarget at the PUT %s: %v", body, got)
		}
	}
	// the request needs a second admin; a target on the same origin is not one
	e.admin.call("POST", "/api/admin/change-requests", fmt.Sprintf(`{"type":"siem.sink.target","payload":{"sink_id":%q,"target":"https://a.example.com/other"}}`, id), 422)
	e.admin.call("POST", "/api/admin/change-requests", fmt.Sprintf(`{"type":"siem.sink.target","payload":{"sink_id":%q,"target":"http://b.example.com/x"}}`, id), 422) // not https
	ch = e.admin.call("POST", "/api/admin/change-requests", fmt.Sprintf(`{"type":"siem.sink.target","payload":{"sink_id":%q,"target":"https://b.example.com/services/collector"}}`, id), 201)
	if ch["status"] != "pending_approval" || ch["two_person"] != true {
		t.Fatalf("retarget request = %v", ch)
	}
	// until it is approved the sink still points at the old destination, so the request reaches it
	if !strings.Contains(e.admin.do("GET", "/api/siem/sinks", "").Body.String(), "a.example.com") {
		t.Error("the sink moved before the approval")
	}
	approveChange(t, admin2, e.admin, ch)
	var moved *store.SiemSink
	var retargeted []*store.AuditEvent
	_ = e.f.DB.ReadTenant(context.Background(), e.f.B.ID, func(tx *store.TenantTx) error {
		moved, _ = tx.SiemSink(id)
		evs, _ := tx.AuditEvents(store.AuditFilter{})
		for _, ev := range evs {
			if ev.Action == "siem.sink.retargeted" {
				retargeted = append(retargeted, ev)
			}
		}
		return nil
	})
	if moved == nil || !strings.Contains(moved.Target, "b.example.com") || moved.Enabled || len(moved.SecretSealed) != 0 {
		t.Fatalf("retargeted sink = %+v", moved)
	}
	if len(retargeted) != 1 || !strings.Contains(string(retargeted[0].Detail), "https://a.example.com") ||
		!strings.Contains(string(retargeted[0].Detail), "https://b.example.com") || strings.Contains(string(retargeted[0].Detail), "tok-") {
		t.Errorf("retargeted events = %+v", retargeted)
	}
	// the admin enables the sink at its new destination
	e.admin.call("PUT", "/api/siem/sinks/"+id, `{"name":"splunk-prod","enabled":true}`, 200)

	// rewind needs a step-up
	stale := signIn(t, e.f.DB, e.f.B.ID, authtest.User{Email: "stale@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}, storetest.Now)
	if rec := corrDo(e.srv.Handler(), stale, "POST", "/api/siem/sinks/"+id+"/rewind", `{"seq":0}`); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Errorf("rewind without a step-up: %d %s", rec.Code, rec.Body)
	}
	e.admin.call("POST", "/api/siem/sinks/"+id+"/rewind", `{"seq":0}`, 200)
}

// TestAlertRules_SecurityRuleLoosening (issue #521): changing a rule needs a step-up, and loosening a security rule
// needs a second admin; tightening it and changing another rule do not.
func TestAlertRules_SecurityRuleLoosening(t *testing.T) {
	e := newPrivEnv(t)
	admin2 := e.as("admin2", []auth.Role{auth.RoleTenantAdmin}, nil)
	h := e.srv.Handler()
	stale := signIn(t, e.f.DB, e.f.B.ID, authtest.User{Email: "stale@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}, storetest.Now)
	off := `{"enabled":false,"severity":"high","threshold":1,"window_minutes":60}`
	if rec := corrDo(h, stale, "PUT", "/api/alerts/rules/schedule_paused", off); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Errorf("a rule change without a step-up: %d %s", rec.Code, rec.Body)
	}
	// every security rule: disabling, raising the threshold, lowering the severity and shortening the window are refused
	for _, id := range []string{"schedule_paused", "provision_failed", "queue_job_dead", "oauth_app_change", "provisioning_failed"} {
		for label, body := range map[string]string{"disable": off,
			"threshold": `{"enabled":true,"severity":"high","threshold":5,"window_minutes":60}`,
			"severity":  `{"enabled":true,"severity":"low","threshold":1,"window_minutes":60}`,
			"window":    `{"enabled":true,"severity":"high","threshold":1,"window_minutes":10}`} {
			got := e.admin.call("PUT", "/api/alerts/rules/"+id, body, 409)
			if errCode(got) != "two_admin_change_required" || got["change_type"] != "alerts.rule.loosen" {
				t.Errorf("%s %s: %v", id, label, got)
			}
		}
	}
	// tightening is one admin; so is a rule that is not a security rule
	for path, body := range map[string]string{"schedule_paused": `{"enabled":true,"severity":"critical","threshold":1,"window_minutes":120}`, "access_drift": off} {
		if rec := e.admin.do("PUT", "/api/alerts/rules/"+path, body); rec.Code != 200 {
			t.Errorf("PUT %s: %d %s", path, rec.Code, rec.Body)
		}
	}
	// the request: two admins; a change that does not loosen, or another rule, is not one
	body := `{"type":"alerts.rule.loosen","payload":{"rule_id":"schedule_paused","enabled":false,"severity":"critical","threshold":1,"window_minutes":120}}`
	e.admin.call("POST", "/api/admin/change-requests", `{"type":"alerts.rule.loosen","payload":{"rule_id":"schedule_paused","enabled":true,"severity":"critical","threshold":1,"window_minutes":120}}`, 422)
	e.admin.call("POST", "/api/admin/change-requests", `{"type":"alerts.rule.loosen","payload":{"rule_id":"access_drift","enabled":false,"severity":"medium","threshold":1,"window_minutes":60}}`, 422)
	ch := e.admin.call("POST", "/api/admin/change-requests", body, 201)
	if ch["status"] != "pending_approval" || ch["two_person"] != true {
		t.Fatalf("loosen request = %v", ch)
	}
	approveChange(t, admin2, e.admin, ch)
	var enabled = true
	_ = e.f.DB.ReadTenant(context.Background(), e.f.B.ID, func(tx *store.TenantTx) error {
		r, err := alerts.EffectiveRule(tx, "schedule_paused")
		if err != nil || r == nil {
			t.Fatalf("rule: %v", err)
		}
		enabled = r.Enabled
		return nil
	})
	if enabled {
		t.Error("the approved change did not disable the rule")
	}
}

func TestSecurityScheduleSet(t *testing.T) {
	for _, n := range []string{jobs.SweepSSFPoll, jobs.VmsSync, jobs.GuestLifecycle, jobs.OAuthSync, jobs.JITSweep, jobs.SweepRequests,
		jobs.ContainmentRetry, worker.DeltaScheduleName, worker.FullScheduleName} {
		if !protectedSchedules[n] {
			t.Errorf("%s is not a protected schedule", n)
		}
	}
	if protectedSchedules[jobs.Maintenance] {
		t.Error("job_maintenance is protected")
	}
	// a pause of a newly protected schedule needs a reason and ends
	f := storetest.TwoTenants(t)
	srv := newIsolationServer(f)
	if err := srv.Queue().Tick(context.Background()); err != nil { // creates the schedules
		t.Fatal(err)
	}
	srv.Queue().Wait()
	h := srv.Handler()
	admin := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	if rec := corrDo(h, admin, "POST", "/api/queue/schedules/ssf_poll/pause", `{}`); rec.Code != 422 && rec.Code != 400 {
		t.Errorf("ssf_poll pause without a reason: %d %s", rec.Code, rec.Body)
	}
}

// TestSyncScheduleEffectivelyOff (issue #521): no delta sync with a full sync every 7 days or less often alerts too.
func TestSyncScheduleEffectivelyOff(t *testing.T) {
	for _, tc := range []struct {
		delta, full int
		off         bool
	}{{0, 0, true}, {0, 720, true}, {0, 168, true}, {0, 167, false}, {0, 24, false}, {5, 0, false}, {15, 720, false}} {
		if got := syncsEffectivelyOff(tc.delta, tc.full); got != tc.off {
			t.Errorf("delta %d full %d: %v", tc.delta, tc.full, got)
		}
	}
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	admin := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	if rec := reqDo(h, admin, "PUT", "/api/connectors/sync-schedule", `{"delta_every_minutes":0,"full_every_hours":720}`); rec.Code != 200 {
		t.Fatalf("put: %d %s", rec.Code, rec.Body)
	}
	_ = f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		evs, _ := tx.AuditEvents(store.AuditFilter{})
		for _, ev := range evs {
			if ev.Action == "connectors.schedule_updated" {
				if !strings.Contains(string(ev.Detail), `"all_syncs_off":true`) {
					t.Errorf("detail = %s", ev.Detail)
				}
				if _, ok := alerts.RuleByID("schedule_paused").Match(ev); !ok {
					t.Error("the schedule_paused rule does not match")
				}
				return nil
			}
		}
		t.Error("no connectors.schedule_updated event")
		return nil
	})
}

// TestLegacyIndefinitePausesGetAnEnd (issue #522): a protected schedule paused with no end before the upgrade gets
// 24 hours, an audited protected+migrated pause event, and resumes by itself; the sync schedules and ordinary
// schedules are left alone.
func TestLegacyIndefinitePausesGetAnEnd(t *testing.T) {
	f := storetest.TwoTenants(t)
	srv := newIsolationServerWith(f, func(c *Config) {
		c.Clock = func() time.Time { return storetest.Now }
	})
	ctx := context.Background()
	if err := srv.Queue().Tick(ctx); err != nil { // creates the schedules
		t.Fatal(err)
	}
	srv.Queue().Wait()
	// a pause as an old build made it: disabled, no end
	if err := f.DB.InTenant(ctx, f.A.ID, func(tx *store.TenantTx) error {
		for _, n := range []string{jobs.ContainmentRetry, jobs.Maintenance} {
			if err := tx.SetQueueScheduleEnabled(n, false, storetest.Now); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// the process sees the tenant again (a restart): a new queue
	q2 := srv.newQueue()
	if err := q2.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	q2.Wait()
	var contain, other *store.QueueSchedule
	_ = f.DB.ReadTenant(ctx, f.A.ID, func(tx *store.TenantTx) error {
		contain, _ = tx.QueueSchedule(jobs.ContainmentRetry)
		other, _ = tx.QueueSchedule(jobs.Maintenance)
		return nil
	})
	if contain == nil || contain.Enabled || contain.PausedUntil == nil || !contain.PausedUntil.Equal(storetest.Now.Add(24*time.Hour)) {
		t.Fatalf("containment_retries = %+v", contain)
	}
	if other == nil || other.Enabled || other.PausedUntil != nil {
		t.Errorf("an ordinary schedule was changed: %+v", other)
	}
	var migrated int
	_ = f.DB.ReadTenant(ctx, f.A.ID, func(tx *store.TenantTx) error {
		evs, _ := tx.AuditEvents(store.AuditFilter{})
		for _, ev := range evs {
			if ev.Action == "queue.schedule_paused" && strings.Contains(string(ev.Detail), `"migrated":true`) && strings.Contains(string(ev.Detail), `"protected":true`) {
				migrated++
				if _, ok := alerts.RuleByID("schedule_paused").Match(ev); !ok {
					t.Error("the migrated pause does not raise the alert")
				}
			}
		}
		return nil
	})
	if migrated != 1 {
		t.Errorf("migrated pause events = %d", migrated)
	}
	// it resumes by itself after the 24 hours
	later := storetest.Now.Add(25 * time.Hour)
	srv2 := newIsolationServerWith(f, func(c *Config) { c.Clock = func() time.Time { return later } })
	if err := srv2.Queue().Tick(ctx); err != nil {
		t.Fatal(err)
	}
	srv2.Queue().Wait()
	_ = f.DB.ReadTenant(ctx, f.A.ID, func(tx *store.TenantTx) error {
		contain, _ = tx.QueueSchedule(jobs.ContainmentRetry)
		return nil
	})
	if contain == nil || !contain.Enabled {
		t.Errorf("containment_retries did not resume: %+v", contain)
	}
	// the two connector sync schedules, which a tenant turns off itself, are never given an end
	if boundLegacyPause(worker.DeltaScheduleName) || boundLegacyPause(worker.FullScheduleName) || !boundLegacyPause(jobs.SweepLifecycle) {
		t.Error("boundLegacyPause covers the wrong schedules")
	}
}

// TestMachineClientApprover (issue #522): a client is held to the admin who created it or last rotated its keys, and
// to its owner when none is on record; a role-less client is refused with a clear message.
func TestMachineClientApprover(t *testing.T) {
	f := storetest.TwoTenants(t)
	ctx := context.Background()
	adminL := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	opL := signIn(t, f.DB, f.B.ID, authtest.User{Email: "op@b.example", Roles: []auth.Role{auth.RoleOperator}}, authtest.Phr, storetest.Now)
	both := signIn(t, f.DB, f.B.ID, authtest.User{Email: "both2@b.example", Roles: []auth.Role{auth.RoleTenantAdmin, auth.RoleOperator}}, authtest.Phr, storetest.Now)
	scopes := []string{"tessera:write", "tessera:read"}
	check := func(approvedBy string, owner *authtest.Login) []string {
		t.Helper()
		var missing []string
		if err := f.DB.ReadTenant(ctx, f.B.ID, func(tx *store.TenantTx) error {
			cl := &store.APIClient{Roles: []string{"operator"}, AllowedScopes: scopes, ApprovedBy: approvedBy}
			if owner != nil {
				cl.OwnerUserID = &owner.UserID
			}
			var err error
			missing, err = auth.ClientExceedsApprover(tx, cl, scopes, storetest.Now)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return missing
	}
	if m := check(adminL.UserID.String(), &opL); !strings.Contains(strings.Join(m, ","), "jit.deny_revoke") {
		t.Errorf("a tenant-admin-only approver lacks %v", m)
	}
	if m := check(opL.UserID.String(), &adminL); len(m) != 0 {
		t.Errorf("an operator approver lacks %v", m)
	}
	if m := check("", &adminL); len(m) == 0 {
		t.Error("a legacy client with a tenant-admin-only owner is not flagged")
	}
	if m := check("", &opL); len(m) != 0 {
		t.Errorf("a legacy client with an operator owner lacks %v", m)
	}
	if m := check(store.ApprovedByOperator, &adminL); len(m) != 0 {
		t.Errorf("a CLI client lacks %v", m)
	}
	// the API records the creating admin as the approver, and a role-less client is told why
	h := newIsolationServer(f).Handler()
	rec := reqDo(h, both, "POST", "/api/admin/api-clients", fmt.Sprintf(`{"name":"ops","owner":"op@b.example","scopes":["tessera:write","tessera:read"],"roles":["operator"],"jwks":%s}`, pubJWKS(t, "k1")))
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var created struct {
		ClientID string `json:"client_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	var c *store.APIClient
	_ = f.DB.ReadTenant(ctx, f.B.ID, func(tx *store.TenantTx) error { c, _ = tx.APIClientByClientID(created.ClientID); return nil })
	if c == nil || c.ApprovedBy != both.UserID.String() {
		t.Errorf("approved_by = %+v", c)
	}
	rec = reqDo(h, both, "POST", "/api/admin/api-clients", fmt.Sprintf(`{"name":"dsn","owner":"op@b.example","scopes":["tessera:email-dsn"],"roles":[],"jwks":%s}`, pubJWKS(t, "k2")))
	if rec.Code != 422 || !strings.Contains(rec.Body.String(), "invalid_roles") || !strings.Contains(rec.Body.String(), "email-dsn") {
		t.Errorf("no role: %d %s", rec.Code, rec.Body)
	}
}
