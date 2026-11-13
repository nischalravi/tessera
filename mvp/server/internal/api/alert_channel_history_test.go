package api

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/alerts"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// TestAlertChannelChangeHistory covers issue #977: once an alert-channel change request is applied its summary still
// reads old -> new, a deleted channel keeps its name and type, the audit event holds the previous recipients, and no
// secret or webhook URL appears in a summary, the list or an audit entry.
func TestAlertChannelChangeHistory(t *testing.T) {
	e := newPrivEnv(t)
	sealer, err := seal.New(seal.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	e.srv.cfg.Alerts = &alerts.Service{DB: e.f.DB, Sealer: sealer, Mail: alerts.LogMailer{}}
	e.srv.admin.Sealer = sealer
	admin2 := e.as("admin2", []auth.Role{auth.RoleTenantAdmin}, nil)
	const tok = "TOKENhistory5d1e"
	const rotated = "whsec_history_rotation_0123456789"
	hook := e.admin.call("POST", "/api/alerts/channels", `{"name":"Hook","kind":"webhook","target":"https://hooks.slack.com/services/T0/B0/`+tok+`","min_severity":"high"}`, 201)
	mail := e.admin.call("POST", "/api/alerts/channels", `{"name":"Mail","kind":"email","target":"a@x.example, b@x.example","min_severity":"medium"}`, 201)
	off := e.admin.call("POST", "/api/alerts/channels", `{"name":"Off","kind":"email","target":"c@x.example","min_severity":"low"}`, 201)
	hid, mid := hook["id"].(string), mail["id"].(string)
	oldSecret := hook["secret"].(string)
	file := func(typ, payload, secret string) map[string]any {
		body := `{"type":"` + typ + `","payload":` + payload
		if secret != "" {
			body += `,"client_secret":"` + secret + `"`
		}
		return e.admin.call("POST", "/api/admin/change-requests", body+`}`, 201)
	}
	read := func(ch map[string]any) string {
		got := e.admin.call("GET", "/api/admin/change-requests/"+ch["id"].(string), "", 200)
		return got["summary"].(string)
	}
	tgt := file("alerts.channel.target", `{"channel_id":"`+mid+`","target":"new1@x.example, new2@x.example"}`, "")
	sev := file("alerts.channel.severity", `{"channel_id":"`+mid+`","min_severity":"critical"}`, "")
	rot := file("alerts.channel.rotate_secret", `{"channel_id":"`+hid+`"}`, rotated)
	dis := file("alerts.channel.disable", `{"channel_id":"`+off["id"].(string)+`"}`, "")
	del := file("alerts.channel.delete", `{"channel_id":"`+hid+`"}`, "")
	pending := []string{read(tgt), read(sev)}
	for _, c := range []map[string]any{tgt, sev, rot, dis} {
		approveChange(t, admin2, e.admin, c)
	}
	approveChange(t, admin2, e.admin, del)

	summaries := map[string]string{"target": read(tgt), "severity": read(sev), "rotate": read(rot), "delete": read(del), "disable": read(dis)}
	for k, want := range map[string][]string{
		"target":   {`"Mail" (email`, "a@x.example, b@x.example → new1@x.example, new2@x.example"},
		"severity": {`"Mail" (email`, "medium → critical"},
		"rotate":   {`"Hook" (webhook`},
		"delete":   {`"Hook" (webhook`, "Delete"},
		"disable":  {`"Off" (email`, "enabled \u2192 disabled"},
	} {
		for _, w := range want {
			if !strings.Contains(summaries[k], w) {
				t.Errorf("applied %s summary %q lacks %q", k, summaries[k], w)
			}
		}
	}
	if !strings.Contains(pending[0], "a@x.example, b@x.example → new1") || !strings.Contains(pending[1], "medium → critical") {
		t.Errorf("pending summaries = %q", pending)
	}
	list := e.admin.do("GET", "/api/admin/change-requests", "").Body.String()
	if !strings.Contains(list, "a@x.example, b@x.example → new1@x.example, new2@x.example") || !strings.Contains(list, `\"Hook\" (webhook`) {
		t.Errorf("the list does not keep the applied summaries: %.300s", list)
	}

	// the audit keeps the previous recipients; no secret or URL is in a summary, the list or any audit entry
	var sawPrev bool
	leaks := []string{rotated, oldSecret, tok, "hooks.slack.com", "https://"}
	check := func(what, s string) {
		for _, l := range leaks {
			if strings.Contains(s, l) {
				t.Errorf("%s leaks %q: %.200s", what, l, s)
			}
		}
	}
	for k, s := range summaries {
		check("summary "+k, s)
	}
	check("list", list)
	if err := e.f.DB.ReadTenant(context.Background(), e.f.B.ID, func(tx *store.TenantTx) error {
		evs, err := tx.AuditEvents(store.AuditFilter{})
		for _, ev := range evs {
			if !strings.HasPrefix(ev.Action, "alert.channel.") {
				continue
			}
			d := string(ev.Detail)
			if ev.Action == "alert.channel.updated" && strings.Contains(d, `"previous_target"`) {
				sawPrev = strings.Contains(d, "a@x.example, b@x.example") && strings.Contains(d, "new1@x.example, new2@x.example")
			}
			if strings.Contains(d, rotated) || strings.Contains(d, oldSecret) || strings.Contains(d, tok) || strings.Contains(string(ev.HTTP), tok) {
				t.Errorf("audit event %s records a secret", ev.Action)
			}
			if strings.Contains(d, "/services/") {
				t.Errorf("audit event %s records a URL path: %.200s", ev.Action, d)
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !sawPrev {
		t.Error("no alert.channel.updated event holds previous_target next to the new target")
	}
}

// A retarget between two full recipient lists (20 long addresses each) applies; the kept summary stays within the
// 1000 characters admin_change_summaries holds, whatever the lists.
func TestAlertChannelRetargetLongRecipientsApplies(t *testing.T) {
	e := newPrivEnv(t)
	sealer, err := seal.New(seal.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	e.srv.cfg.Alerts = &alerts.Service{DB: e.f.DB, Sealer: sealer, Mail: alerts.LogMailer{}}
	e.srv.admin.Sealer = sealer
	admin2 := e.as("admin2", []auth.Role{auth.RoleTenantAdmin}, nil)
	list := func(prefix string) string {
		var a []string
		for i := 0; i < 20; i++ {
			a = append(a, fmt.Sprintf("%s-%02d-%s@%s.example.com", prefix, i, strings.Repeat("l", 40), strings.Repeat("d", 30)))
		}
		return strings.Join(a, ", ")
	}
	mail := e.admin.call("POST", "/api/alerts/channels", `{"name":"Wide","kind":"email","target":"`+list("old")+`","min_severity":"low"}`, 201)
	ch := e.admin.call("POST", "/api/admin/change-requests", `{"type":"alerts.channel.target","payload":{"channel_id":"`+mail["id"].(string)+`","target":"`+list("new")+`"}}`, 201)
	approveChange(t, admin2, e.admin, ch)
	got := e.admin.call("GET", "/api/admin/change-requests/"+ch["id"].(string), "", 200)
	if got["status"] != "applied" {
		t.Fatalf("status after approve = %v, want applied", got["status"])
	}
	var kept string
	if err := e.f.DB.ReadTenant(context.Background(), e.f.B.ID, func(tx *store.TenantTx) error {
		id, err := uuid.Parse(ch["id"].(string))
		if err != nil {
			return err
		}
		kept, err = tx.AdminChangeSummary(id)
		return err
	}); err != nil {
		t.Fatalf("no summary kept: %v", err)
	}
	if n := utf8.RuneCountInString(kept); n < 1 || n > 1000 {
		t.Errorf("kept summary has %d characters", n)
	}
}
