package api

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/nischalravi/tessera/mvp/server/internal/alerts"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// TestAlertChannelFollowups covers issue #973: rotate_secret is a two-admin change, summaries name the channel and the
// old and new value without any secret, and one save that needs several changes names every one of them.
func TestAlertChannelFollowups(t *testing.T) {
	e := newPrivEnv(t)
	sealer, err := seal.New(seal.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	e.srv.cfg.Alerts = &alerts.Service{DB: e.f.DB, Sealer: sealer, Mail: alerts.LogMailer{}}
	e.srv.admin.Sealer = sealer
	admin2 := e.as("admin2", []auth.Role{auth.RoleTenantAdmin}, nil)
	const tok = "TOKENsecret7f3a9c"
	const newSecret = "whsec_chosen_by_requester_0123456789"
	hook := e.admin.call("POST", "/api/alerts/channels", `{"name":"Hook","kind":"webhook","target":"https://hooks.slack.com/services/T0/B0/`+tok+`","min_severity":"high"}`, 201)
	mail := e.admin.call("POST", "/api/alerts/channels", `{"name":"Mail","kind":"email","target":"soc@b.example","min_severity":"low"}`, 201)
	hid, mid := hook["id"].(string), mail["id"].(string)
	oldSecret := hook["secret"].(string)
	chanOf := func(id string) *store.AlertChannel {
		var c *store.AlertChannel
		if err := e.f.DB.ReadTenant(context.Background(), e.f.B.ID, func(tx *store.TenantTx) error {
			var err error
			c, err = tx.AlertChannel(id)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return c
	}
	file := func(typ, payload, secret string, want int) map[string]any {
		body := `{"type":"` + typ + `","payload":` + payload
		if secret != "" {
			body += `,"client_secret":"` + secret + `"`
		}
		return e.admin.call("POST", "/api/admin/change-requests", body+`}`, want)
	}
	var summaries []string

	// 1. rotate_secret: the PUT answers 409, one admin cannot rotate
	got := e.admin.call("PUT", "/api/alerts/channels/"+hid, `{"name":"Hook","rotate_secret":true}`, 409)
	if errCode(got) != "two_admin_change_required" || got["change_type"] != "alerts.channel.rotate_secret" {
		t.Fatalf("rotate PUT: %v", got)
	}
	before := chanOf(hid).SecretSealed
	file("alerts.channel.rotate_secret", `{"channel_id":"`+hid+`"}`, "", 422)                                             // no secret
	file("alerts.channel.rotate_secret", `{"channel_id":"`+hid+`"}`, "short", 422)                                        // too short
	file("alerts.channel.rotate_secret", `{"channel_id":"`+hid+`"}`, strings.Repeat("s", alerts.MinSigningSecret-1), 422) // one under the 32 floor
	file("alerts.channel.rotate_secret", `{"channel_id":"`+mid+`"}`, newSecret, 422)                                      // email: nothing to rotate
	file("alerts.channel.rotate_secret", `{"channel_id":"nope"}`, newSecret, 422)                                         // unknown
	file("alerts.channel.rotate_secret", `{"channel_id":"`+hid+`","secret":"x"}`, newSecret, 422)                         // no secret in a payload
	rot := file("alerts.channel.rotate_secret", `{"channel_id":"`+hid+`"}`, newSecret, 201)
	if string(chanOf(hid).SecretSealed) != string(before) {
		t.Fatal("the secret changed before the approval")
	}
	summaries = append(summaries, rot["summary"].(string))
	approveChange(t, admin2, e.admin, rot)
	open := func() string {
		b, err := sealer.Open(chanOf(hid).SecretSealed, alerts.SecretAAD(e.f.B.ID, hid))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if open() != newSecret {
		t.Error("the approved rotation did not install the requested secret")
	}

	// 2. summaries: name, type and old -> new, never a secret or a URL token
	summaries = append(summaries,
		file("alerts.channel.disable", `{"channel_id":"`+hid+`"}`, "", 201)["summary"].(string),
		file("alerts.channel.delete", `{"channel_id":"`+hid+`"}`, "", 201)["summary"].(string),
		file("alerts.channel.target", `{"channel_id":"`+mid+`","target":"a@b.example"}`, "", 201)["summary"].(string),
		file("alerts.channel.severity", `{"channel_id":"`+mid+`","min_severity":"critical"}`, "", 201)["summary"].(string))
	for i, want := range [][]string{{`"Hook" (webhook`, "signing secret"}, {`"Hook" (webhook`, "enabled → disabled"}, {`"Hook" (webhook`, "Delete"},
		{`"Mail" (email`, "soc@b.example → a@b.example"}, {`"Mail" (email`, "low → critical"}} {
		for _, w := range want {
			if !strings.Contains(summaries[i], w) {
				t.Errorf("summary %q lacks %q", summaries[i], w)
			}
		}
	}
	lists := []string{e.admin.do("GET", "/api/admin/change-requests", "").Body.String()}
	for _, s := range summaries {
		lists = append(lists, s)
	}
	for _, s := range lists {
		for _, secret := range []string{newSecret, oldSecret, tok} {
			if strings.Contains(s, secret) {
				t.Errorf("a summary or list leaks %q: %.200s", secret, s)
			}
		}
	}
	if err := e.f.DB.ReadTenant(context.Background(), e.f.B.ID, func(tx *store.TenantTx) error {
		evs, err := tx.AuditEvents(store.AuditFilter{})
		for _, ev := range evs {
			for _, secret := range []string{newSecret, oldSecret, tok} {
				if strings.Contains(string(ev.Detail), secret) || strings.Contains(string(ev.HTTP), secret) {
					t.Errorf("audit event %s records a secret", ev.Action)
				}
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}

	// 3. one save, several changes: the 409 names every one, in order, change_type is the first
	types := func(path, body string) []string {
		got := e.admin.call("PUT", path, body, 409)
		var out []string
		raw, _ := json.Marshal(got["change_types"])
		_ = json.Unmarshal(raw, &out)
		if len(out) == 0 || got["change_type"] != out[0] {
			t.Errorf("change_type %v is not the first of %v", got["change_type"], out)
		}
		return out
	}
	if got, want := types("/api/alerts/channels/"+mid, `{"name":"Mail","enabled":false,"target":"z@b.example","min_severity":"critical"}`),
		[]string{"alerts.channel.disable", "alerts.channel.target", "alerts.channel.severity"}; !reflect.DeepEqual(got, want) {
		t.Errorf("email save needs %v, want %v", got, want)
	}
	if got, want := types("/api/alerts/channels/"+hid, `{"name":"Hook","enabled":false,"min_severity":"critical","rotate_secret":true}`),
		[]string{"alerts.channel.disable", "alerts.channel.severity", "alerts.channel.rotate_secret"}; !reflect.DeepEqual(got, want) {
		t.Errorf("webhook save needs %v, want %v", got, want)
	}
	if got, want := types("/api/alerts/channels/"+hid, `{"name":"Hook","target":"https://hooks.slack.com/services/T0/B0/other","min_severity":"critical"}`),
		[]string{"config.proposal", "alerts.channel.severity"}; !reflect.DeepEqual(got, want) {
		t.Errorf("webhook move needs %v, want %v", got, want)
	}
}

// TestAlertChannelRotateLifecycle: the sealed secret of a rotate_secret request is cleared when the request is rejected or
// cancelled, another tenant cannot file one for this tenant's channel, and a rotation filed before the channel's secret
// was replaced is refused at approval (and ends) instead of overwriting the newer secret.
func TestAlertChannelRotateLifecycle(t *testing.T) {
	e := newPrivEnv(t)
	sealer, err := seal.New(seal.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	e.srv.cfg.Alerts = &alerts.Service{DB: e.f.DB, Sealer: sealer, Mail: alerts.LogMailer{}}
	e.srv.admin.Sealer = sealer
	admin2 := e.as("admin2", []auth.Role{auth.RoleTenantAdmin}, nil)
	hook := e.admin.call("POST", "/api/alerts/channels", `{"name":"Hook","kind":"webhook","target":"https://hooks.slack.com/services/T0/B0/TOKENx","min_severity":"high"}`, 201)
	hid := hook["id"].(string)
	file := func(c grpClient, secret string, want int) map[string]any {
		return c.call("POST", "/api/admin/change-requests", `{"type":"alerts.channel.rotate_secret","payload":{"channel_id":"`+hid+`"},"client_secret":"`+secret+`"}`, want)
	}
	sealedOf := func(id string) []byte {
		var enc []byte
		if err := e.f.DB.ReadTenant(context.Background(), e.f.B.ID, func(tx *store.TenantTx) error {
			ch, err := tx.AdminChange(uuid.MustParse(id))
			if err == nil {
				enc = ch.SecretEnc
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return enc
	}

	// another tenant's admin cannot reach this channel
	l := signIn(t, e.f.DB, e.f.A.ID, authtest.User{Email: "admin@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	other := grpClient{client{t, l.Handler(e.srv.Handler())}}
	file(other, "whsec_other_tenant_0123456789", 422)

	// reject and cancel clear the sealed secret
	rej := file(e.admin, "whsec_rejected_0123456789abcdef-0123456789", 201)
	if len(sealedOf(rej["id"].(string))) == 0 {
		t.Fatal("a pending rotation holds no sealed secret")
	}
	admin2.call("POST", "/api/admin/change-requests/"+rej["id"].(string)+"/reject", "{}", 200)
	if len(sealedOf(rej["id"].(string))) != 0 {
		t.Error("a rejected rotation still holds its sealed secret")
	}
	can := file(e.admin, "whsec_cancelled_0123456789abcdef-0123456789", 201)
	e.admin.call("POST", "/api/admin/change-requests/"+can["id"].(string)+"/cancel", "", 200)
	if len(sealedOf(can["id"].(string))) != 0 {
		t.Error("a cancelled rotation still holds its sealed secret")
	}

	// two rotations filed against the same secret: once one applies, the other is stale and ends failed
	first := file(e.admin, "whsec_first_0123456789abcdef-0123456789", 201)
	second := file(e.admin, "whsec_second_0123456789abcdef-0123456789", 201)
	approveChange(t, admin2, e.admin, first)
	got := admin2.call("POST", "/api/admin/change-requests/"+second["id"].(string)+"/approve", `{"payload_hash":"`+second["payload_hash"].(string)+`"}`, 409)
	if errCode(got) != "stale_base" {
		t.Errorf("stale rotation approval = %v, want stale_base", got)
	}
	if len(sealedOf(second["id"].(string))) != 0 {
		t.Error("the stale rotation still holds its sealed secret")
	}
	var plain []byte
	if err := e.f.DB.ReadTenant(context.Background(), e.f.B.ID, func(tx *store.TenantTx) error {
		c, err := tx.AlertChannel(hid)
		if err == nil {
			plain, err = sealer.Open(c.SecretSealed, alerts.SecretAAD(e.f.B.ID, hid))
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if string(plain) != "whsec_first_0123456789abcdef-0123456789" {
		t.Error("the stale rotation replaced the applied secret")
	}
}
