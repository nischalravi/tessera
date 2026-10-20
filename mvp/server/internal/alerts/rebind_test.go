package alerts_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/alerts"
	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// TestUpdateChannelOriginNeedsNewSecret: a webhook channel's signing secret
// never follows it to another origin (#332). A path-only edit keeps it; an
// origin change without rotate_secret is refused and nothing reaches the new
// host; with rotate_secret the secret is replaced.
func TestUpdateChannelOriginNeedsNewSecret(t *testing.T) {
	w := newWorld(t)
	var homeN, attackerN atomic.Int32
	home := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { homeN.Add(1) }))
	defer home.Close()
	attacker := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { attackerN.Add(1) }))
	defer attacker.Close()
	svc := w.service(t, devClient(t), nil)
	var ch *store.AlertChannel
	w.write(t, func(tx *store.TenantTx) error {
		var err error
		ch, _, err = alerts.CreateChannel(tx, w.sealer, alerts.ChannelSpec{Name: "Hook", Kind: "webhook", Target: home.URL + "/a",
			MinSeverity: "low", Enabled: true}, true, alerts.Actor{Display: "test"}, w.now)
		return err
	})
	update := func(target string, rotate bool) (*store.AlertChannel, string, error) {
		var c *store.AlertChannel
		var secret string
		err := w.st.InTenant(audit.WithSystemActor(context.Background(), "test"), w.st.Tenant, func(tx *store.TenantTx) error {
			var err error
			c, secret, err = alerts.UpdateChannel(tx, w.sealer, ch.ID, alerts.ChannelSpec{Name: "Hook", Target: target, MinSeverity: "low",
				Enabled: true, RotateSecret: rotate}, true, alerts.Actor{Display: "test"}, w.now)
			return err
		})
		return c, secret, err
	}
	current := func() *store.AlertChannel {
		return testkit.Get(t, w.st, func(tx *store.TenantTx) (*store.AlertChannel, error) { return tx.AlertChannel(ch.ID) })
	}

	if c, s, err := update(home.URL+"/b?x=1", false); err != nil || s != "" || string(c.SecretSealed) != string(ch.SecretSealed) {
		t.Fatalf("path-only edit: %q %v", s, err)
	}
	_, _, err := update(attacker.URL+"/a", false)
	var ae *alerts.Error
	if !errors.As(err, &ae) || ae.Status != 422 || ae.Code != "credential_required" {
		t.Fatalf("origin change without rotate_secret: %v", err)
	}
	if cur := current(); !strings.HasPrefix(cur.Target, home.URL) {
		t.Fatalf("target moved after the refusal: %s", cur.Target)
	}
	if err := svc.TestChannel(context.Background(), w.st.Tenant, "tiny", current()); err != nil {
		t.Fatalf("test channel: %v", err)
	}
	if homeN.Load() != 1 || attackerN.Load() != 0 {
		t.Fatalf("requests: home %d, new origin %d", homeN.Load(), attackerN.Load())
	}
	c, s, err := update(attacker.URL+"/a", true)
	if err != nil || s == "" || string(c.SecretSealed) == string(ch.SecretSealed) {
		t.Fatalf("origin change with rotate_secret: %q %v", s, err)
	}
	evs := testkit.Get(t, w.st, func(tx *store.TenantTx) ([]*store.AuditEvent, error) {
		return tx.AuditEvents(store.AuditFilter{Action: "alert.channel.updated"})
	})
	moved := 0
	for _, e := range evs {
		if strings.Contains(string(e.Detail), `"previous_origin"`) {
			moved++
		}
		if strings.Contains(string(e.Detail), "/b") || strings.Contains(string(e.Detail), "x=1") {
			t.Errorf("path or query in the audit detail: %s", e.Detail)
		}
	}
	if len(evs) != 2 || moved != 1 {
		t.Errorf("alert.channel.updated events %d, moves %d", len(evs), moved)
	}
}
