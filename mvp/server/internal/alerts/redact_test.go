package alerts_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/alerts"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// TestDeliveryErrorRedactsURL: a failed webhook delivery stores last_error and
// audits it without the URL's path or query, which may be the credential (#333).
func TestDeliveryErrorRedactsURL(t *testing.T) {
	w := newWorld(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := "http://" + l.Addr().String() + "/services/T000/B000/SECRETPATHXYZ?token=SECRETQUERYXYZ"
	_ = l.Close()
	w.write(t, func(tx *store.TenantTx) error {
		_, _, err := alerts.CreateChannel(tx, w.sealer, alerts.ChannelSpec{Name: "Slack", Kind: "webhook", Target: target,
			MinSeverity: "low", Enabled: true}, true, alerts.Actor{Display: "test"}, w.now)
		return err
	})
	w.record(t, "auth.break_glass.used", "success", `{}`, w.now)
	w.eval(t, false)
	svc := w.service(t, devClient(t), nil)
	for i := 0; i < alerts.MaxAttempts; i++ {
		if err := svc.DeliverTenant(context.Background(), w.st.Tenant, "tiny"); err != nil {
			t.Fatal(err)
		}
		w.now = w.now.Add(5 * time.Hour)
	}
	d := w.deliveries(t)[0]
	if d.LastError == nil || !strings.Contains(*d.LastError, "webhook: ") {
		t.Fatalf("delivery %+v", d)
	}
	texts := []string{*d.LastError}
	for _, e := range testkit.Get(t, w.st, func(tx *store.TenantTx) ([]*store.AuditEvent, error) {
		return tx.AuditEvents(store.AuditFilter{})
	}) {
		texts = append(texts, string(e.Detail))
	}
	for _, s := range texts {
		for _, bad := range []string{"SECRETPATHXYZ", "SECRETQUERYXYZ", "T000", "/services"} {
			if strings.Contains(s, bad) {
				t.Errorf("leaks %q: %s", bad, s)
			}
		}
	}
}
