package api

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/alerts"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/siem"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Fragments of the webhook URL that must never appear outside the row (#333).
var urlSecrets = []string{"SECRETPATHXYZ", "SECRETQUERYXYZ", "T000", "B000", "/services"}

// closedLoopbackURL is a loopback webhook URL nothing listens on, with a
// credential in its path and query, so a send fails with a *url.Error.
func closedLoopbackURL(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return "http://" + addr + "/services/T000/B000/SECRETPATHXYZ?token=SECRETQUERYXYZ"
}

func assertNoURLSecret(t *testing.T, where, s string) {
	t.Helper()
	for _, bad := range urlSecrets {
		if strings.Contains(s, bad) {
			t.Errorf("%s leaks %q: %.400s", where, bad, s)
		}
	}
}

func assertLedgerClean(t *testing.T, f *storetest.Fixture) {
	t.Helper()
	if err := f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		evs, err := tx.AuditEvents(store.AuditFilter{})
		for _, e := range evs {
			assertNoURLSecret(t, "audit "+e.Action, string(e.Detail))
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestWebhookSendErrorsAreRedacted(t *testing.T) {
	f := storetest.TwoTenants(t)
	sealer, err := seal.New(seal.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	client, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	srv := newIsolationServer(f)
	srv.cfg.Alerts = &alerts.Service{DB: f.DB, Sealer: sealer, HTTP: client, Mail: alerts.LogMailer{}}
	srv.cfg.Siem = &siem.Service{DB: f.DB, Sealer: sealer, HTTP: client, Dev: true}
	h := srv.Handler()
	admin := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	target := closedLoopbackURL(t)

	// rows are written directly: the API only accepts https outside dev
	var ch *store.AlertChannel
	if err := f.DB.InTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		var err error
		ch, _, err = alerts.CreateChannel(tx, sealer, alerts.ChannelSpec{Name: "Slack", Kind: "webhook", Target: target,
			MinSeverity: "low", Enabled: true}, true, alerts.Actor{Display: "test"}, storetest.Now)
		if err != nil {
			return err
		}
		tok := "hec-token"
		_, err = siem.CreateSink(tx, sealer, siem.SinkSpec{Name: "Sumo", Kind: "webhook", Format: siem.FormatJSON, Target: target,
			Flavor: siem.FlavorJSON, Token: &tok, Enabled: true}, true, siem.Actor{Display: "test"}, storetest.Now)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	rec := alertsDo(h, admin, "POST", "/api/alerts/channels/"+ch.ID+"/test", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"ok":false`) || !strings.Contains(rec.Body.String(), "127.0.0.1") {
		t.Fatalf("channel test: %d %s", rec.Code, rec.Body)
	}
	assertNoURLSecret(t, "channel test response", rec.Body.String())
	rec = alertsDo(h, admin, "GET", "/api/alerts/channels", "")
	assertNoURLSecret(t, "channel list", rec.Body.String())

	rec = siemDo(h, admin, "GET", "/api/siem/sinks", "")
	var id string
	if i := strings.Index(rec.Body.String(), `"id":"`); i >= 0 {
		id = strings.SplitN(rec.Body.String()[i+6:], `"`, 2)[0]
	}
	rec = siemDo(h, admin, "POST", "/api/siem/sinks/"+id+"/test", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"ok":false`) {
		t.Fatalf("sink test: %d %s", rec.Code, rec.Body)
	}
	assertNoURLSecret(t, "sink test response", rec.Body.String())
	// a delivery attempt stores last_error and audits the failure
	for range 3 {
		if err := srv.cfg.Siem.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	rec = siemDo(h, admin, "GET", "/api/siem/sinks", "")
	if !strings.Contains(rec.Body.String(), `"last_error":"webhook: `) {
		t.Errorf("sink list has no last_error: %s", rec.Body)
	}
	assertNoURLSecret(t, "sink list", rec.Body.String())
	if err := f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		k, err := tx.SiemSink(id)
		if err == nil && k.LastError != nil {
			assertNoURLSecret(t, "siem_sinks.last_error", *k.LastError)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	assertLedgerClean(t, f)
}
