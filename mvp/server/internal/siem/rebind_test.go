package siem_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/siem"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// authRecorder is an HTTP destination that records every Authorization header.
type authRecorder struct {
	*httptest.Server
	mu    sync.Mutex
	auths []string
}

func newAuthRecorder(t *testing.T) *authRecorder {
	r := &authRecorder{}
	r.Server = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.auths = append(r.auths, req.Header.Get("Authorization"))
		r.mu.Unlock()
		rw.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(r.Close)
	return r
}

func (r *authRecorder) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.auths...)
}

func (w *world) update(id string, s siem.SinkSpec) (*store.SiemSink, error) {
	var k *store.SiemSink
	err := w.st.InTenant(audit.WithSystemActor(context.Background(), "test"), w.st.Tenant, func(tx *store.TenantTx) error {
		var err error
		k, err = siem.UpdateSink(tx, w.sealer, id, s, true, siem.Actor{Display: "test"}, w.now)
		return err
	})
	return k, err
}

// TestUpdateSinkOriginNeedsNewToken: the stored token never follows the sink
// to another origin (#332). A path-only edit keeps it; an origin change
// without a token is refused and nothing reaches the new host; with a token
// the token is rotated.
func TestUpdateSinkOriginNeedsNewToken(t *testing.T) {
	w := newWorld(t)
	home, attacker := newAuthRecorder(t), newAuthRecorder(t)
	client, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	svc := &siem.Service{DB: w.st.DB, Sealer: w.sealer, HTTP: client, Dev: true}
	token := "hec-original-token"
	k := w.create(t, siem.SinkSpec{Name: "Splunk", Kind: "webhook", Format: siem.FormatJSON, Target: home.URL + "/services/collector",
		Flavor: siem.FlavorHEC, Token: &token, Enabled: true})
	spec := func(target string, tok *string) siem.SinkSpec {
		return siem.SinkSpec{Name: "Splunk", Kind: "webhook", Format: siem.FormatJSON, Target: target, Flavor: siem.FlavorHEC,
			Token: tok, Enabled: true}
	}
	testSink := func() {
		t.Helper()
		if err := svc.TestSink(context.Background(), w.st.Tenant, "tiny", w.sink(t, k.ID)); err != nil {
			t.Fatalf("test sink: %v", err)
		}
	}

	// path only: kept
	if _, err := w.update(k.ID, spec(home.URL+"/services/collector/event?channel=1", nil)); err != nil {
		t.Fatalf("path-only edit: %v", err)
	}
	testSink()
	if got := home.got(); len(got) != 1 || got[0] != "Splunk "+token {
		t.Fatalf("home got %v", got)
	}

	// another origin (port) without a token: refused, nothing changes
	for _, target := range []string{attacker.URL + "/services/collector", strings.Replace(home.URL, "127.0.0.1", "[::1]", 1) + "/x"} {
		_, err := w.update(k.ID, spec(target, nil))
		var se *siem.Error
		if !errors.As(err, &se) || se.Status != 422 || se.Code != "credential_required" {
			t.Fatalf("origin change to %s without a token: %v", target, err)
		}
	}
	if cur := w.sink(t, k.ID); !strings.HasPrefix(cur.Target, home.URL) {
		t.Fatalf("target moved after the refusal: %s", cur.Target)
	}
	testSink()
	if got := attacker.got(); len(got) != 0 {
		t.Fatalf("the new origin received %d requests: %v", len(got), got)
	}

	// with a new token: rotated, and only the new token goes to the new host
	fresh := "hec-new-token"
	if _, err := w.update(k.ID, spec(attacker.URL+"/services/collector", &fresh)); err != nil {
		t.Fatalf("origin change with a token: %v", err)
	}
	testSink()
	if got := attacker.got(); len(got) != 1 || got[0] != "Splunk "+fresh {
		t.Fatalf("new origin got %v", got)
	}
	evs := testkit.Get(t, w.st, func(tx *store.TenantTx) ([]*store.AuditEvent, error) {
		return tx.AuditEvents(store.AuditFilter{Action: "siem.sink.updated"})
	})
	moved := 0
	for _, e := range evs {
		d := string(e.Detail)
		if strings.Contains(d, token) || strings.Contains(d, fresh) {
			t.Errorf("token in the audit detail: %s", d)
		}
		if strings.Contains(d, `"previous_origin"`) {
			moved++
			if !strings.Contains(d, `"token_changed":true`) {
				t.Errorf("move without token_changed: %s", d)
			}
		}
	}
	if len(evs) != 2 || moved != 1 {
		t.Errorf("siem.sink.updated events %d, moves %d", len(evs), moved)
	}
}

// A syslog sink that holds a token cannot move host:port without a new one.
func TestUpdateSyslogSinkOriginNeedsNewToken(t *testing.T) {
	w := newWorld(t)
	token := "syslog-token"
	k := w.create(t, siem.SinkSpec{Name: "Syslog", Kind: "syslog", Format: siem.FormatJSON, Target: "127.0.0.1:6514", Token: &token, Enabled: true})
	spec := siem.SinkSpec{Name: "Syslog", Kind: "syslog", Format: siem.FormatJSON, Target: "127.0.0.1:6515", Enabled: true}
	var se *siem.Error
	if _, err := w.update(k.ID, spec); !errors.As(err, &se) || se.Code != "credential_required" {
		t.Fatalf("syslog port change without a token: %v", err)
	}
	spec.Target = "127.0.0.1:6514"
	if _, err := w.update(k.ID, spec); err != nil {
		t.Fatalf("syslog edit on the same address: %v", err)
	}
}
