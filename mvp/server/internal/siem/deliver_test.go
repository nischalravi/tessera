package siem_test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/siem"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

func TestMain(m *testing.M) { testkit.Main(m) }

type world struct {
	st     *testkit.DB
	sealer *seal.Sealer
	now    time.Time
}

func newWorld(t *testing.T) *world {
	t.Helper()
	st, _ := testkit.Tiny(t)
	s, err := seal.New(seal.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	return &world{st: st, sealer: s, now: testkit.Now}
}

func (w *world) write(t *testing.T, fn func(*store.TenantTx) error) {
	t.Helper()
	if err := w.st.InTenant(audit.WithSystemActor(context.Background(), "test"), w.st.Tenant, fn); err != nil {
		t.Fatal(err)
	}
}

// events appends n audit events (and one http.request) and returns the last seq.
func (w *world) events(t *testing.T, n int) {
	t.Helper()
	w.write(t, func(tx *store.TenantTx) error {
		for i := range n {
			if _, err := audit.Record(context.Background(), tx, "grant.revoke", map[string]any{"i": i}, audit.At(w.now)); err != nil {
				return err
			}
		}
		return nil
	})
}

func (w *world) head(t *testing.T) int64 {
	return testkit.Get(t, w.st, func(tx *store.TenantTx) (int64, error) {
		h, err := tx.AuditHead()
		return h.LastSeq, err
	})
}

func (w *world) pending(t *testing.T, id string) int64 {
	k := w.sink(t, id)
	return testkit.Get(t, w.st, func(tx *store.TenantTx) (int64, error) { return tx.SiemPending(k.CursorSeq, k.IncludeHTTP) })
}

func (w *world) sink(t *testing.T, id string) *store.SiemSink {
	return testkit.Get(t, w.st, func(tx *store.TenantTx) (*store.SiemSink, error) { return tx.SiemSink(id) })
}

func (w *world) create(t *testing.T, s siem.SinkSpec) *store.SiemSink {
	t.Helper()
	var k *store.SiemSink
	w.write(t, func(tx *store.TenantTx) error {
		var err error
		k, err = siem.CreateSink(tx, w.sealer, s, true, siem.Actor{Display: "test"}, w.now)
		return err
	})
	return k
}

// recorder is a fake destination that keeps every batch and can fail.
type recorder struct {
	mu      sync.Mutex
	batches [][]siem.Record
	fail    error
	failAt  int // fail the batch with this index (1-based); 0: per fail
	calls   int
}

func (r *recorder) Send(_ context.Context, b []siem.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.fail != nil && (r.failAt == 0 || r.failAt == r.calls) {
		return r.fail
	}
	r.batches = append(r.batches, b)
	return nil
}

func (r *recorder) seqs() []int64 {
	var out []int64
	for _, b := range r.batches {
		for _, x := range b {
			out = append(out, x.Seq)
		}
	}
	return out
}

func (w *world) service(snd siem.Sender) *siem.Service {
	return &siem.Service{DB: w.st.DB, Sealer: w.sealer, Clock: func() time.Time { return w.now }, Dev: true,
		NewSender: func(*store.SiemSink, string, string) (siem.Sender, error) { return snd, nil }}
}

func (w *world) tick(t *testing.T, svc *siem.Service) {
	t.Helper()
	if err := svc.DeliverTenant(context.Background(), w.st.Tenant, "tiny"); err != nil {
		t.Fatal(err)
	}
}

func auditCount(t *testing.T, w *world, action string) int {
	evs := testkit.Get(t, w.st, func(tx *store.TenantTx) ([]*store.AuditEvent, error) {
		return tx.AuditEvents(store.AuditFilter{Action: action})
	})
	return len(evs)
}

// TestCursorSurvivesRestart: a sink that fails mid-stream resumes from its
// cursor with a fresh service, and every seq arrives in order, none missing.
func TestCursorSurvivesRestart(t *testing.T) {
	w := newWorld(t)
	k := w.create(t, siem.SinkSpec{Name: "SIEM", Kind: "webhook", Format: siem.FormatJSON, Target: "https://siem.example/ingest",
		Flavor: siem.FlavorJSON, Enabled: true, Start: "beginning"})
	w.events(t, 30)
	defer func(n int) { siem.BatchSize = n }(siem.BatchSize)
	siem.BatchSize = 7
	first := &recorder{fail: errors.New("connection reset"), failAt: 3}
	w.tick(t, w.service(first)) // two batches accepted, the third fails
	after := w.sink(t, k.ID)
	if len(first.batches) != 2 || after.CursorSeq != first.batches[1][len(first.batches[1])-1].Seq || after.Attempts != 1 || after.NextAttemptAt == nil {
		t.Fatalf("after the failure: %d batches, sink %+v", len(first.batches), after)
	}
	// "restart": a new service, the clock past the backoff
	w.now = w.now.Add(time.Minute)
	second := &recorder{}
	w.tick(t, w.service(second))
	all := append(first.seqs(), second.seqs()...)
	head := w.head(t)
	for i, s := range all {
		if s != int64(i+1) {
			t.Fatalf("seq %d at %d (gap or reorder): %v", s, i, all)
		}
	}
	if int64(len(all)) < head-1 { // the engine's own events after the last batch may follow
		t.Fatalf("delivered %d of %d", len(all), head)
	}
	if got := w.sink(t, k.ID); got.Attempts != 0 || got.LastError != nil || got.DeliveredCount != int64(len(all)) {
		t.Errorf("after recovery: %+v", got)
	}
}

func TestStartNowSkipsHistoryAndFiltersHTTP(t *testing.T) {
	w := newWorld(t)
	w.events(t, 5)
	k := w.create(t, siem.SinkSpec{Name: "SIEM", Kind: "webhook", Format: siem.FormatOCSF, Target: "https://siem.example/x",
		Flavor: siem.FlavorJSON, Enabled: true})
	start := w.sink(t, k.ID).CursorSeq
	w.write(t, func(tx *store.TenantTx) error {
		if _, err := audit.Record(context.Background(), tx, "grant.revoke", nil, audit.At(w.now)); err != nil {
			return err
		}
		_, err := tx.AppendAudit(store.AuditEvent{TenantID: w.st.Tenant, OccurredAt: w.now, ActorType: "anonymous", Action: "http.request",
			Outcome: "success", HTTP: json.RawMessage(`{"method":"GET","route":"/api/x","path_params":{},"query_keys":[],"status":200,"latency_ms":1}`),
			Detail: json.RawMessage(`{}`), SchemaVersion: 1})
		return err
	})
	rec := &recorder{}
	w.tick(t, w.service(rec))
	for _, s := range rec.seqs() {
		if s <= start {
			t.Errorf("history seq %d sent", s)
		}
	}
	for _, b := range rec.batches {
		for _, r := range b {
			if r.Action == "http.request" {
				t.Error("http.request sent without include_http")
			}
		}
	}
	if got := w.sink(t, k.ID); got.CursorSeq != w.head(t) {
		t.Errorf("cursor %d, head %d (skipped events still advance it)", got.CursorSeq, w.head(t))
	}
}

func TestBackoffFailingAndRecovered(t *testing.T) {
	w := newWorld(t)
	k := w.create(t, siem.SinkSpec{Name: "SIEM", Kind: "webhook", Format: siem.FormatJSON, Target: "https://siem.example/x",
		Flavor: siem.FlavorJSON, Enabled: true})
	w.events(t, 3)
	rec := &recorder{fail: errors.New("503")}
	svc := w.service(rec)
	for i := 1; i <= siem.FailingAfter; i++ {
		w.tick(t, svc)
		got := w.sink(t, k.ID)
		if got.Attempts != i || !got.NextAttemptAt.Equal(w.now.Add(siem.Backoff(i))) {
			t.Fatalf("attempt %d: %+v", i, got)
		}
		calls := rec.calls
		w.tick(t, svc) // not due: no call
		if rec.calls != calls {
			t.Fatalf("sent before the backoff elapsed")
		}
		w.now = w.now.Add(siem.Backoff(i))
	}
	if got := siem.HealthOf(w.sink(t, k.ID), w.pending(t, k.ID)); got.Status != "failing" || got.Lag == 0 {
		t.Errorf("health %+v", got)
	}
	if auditCount(t, w, "siem.sink.failing") != 1 {
		t.Error("failing not audited once")
	}
	rec.fail = nil
	w.tick(t, svc)
	if got := siem.HealthOf(w.sink(t, k.ID), w.pending(t, k.ID)); got.Status != "healthy" {
		t.Errorf("after recovery %+v", got)
	}
	if auditCount(t, w, "siem.sink.recovered") != 1 {
		t.Error("recovered not audited")
	}
	if siem.Backoff(1) != 10*time.Second || siem.Backoff(20) != 30*time.Minute {
		t.Errorf("backoff %v %v", siem.Backoff(1), siem.Backoff(20))
	}
}

// TestDeadLetter: a batch the destination keeps rejecting is recorded and
// skipped; retryable failures never are.
func TestDeadLetter(t *testing.T) {
	w := newWorld(t)
	k := w.create(t, siem.SinkSpec{Name: "SIEM", Kind: "webhook", Format: siem.FormatJSON, Target: "https://siem.example/x",
		Flavor: siem.FlavorJSON, Enabled: true})
	w.events(t, 4)
	from := w.sink(t, k.ID).CursorSeq + 1
	rec := &recorder{fail: &siem.SendError{Permanent: true, Msg: "webhook: HTTP 400"}}
	svc := w.service(rec)
	for range siem.MaxAttempts {
		w.tick(t, svc)
		w.now = w.now.Add(time.Hour)
	}
	got := w.sink(t, k.ID)
	dls := testkit.Get(t, w.st, func(tx *store.TenantTx) ([]*store.SiemDeadLetter, error) { return tx.SiemDeadLetters(k.ID) })
	// the batch holds the sink's own creation event and the four revokes
	if len(dls) != 1 || dls[0].FromSeq != from || dls[0].Events < 5 || !strings.Contains(dls[0].Error, "400") {
		t.Fatalf("dead letters %+v", dls)
	}
	if got.DeadLetterCount != int64(dls[0].Events) || got.CursorSeq != dls[0].ToSeq || got.Attempts != 0 {
		t.Fatalf("sink %+v", got)
	}
	if auditCount(t, w, "siem.sink.dead_letter") != 1 {
		t.Error("dead letter not audited")
	}
	// the stream goes on after the dead letter
	rec.fail = nil
	w.events(t, 2)
	w.tick(t, svc)
	if len(rec.batches) == 0 {
		t.Fatal("nothing sent after the dead letter")
	}
	// retryable errors never dead-letter
	w2 := newWorld(t)
	k2 := w2.create(t, siem.SinkSpec{Name: "SIEM", Kind: "webhook", Format: siem.FormatJSON, Target: "https://siem.example/x",
		Flavor: siem.FlavorJSON, Enabled: true})
	w2.events(t, 2)
	svc2 := w2.service(&recorder{fail: errors.New("timeout")})
	for range siem.MaxAttempts + 3 {
		w2.tick(t, svc2)
		w2.now = w2.now.Add(time.Hour)
	}
	if got := w2.sink(t, k2.ID); got.DeadLetterCount != 0 || got.Attempts != siem.MaxAttempts+3 {
		t.Fatalf("retryable sink %+v", got)
	}
}

func TestWebhookHECAndJSON(t *testing.T) {
	w := newWorld(t)
	var mu sync.Mutex
	got := map[string][]string{} // path -> [auth, body]
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got[r.URL.Path] = []string{r.Header.Get("Authorization"), string(b)}
		mu.Unlock()
		rw.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	token := "hec-token-123"
	hec := w.create(t, siem.SinkSpec{Name: "Splunk", Kind: "webhook", Format: siem.FormatOCSF, Target: srv.URL + "/services/collector/event",
		Flavor: siem.FlavorHEC, Token: &token, Enabled: true})
	bearer := "sentinel"
	js := w.create(t, siem.SinkSpec{Name: "Sentinel", Kind: "webhook", Format: siem.FormatJSON, Target: srv.URL + "/ingest",
		Flavor: siem.FlavorJSON, Token: &bearer, Enabled: true})
	w.events(t, 3)
	client, err := safehttp.New(safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	svc := &siem.Service{DB: w.st.DB, Sealer: w.sealer, HTTP: client, Clock: func() time.Time { return w.now }, Dev: true}
	w.tick(t, svc)
	h := got["/services/collector/event"]
	if h == nil || h[0] != "Splunk "+token {
		t.Fatalf("HEC request %v", h)
	}
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(h[1]), "\n") {
		if strings.Contains(l, `"message":"grant.revoke"`) {
			lines = append(lines, l)
		}
	}
	if len(lines) != 3 {
		t.Fatalf("HEC revoke lines %d: %s", len(lines), h[1])
	}
	var env struct {
		Time       float64        `json:"time"`
		Host       string         `json:"host"`
		Sourcetype string         `json:"sourcetype"`
		Event      map[string]any `json:"event"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &env); err != nil || env.Host != "tiny" || env.Sourcetype != "tessera:ocsf" || env.Event["class_uid"] != float64(6003) || env.Time == 0 {
		t.Errorf("HEC envelope %s (%v)", lines[0], err)
	}
	j := got["/ingest"]
	var arr []json.RawMessage
	if j == nil || j[0] != "Bearer sentinel" || json.Unmarshal([]byte(j[1]), &arr) != nil || len(arr) < 3 {
		t.Fatalf("JSON request %v", j)
	}
	for _, rec := range arr {
		if ok, _, err := audit.VerifyRecord(rec); !ok || err != nil {
			t.Errorf("record does not verify: %s", rec)
		}
	}
	for _, id := range []string{hec.ID, js.ID} {
		if k := w.sink(t, id); k.CursorSeq != w.head(t) && k.CursorSeq < w.head(t)-1 {
			t.Errorf("sink %s cursor %d head %d", k.Name, k.CursorSeq, w.head(t))
		}
	}
	// status mapping
	for code, permanent := range map[int]bool{400: true, 401: true, 413: true, 408: false, 429: false, 500: false, 503: false} {
		s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(code) }))
		err := (&siem.Webhook{Client: client, URL: s.URL, Flavor: siem.FlavorJSON}).Send(context.Background(), []siem.Record{{Payload: []byte(`{}`)}})
		s.Close()
		var se *siem.SendError
		if !errors.As(err, &se) || se.Permanent != permanent {
			t.Errorf("HTTP %d: %v (permanent %v)", code, err, permanent)
		}
	}
}

func selfSigned(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "collector.test"}, DNSNames: []string{"collector.test"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemCert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pemCert
}

// TestSyslogTLS: RFC 5425 frames over a verified TLS connection to a
// collector with a private CA.
func TestSyslogTLS(t *testing.T) {
	w := newWorld(t)
	cert, caPEM := selfSigned(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	frames := make(chan string, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					n, err := r.ReadString(' ')
					if err != nil {
						return
					}
					size, _ := strconv.Atoi(strings.TrimSpace(n))
					buf := make([]byte, size)
					if _, err := io.ReadFull(r, buf); err != nil {
						return
					}
					frames <- string(buf)
				}
			}(c)
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	k := w.create(t, siem.SinkSpec{Name: "Collector", Kind: "syslog", Format: siem.FormatJSON, Target: "collector.test:" + port,
		CAPEM: caPEM, Enabled: true})
	w.write(t, func(tx *store.TenantTx) error {
		_, err := audit.Record(context.Background(), tx, "auth.login.failure", map[string]any{"email": "m@x"}, audit.At(w.now),
			audit.Outcome("failure"))
		return err
	})
	svc := &siem.Service{DB: w.st.DB, Sealer: w.sealer, Clock: func() time.Time { return w.now }, Dev: true,
		Resolver: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}}
	w.tick(t, svc)
	var f string
	deadline := time.After(5 * time.Second)
	for !strings.Contains(f, "auth.login.failure") {
		select {
		case f = <-frames:
		case <-deadline:
			t.Fatalf("no login failure frame; sink %+v", w.sink(t, k.ID))
		}
	}
	{
		// facility 13 (log audit) * 8 + warning (4) = 108
		if !strings.HasPrefix(f, "<108>1 ") || !strings.Contains(f, " tiny tessera - auth.login.failure [tessera@32473 seq=") {
			t.Errorf("frame %q", f)
		}
		body := f[strings.Index(f, "] ")+2:]
		if ok, _, err := audit.VerifyRecord([]byte(body)); !ok || err != nil {
			t.Errorf("payload does not verify: %s", body)
		}
	}
	// without the CA the handshake fails and the batch retries
	k2 := w.create(t, siem.SinkSpec{Name: "No CA", Kind: "syslog", Format: siem.FormatJSON, Target: "collector.test:" + port, Enabled: true})
	w.events(t, 1)
	w.tick(t, svc)
	if got := w.sink(t, k2.ID); got.Attempts != 1 || got.LastError == nil || !strings.Contains(*got.LastError, "certificate") {
		t.Errorf("unverified collector: %+v", got)
	}
}

// TestSSRFGuard: syslog collectors and webhooks never reach private,
// loopback (outside dev) or metadata addresses.
func TestSSRFGuard(t *testing.T) {
	w := newWorld(t)
	for _, target := range []string{"10.0.0.5:6514", "169.254.169.254:6514", "[fd00::1]:6514"} {
		_, err := func() (*store.SiemSink, error) {
			var k *store.SiemSink
			err := w.st.InTenant(context.Background(), w.st.Tenant, func(tx *store.TenantTx) error {
				var err error
				k, err = siem.CreateSink(tx, w.sealer, siem.SinkSpec{Name: "x", Kind: "syslog", Format: siem.FormatJSON, Target: target, Enabled: true},
					false, siem.Actor{}, w.now)
				return err
			})
			return k, err
		}()
		var e *siem.Error
		if !errors.As(err, &e) || e.Code != "invalid_target" {
			t.Errorf("%s: %v", target, err)
		}
	}
	// a name that resolves to the metadata address is refused at dial time, for good
	sl := &siem.Syslog{Addr: "logs.evil.example:6514",
		Resolver: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
		}}
	err := sl.Send(context.Background(), []siem.Record{{Payload: []byte(`{}`)}})
	var se *siem.SendError
	if !errors.As(err, &se) || !se.Permanent || !strings.Contains(se.Msg, "blocked") {
		t.Errorf("rebinding to metadata: %v", err)
	}
	// loopback only with the dev exception
	sl = &siem.Syslog{Addr: "127.0.0.1:1"}
	if err := sl.Send(context.Background(), []siem.Record{{Payload: []byte(`{}`)}}); !errors.As(err, &se) || !se.Permanent {
		t.Errorf("loopback outside dev: %v", err)
	}
	// webhooks: the production safehttp client refuses the metadata address
	prod, err := safehttp.New(safehttp.Options{Env: config.Prod})
	if err != nil {
		t.Fatal(err)
	}
	if err := (&siem.Webhook{Client: prod, URL: "https://169.254.169.254/latest", Flavor: siem.FlavorJSON}).Send(context.Background(),
		[]siem.Record{{Payload: []byte(`{}`)}}); err == nil {
		t.Error("webhook to the metadata address succeeded")
	}
	// and validation refuses plain http and credentials in the URL
	for _, target := range []string{"http://siem.example/x", "https://u:p@siem.example/x"} {
		err := w.st.InTenant(context.Background(), w.st.Tenant, func(tx *store.TenantTx) error {
			_, err := siem.CreateSink(tx, w.sealer, siem.SinkSpec{Name: "x", Kind: "webhook", Format: siem.FormatJSON, Target: target,
				Flavor: siem.FlavorJSON, Enabled: true}, false, siem.Actor{}, w.now)
			return err
		})
		var e *siem.Error
		if !errors.As(err, &e) || e.Code != "invalid_target" {
			t.Errorf("%s: %v", target, err)
		}
	}
}

func TestTokenSealedAndValidation(t *testing.T) {
	w := newWorld(t)
	token := "super-secret-hec"
	k := w.create(t, siem.SinkSpec{Name: "Splunk", Kind: "webhook", Format: siem.FormatJSON, Target: "https://splunk.example:8088/services/collector",
		Flavor: siem.FlavorHEC, Token: &token, Enabled: true})
	if strings.Contains(string(k.SecretSealed), token) {
		t.Fatal("token stored in clear")
	}
	if _, err := w.sealer.Open(k.SecretSealed, siem.SecretAAD(w.st.Tenant, "other")); err == nil {
		t.Fatal("token opens under another row's AAD")
	}
	if b, err := w.sealer.Open(k.SecretSealed, siem.SecretAAD(w.st.Tenant, k.ID)); err != nil || string(b) != token {
		t.Fatalf("open %q %v", b, err)
	}
	evs := testkit.Get(t, w.st, func(tx *store.TenantTx) ([]*store.AuditEvent, error) {
		return tx.AuditEvents(store.AuditFilter{Action: "siem.sink.created"})
	})
	if len(evs) != 1 || strings.Contains(string(evs[0].Detail), token) || strings.Contains(string(evs[0].Detail), "/services") {
		t.Fatalf("audit detail %s", evs[0].Detail)
	}
	bad := []siem.SinkSpec{
		{Name: "", Kind: "webhook", Format: "json", Target: "https://x.example", Flavor: "json"},
		{Name: "x", Kind: "kafka", Format: "json", Target: "x"},
		{Name: "x", Kind: "webhook", Format: "cef", Target: "https://x.example", Flavor: "json"},
		{Name: "x", Kind: "webhook", Format: "json", Target: "https://x.example", Flavor: "elastic"},
		{Name: "x", Kind: "webhook", Format: "json", Target: "https://x.example", Flavor: "hec"}, // no token
		{Name: "x", Kind: "syslog", Format: "json", Target: "logs.example:99999"},
		{Name: "x", Kind: "syslog", Format: "json", Target: "logs.example:6514", CAPEM: "not pem"},
		{Name: "x", Kind: "webhook", Format: "json", Target: "https://x.example", Flavor: "json", Start: "yesterday"},
	}
	for i, s := range bad {
		err := w.st.InTenant(context.Background(), w.st.Tenant, func(tx *store.TenantTx) error {
			_, err := siem.CreateSink(tx, w.sealer, s, false, siem.Actor{}, w.now)
			return err
		})
		var e *siem.Error
		if !errors.As(err, &e) {
			t.Errorf("case %d accepted: %v", i, err)
		}
	}
	// the syslog port defaults to 6514
	k2 := w.create(t, siem.SinkSpec{Name: "Collector", Kind: "syslog", Format: "ocsf", Target: "logs.example", Enabled: true})
	if k2.Target != "logs.example:6514" {
		t.Errorf("target %q", k2.Target)
	}
	// rewinding replays; the kind is fixed
	w.write(t, func(tx *store.TenantTx) error {
		if _, err := siem.Rewind(tx, k2.ID, 0, siem.Actor{Display: "t"}, w.now); err != nil {
			return err
		}
		var e *siem.Error
		if _, err := siem.Rewind(tx, k2.ID, 1<<40, siem.Actor{}, w.now); !errors.As(err, &e) {
			t.Errorf("rewind past head: %v", err)
		}
		if _, err := siem.UpdateSink(tx, w.sealer, k2.ID, siem.SinkSpec{Name: "x", Kind: "webhook", Format: "json", Target: "https://x.example", Flavor: "json"}, false, siem.Actor{}, w.now); !errors.As(err, &e) || e.Code != "invalid_kind" {
			t.Errorf("kind change: %v", err)
		}
		return nil
	})
	if w.sink(t, k2.ID).CursorSeq != 0 {
		t.Error("rewind did not move the cursor")
	}
}
