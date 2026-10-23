package siem_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/siem"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The PUT Object example of the AWS Signature Version 4 documentation ("Authenticating Requests: Using the
// Authorization Header"): the signature must match what AWS publishes for it.
func TestSignV4_AWSExample(t *testing.T) {
	body := []byte("Welcome to Amazon S3.")
	req, err := http.NewRequest(http.MethodPut, "https://examplebucket.s3.amazonaws.com/test%24file.text", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Date", "Fri, 24 May 2013 00:00:00 GMT")
	req.Header.Set("X-Amz-Storage-Class", "REDUCED_REDUNDANCY")
	siem.SignV4(req, body, "us-east-1", "s3", "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC))
	want := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request," +
		" SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class," +
		" Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
	if got := req.Header.Get("Authorization"); got != want {
		t.Errorf("Authorization\n got  %s\n want %s", got, want)
	}
	if got := req.Header.Get("X-Amz-Content-Sha256"); got != "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072" {
		t.Errorf("payload hash %s", got)
	}
}

func TestEventMatches(t *testing.T) {
	for _, tc := range []struct {
		filter []string
		action string
		want   bool
	}{
		{nil, "grant.revoke", true},
		{[]string{}, "http.request", true},
		{[]string{"grant.revoke"}, "grant.revoke", true},
		{[]string{"grant.revoke"}, "grant.revoke.all", false},
		{[]string{"grant.*"}, "grant.revoke", true},
		{[]string{"grant.*"}, "grantee.added", false},
		{[]string{"grant.*"}, "grant", false},
		{[]string{"auth.login", "grant.*"}, "auth.login", true},
		{[]string{"auth.login", "grant.*"}, "auth.logout", false},
		{[]string{"*"}, "anything.at.all", true},
	} {
		if got := siem.EventMatches(tc.filter, tc.action); got != tc.want {
			t.Errorf("EventMatches(%v, %q) = %t, want %t", tc.filter, tc.action, got, tc.want)
		}
	}
}

func TestNormalizeFilter(t *testing.T) {
	got, err := siem.NormalizeFilter([]string{" Grant.* ", "grant.*", "", "auth.login"})
	if err != nil || strings.Join(got, ",") != "grant.*,auth.login" {
		t.Errorf("normalize = %v, %v", got, err)
	}
	for _, bad := range []string{"grant.*.x", "gr ant", "grant..x", "a/b", "*.x", strings.Repeat("a", 101), "grant.%"} {
		if _, err := siem.NormalizeFilter([]string{bad}); err == nil {
			t.Errorf("filter entry %q accepted", bad)
		}
	}
	many := make([]string, siem.MaxFilterEntries+1)
	for i := range many {
		many[i] = "a" + strings.Repeat("b", i%5) + "." + strings.Repeat("c", i/5+1)
	}
	if _, err := siem.NormalizeFilter(many); err == nil {
		t.Error("an oversized filter was accepted")
	}
}

// A sink with a filter sends only the matching actions, and its cursor still moves past the rest.
func TestEventFilterDelivery(t *testing.T) {
	w := newWorld(t)
	k := w.create(t, siem.SinkSpec{Name: "SIEM", Kind: "webhook", Format: siem.FormatJSON, Target: "https://siem.example/x",
		Flavor: siem.FlavorJSON, Enabled: true, Start: "beginning", EventFilter: []string{"Grant.*"}})
	if len(k.EventFilter) != 1 || k.EventFilter[0] != "grant.*" {
		t.Fatalf("stored filter %v", k.EventFilter)
	}
	w.write(t, func(tx *store.TenantTx) error {
		for _, a := range []string{"grant.revoke", "auth.login", "grant.add", "request.created"} {
			if _, err := audit.Record(context.Background(), tx, a, nil, audit.At(w.now)); err != nil {
				return err
			}
		}
		return nil
	})
	rec := &recorder{}
	w.tick(t, w.service(rec))
	var actions []string
	for _, b := range rec.batches {
		for _, r := range b {
			actions = append(actions, r.Action)
		}
	}
	// siem.* always matches (issue #511): the sink's own creation is delivered whatever the filter says
	if strings.Join(actions, ",") != "siem.sink.created,grant.revoke,grant.add" {
		t.Errorf("sent %v", actions)
	}
	if got := w.sink(t, k.ID); got.CursorSeq != w.head(t) || got.DeliveredCount != 3 {
		t.Errorf("cursor %d (head %d), delivered %d", got.CursorSeq, w.head(t), got.DeliveredCount)
	}
}

func TestS3Sink(t *testing.T) {
	w := newWorld(t)
	var mu sync.Mutex
	type put struct{ path, auth, sha, body string }
	var puts []put
	status := http.StatusServiceUnavailable
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		if r.Method != http.MethodPut {
			t.Errorf("method %s", r.Method)
		}
		puts = append(puts, put{r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("X-Amz-Content-Sha256"), string(b)})
		rw.WriteHeader(status)
	}))
	defer srv.Close()
	secret := "s3cr3t/ACCESS+key"
	k := w.create(t, siem.SinkSpec{Name: "Bucket", Kind: "s3", Format: siem.FormatJSON, Target: srv.URL + "/audit-bucket/tessera", Region: "eu-west-1",
		AccessKeyID: "AKIAEXAMPLE12345", Token: &secret, Enabled: true, Start: "beginning"})
	w.events(t, 3)
	client, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	svc := &siem.Service{DB: w.st.DB, Sealer: w.sealer, HTTP: client, Clock: func() time.Time { return w.now }, Dev: true}

	w.tick(t, svc) // the bucket answers 503: nothing is acknowledged
	if got := w.sink(t, k.ID); got.CursorSeq != 0 || got.Attempts != 1 || got.LastError == nil || !strings.Contains(*got.LastError, "HTTP 503") {
		t.Fatalf("after a 503: %+v", got)
	}
	status = http.StatusOK
	w.now = w.now.Add(time.Minute)
	w.tick(t, svc)
	mu.Lock()
	defer mu.Unlock()
	if len(puts) != 2 {
		t.Fatalf("%d PUTs", len(puts))
	}
	// the retry replaces the same object: no duplicate in the bucket
	if puts[0].path != puts[1].path || puts[0].body != puts[1].body {
		t.Errorf("retry went to another object: %s vs %s", puts[0].path, puts[1].path)
	}
	p := puts[1]
	if !strings.HasPrefix(p.path, "/audit-bucket/tessera/tiny/") || !strings.HasSuffix(p.path, ".ndjson") {
		t.Errorf("object path %s", p.path)
	}
	if !strings.HasPrefix(p.auth, "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE12345/") || !strings.Contains(p.auth, "/eu-west-1/s3/aws4_request") ||
		!strings.Contains(p.auth, "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date,") {
		t.Errorf("Authorization %s", p.auth)
	}
	if strings.Contains(p.auth, secret) || len(p.sha) != 64 {
		t.Errorf("secret leaked or no payload hash: %s %s", p.auth, p.sha)
	}
	lines := strings.Split(strings.TrimSpace(p.body), "\n")
	if len(lines) < 3 || !strings.Contains(p.body, `"action":"grant.revoke"`) {
		t.Errorf("body: %s", p.body)
	}
	got := w.sink(t, k.ID)
	if got.CursorSeq != w.head(t) || got.Attempts != 0 || got.Region != "eu-west-1" || got.AccessKeyID != "AKIAEXAMPLE12345" {
		t.Errorf("after delivery: %+v", got)
	}
	if strings.Contains(string(got.SecretSealed), secret) {
		t.Error("the secret access key is stored in the clear")
	}
}

func TestS3SinkValidation(t *testing.T) {
	w := newWorld(t)
	secret := "x"
	base := siem.SinkSpec{Name: "B", Kind: "s3", Format: siem.FormatJSON, Target: "https://s3.eu-west-1.amazonaws.com/b", Region: "eu-west-1",
		AccessKeyID: "AKIAEXAMPLE12345", Token: &secret, Enabled: true}
	mut := func(f func(*siem.SinkSpec)) siem.SinkSpec { s := base; f(&s); return s }
	for name, s := range map[string]siem.SinkSpec{
		"http":          mut(func(s *siem.SinkSpec) { s.Target = "http://s3.example/b" }),
		"credentials":   mut(func(s *siem.SinkSpec) { s.Target = "https://u:p@s3.example/b" }),
		"query":         mut(func(s *siem.SinkSpec) { s.Target = "https://s3.example/b?x=1" }),
		"no region":     mut(func(s *siem.SinkSpec) { s.Region = "" }),
		"bad region":    mut(func(s *siem.SinkSpec) { s.Region = "EU West" }),
		"no key id":     mut(func(s *siem.SinkSpec) { s.AccessKeyID = "" }),
		"key id spaces": mut(func(s *siem.SinkSpec) { s.AccessKeyID = "AKIA EXAMPLE" }),
		"no secret":     mut(func(s *siem.SinkSpec) { s.Token = nil }),
		"empty secret":  mut(func(s *siem.SinkSpec) { e := ""; s.Token = &e }),
		"bad filter":    mut(func(s *siem.SinkSpec) { s.EventFilter = []string{"a b"} }),
	} {
		var err error
		if werr := w.st.InTenant(audit.WithSystemActor(context.Background(), "test"), w.st.Tenant, func(tx *store.TenantTx) error {
			_, err = siem.CreateSink(tx, w.sealer, s, true, siem.Actor{Display: "test"}, w.now)
			return nil
		}); werr != nil {
			t.Fatal(werr)
		}
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	k := w.create(t, base)
	// a new access key id needs its secret; a new origin needs one too
	w.write(t, func(tx *store.TenantTx) error {
		s := base
		s.Token, s.AccessKeyID = nil, "AKIAOTHERKEY9999"
		if _, err := siem.UpdateSink(tx, w.sealer, k.ID, s, true, siem.Actor{Display: "test"}, w.now); err == nil {
			t.Error("a new access key id kept the old secret")
		}
		s = base
		s.Token, s.Target = nil, "https://s3.attacker.example/b"
		if _, err := siem.UpdateSink(tx, w.sealer, k.ID, s, true, siem.Actor{Display: "test"}, w.now); err == nil {
			t.Error("the secret followed the sink to another origin")
		}
		s = base
		s.Token, s.EventFilter = nil, []string{"auth.*"}
		u, err := siem.UpdateSink(tx, w.sealer, k.ID, s, true, siem.Actor{Display: "test"}, w.now)
		if err != nil || len(u.SecretSealed) == 0 || len(u.EventFilter) != 1 {
			t.Errorf("a filter-only edit: %+v, %v", u, err)
		}
		return nil
	})
}
