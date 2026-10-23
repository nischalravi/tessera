package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/alerts"
	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/samlsp"
	"github.com/nischalravi/tessera/mvp/server/internal/certs"
	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/queue"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// testCertPEM makes a self-signed RSA certificate and its PKCS#8 key.
func testCertPEM(t *testing.T, bits int, notBefore, notAfter time.Time, sig x509.SignatureAlgorithm) (certPEM, keyPEM string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: new(big.Int).SetInt64(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "client.example"},
		DNSNames: []string{"client.example"}, NotBefore: notBefore, NotAfter: notAfter, SignatureAlgorithm: sig}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}))
}

func jsonStr(v any) string { b, _ := json.Marshal(v); return string(b) }

// seedSAMLSPConnection adds a SAML connection with a sealed SP key and returns it.
func seedSAMLSPConnection(t *testing.T, f *storetest.Fixture, tn tenancy.ID, sl *seal.Sealer, name string) *store.IdPConnection {
	t.Helper()
	keyPEM, certPEM, err := samlsp.GenerateSPKey(name, storetest.Now)
	if err != nil {
		t.Fatal(err)
	}
	idpPEM, _ := testCertPEM(t, 2048, storetest.Now.Add(-time.Hour), storetest.Now.AddDate(1, 0, 0), x509.SHA256WithRSA)
	entity, sso := "https://idp.example/"+name, "https://idp.example/sso"
	conn := &store.IdPConnection{ID: uuid.New(), Name: name, Protocol: "saml", Profile: store.ProfileGenericSAML, Status: "active",
		IdPEntityID: &entity, IdPSSOURL: &sso, IdPSigningCerts: json.RawMessage(jsonStr([]string{idpPEM})), SPCertPEM: &certPEM,
		CreatedAt: storetest.Now, UpdatedAt: storetest.Now}
	if err := f.DB.InTenant(context.Background(), tn, func(tx *store.TenantTx) error {
		var err error
		if conn.SPKeyEnc, err = sl.Seal(keyPEM, auth.SPKeyAAD(tn, conn.ID)); err != nil {
			return err
		}
		return tx.InsertIdPConnection(conn)
	}); err != nil {
		t.Fatal(err)
	}
	return conn
}

func certList(t *testing.T, h http.Handler, l authtest.Login) []certView {
	t.Helper()
	rec := reqDo(h, l, "GET", "/api/admin/certificates", "")
	var out []certView
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != 200 {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	return out
}

func findCert(vs []certView, pred func(certView) bool) *certView {
	for i := range vs {
		if pred(vs[i]) {
			return &vs[i]
		}
	}
	return nil
}

func metadata(h http.Handler, conn uuid.UUID) *httptest.ResponseRecorder {
	return serve(h, httptest.NewRequest("GET", "/api/auth/saml/"+conn.String()+"/metadata", nil))
}

func TestCertificatesAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	sl := testSealer()
	srv := newIsolationServerWith(f, func(c *Config) { c.Sealer = sl })
	h := srv.Handler()
	now := storetest.Now
	admin := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, now)
	stale := signIn(t, f.DB, f.B.ID, authtest.User{Email: "stale@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: now.Add(-20 * time.Minute)}, now)
	auditor := signIn(t, f.DB, f.B.ID, authtest.User{Email: "au@b.example", Roles: []auth.Role{auth.RoleAuditor}}, authtest.Phr, now)
	operator := signIn(t, f.DB, f.B.ID, authtest.User{Email: "op@b.example", Roles: []auth.Role{auth.RoleOperator}}, authtest.Phr, now)
	adminA := signIn(t, f.DB, f.A.ID, authtest.User{Email: "ta@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, now)
	conn := seedSAMLSPConnection(t, f, f.B.ID, sl, "Okta SAML")
	connA := seedSAMLSPConnection(t, f, f.A.ID, sl, "A SAML")

	// listing: the connection's SP certificate is there with its details; the roles
	list := certList(t, h, auditor)
	sp := findCert(list, func(c certView) bool { return c.Source == certs.SourceSAMLConnection })
	if sp == nil || sp.Status != "active" || sp.Subject == "" || sp.Issuer == "" || sp.NotAfter == nil || len(sp.Fingerprint) != 64 ||
		!strings.Contains(sp.UsedBy, "Okta SAML") || sp.KeyAlgorithm != "RSA-2048" || sp.CanRetire || sp.CanPromote {
		t.Fatalf("SP certificate entry: %+v", sp)
	}
	if findCert(list, func(c certView) bool { return c.Source == certs.SourceSigningKey }) == nil && len(list) < 1 {
		t.Errorf("list: %+v", list)
	}
	if rec := reqDo(h, operator, "GET", "/api/admin/certificates", ""); rec.Code != 403 {
		t.Errorf("operator list: %d", rec.Code)
	}
	if strings.Contains(jsonStr(certList(t, h, adminA)), conn.ID.String()) {
		t.Error("tenant A lists tenant B's connection")
	}

	// uploads are refused for the wrong role, a stale sign-in and bad input
	c1, k1 := testCertPEM(t, 2048, now.Add(-time.Hour), now.AddDate(0, 0, 20), x509.SHA256WithRSA)
	up := jsonStr(map[string]any{"purpose": "mtls_client", "label": "Workday mTLS", "certificate_pem": c1, "private_key_pem": k1})
	if rec := reqDo(h, auditor, "POST", "/api/admin/certificates", up); rec.Code != 403 {
		t.Errorf("auditor upload: %d", rec.Code)
	}
	if rec := reqDo(h, stale, "POST", "/api/admin/certificates", up); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Errorf("stale upload: %d %s", rec.Code, rec.Body)
	}
	expired, expiredK := testCertPEM(t, 2048, now.AddDate(-2, 0, 0), now.AddDate(0, 0, -1), x509.SHA256WithRSA)
	weak, weakK := testCertPEM(t, 1024, now.Add(-time.Hour), now.AddDate(1, 0, 0), x509.SHA256WithRSA)
	sha1, sha1K := testCertPEM(t, 2048, now.Add(-time.Hour), now.AddDate(1, 0, 0), x509.SHA1WithRSA)
	_, otherK := testCertPEM(t, 2048, now.Add(-time.Hour), now.AddDate(1, 0, 0), x509.SHA256WithRSA)
	for _, tc := range []struct{ name, body, code string }{
		{"expired", jsonStr(map[string]any{"purpose": "signing", "label": "x", "certificate_pem": expired, "private_key_pem": expiredK}), "cert_expired"},
		{"weak key", jsonStr(map[string]any{"purpose": "signing", "label": "x", "certificate_pem": weak, "private_key_pem": weakK}), "weak_key"},
		{"sha1", jsonStr(map[string]any{"purpose": "signing", "label": "x", "certificate_pem": sha1, "private_key_pem": sha1K}), "weak_signature"},
		{"mismatch", jsonStr(map[string]any{"purpose": "signing", "label": "x", "certificate_pem": c1, "private_key_pem": otherK}), "key_mismatch"},
		{"not pem", jsonStr(map[string]any{"purpose": "signing", "label": "x", "certificate_pem": "nope", "private_key_pem": k1}), "bad_pem"},
		{"purpose", jsonStr(map[string]any{"purpose": "tls", "label": "x", "certificate_pem": c1, "private_key_pem": k1}), "invalid_purpose"},
		{"label", jsonStr(map[string]any{"purpose": "signing", "label": " ", "certificate_pem": c1, "private_key_pem": k1}), "invalid_label"},
		{"saml without a connection", jsonStr(map[string]any{"purpose": "saml_sp", "label": "x", "certificate_pem": c1, "private_key_pem": k1}), "invalid_connection"},
		{"connector on a signing cert", jsonStr(map[string]any{"purpose": "signing", "label": "x", "certificate_pem": c1, "private_key_pem": k1, "connection_id": "c1"}), "invalid_connection"},
		{"A's SAML connection", jsonStr(map[string]any{"purpose": "saml_sp", "label": "x", "certificate_pem": c1, "private_key_pem": k1, "connection_id": connA.ID.String()}), "not_found"},
		{"unknown connector", jsonStr(map[string]any{"purpose": "mtls_client", "label": "x", "certificate_pem": c1, "private_key_pem": k1, "connection_id": "nope"}), "not_found"},
	} {
		rec := reqDo(h, admin, "POST", "/api/admin/certificates", tc.body)
		if (rec.Code != 422 && rec.Code != 404) || !strings.Contains(rec.Body.String(), tc.code) {
			t.Errorf("%s: %d %s", tc.name, rec.Code, rec.Body)
		}
		if strings.Contains(rec.Body.String(), "PRIVATE KEY") {
			t.Errorf("%s: the response echoes a private key", tc.name)
		}
	}
	if rec := reqDo(h, admin, "POST", "/api/admin/certificates", `{"purpose":"signing","bogus":1}`); rec.Code != 422 {
		t.Errorf("unknown field: %d", rec.Code)
	}

	// a valid upload: stored sealed, never returned, listed with its expiry warning
	rec := reqDo(h, admin, "POST", "/api/admin/certificates", up)
	if rec.Code != 201 || strings.Contains(rec.Body.String(), "PRIVATE KEY") || strings.Contains(rec.Body.String(), "key_sealed") {
		t.Fatalf("upload: %d %s", rec.Code, rec.Body)
	}
	var up1 certView
	_ = json.Unmarshal(rec.Body.Bytes(), &up1)
	if up1.Status != "active" || up1.Purpose != "mtls_client" || up1.ExpiryWarning != certs.ExpiryWarn30 || up1.DaysLeft == nil || *up1.DaysLeft != 20 ||
		!strings.Contains(strings.Join(up1.SANs, ","), "DNS:client.example") || !up1.CanRetire {
		t.Errorf("uploaded entry: %+v", up1)
	}
	if rec := reqDo(h, admin, "POST", "/api/admin/certificates", up); rec.Code != 409 || !strings.Contains(rec.Body.String(), "duplicate_certificate") {
		t.Errorf("same certificate twice: %d %s", rec.Code, rec.Body)
	}
	_ = f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		id := strings.TrimPrefix(up1.ID, "cert:")
		sealed, err := tx.CertificateKey(id)
		if err != nil || strings.Contains(string(sealed), "PRIVATE KEY") || len(sealed) == 0 {
			t.Errorf("stored key is not sealed: %v", err)
		}
		if _, err := sl.Open(sealed, certs.KeyAAD(f.B.ID, id)); err != nil {
			t.Errorf("sealed key does not open under its AAD: %v", err)
		}
		if _, err := sl.Open(sealed, certs.KeyAAD(f.A.ID, id)); err == nil {
			t.Error("sealed key opens under another tenant's AAD")
		}
		return nil
	})

	// rotation: upload a replacement SAML SP key; it is published beside the active one
	before := metadata(h, conn.ID)
	if before.Code != 200 || strings.Count(before.Body.String(), "<X509Certificate ") != 1 {
		t.Fatalf("metadata before: %d %s", before.Code, before.Body)
	}
	nc, nk := testCertPEM(t, 2048, now.Add(-time.Hour), now.AddDate(2, 0, 0), x509.SHA256WithRSA)
	rec = reqDo(h, admin, "POST", "/api/admin/certificates", jsonStr(map[string]any{"purpose": "saml_sp", "label": "SP 2027", "certificate_pem": nc,
		"private_key_pem": nk, "connection_id": conn.ID.String()}))
	if rec.Code != 201 {
		t.Fatalf("upload SAML SP: %d %s", rec.Code, rec.Body)
	}
	var next certView
	_ = json.Unmarshal(rec.Body.Bytes(), &next)
	if next.Status != "next" || !next.CanPromote || !next.CanRetire || !strings.Contains(next.UsedBy, "Okta SAML") {
		t.Errorf("next entry: %+v", next)
	}
	overlap := metadata(h, conn.ID)
	if strings.Count(overlap.Body.String(), "<X509Certificate ") != 2 {
		t.Errorf("metadata during the overlap lists %d certificates, want 2:\n%s", strings.Count(overlap.Body.String(), "<X509Certificate "), overlap.Body)
	}
	if rec := reqDo(h, admin, "POST", "/api/admin/certificates/generate", jsonStr(map[string]string{"connection_id": conn.ID.String()})); rec.Code != 409 || !strings.Contains(rec.Body.String(), "rotation_in_progress") {
		t.Errorf("second waiting key: %d %s", rec.Code, rec.Body)
	}
	// the active key is untouched: it cannot be retired
	if rec := reqDo(h, admin, "POST", "/api/admin/certificates/"+strings.TrimPrefix(next.ID, "cert:")+"/promote", ""); rec.Code != 200 {
		t.Fatalf("promote: %d %s", rec.Code, rec.Body)
	} else if !strings.Contains(rec.Body.String(), `"status":"active"`) {
		t.Errorf("promote body: %s", rec.Body)
	}
	after := metadata(h, conn.ID)
	if strings.Count(after.Body.String(), "<X509Certificate ") != 1 || after.Body.String() == before.Body.String() {
		t.Errorf("metadata after the promotion:\n%s", after.Body)
	}
	_ = f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		c, err := tx.IdPConnection(conn.ID)
		if err != nil {
			t.Fatal(err)
		}
		keyPEM, err := sl.Open(c.SPKeyEnc, auth.SPKeyAAD(f.B.ID, conn.ID))
		if err != nil {
			t.Fatalf("connection SP key: %v", err)
		}
		if _, _, err := samlsp.ParseSPKey(keyPEM, *c.SPCertPEM); err != nil {
			t.Errorf("the promoted key does not match the promoted certificate: %v", err)
		}
		if !strings.Contains(*c.SPCertPEM, strings.TrimSpace(strings.Split(nc, "\n")[1])) {
			t.Error("the connection does not hold the uploaded certificate")
		}
		return nil
	})
	list = certList(t, h, auditor)
	active := findCert(list, func(c certView) bool { return c.Purpose == "saml_sp" && c.Status == "active" })
	retired := findCert(list, func(c certView) bool { return c.Purpose == "saml_sp" && c.Status == "retired" })
	if active == nil || retired == nil || active.CanRetire || retired.CanRetire || retired.CanPromote || active.Fingerprint == retired.Fingerprint {
		t.Fatalf("after promotion: active %+v retired %+v", active, retired)
	}
	if n := len(certsOf(list, "saml_sp")); n != 2 {
		t.Errorf("%d SAML SP entries after the promotion, want the active one and the retired one: %+v", n, list)
	}
	if rec := reqDo(h, admin, "POST", "/api/admin/certificates/"+strings.TrimPrefix(next.ID, "cert:")+"/retire", ""); rec.Code != 409 || !strings.Contains(rec.Body.String(), "in_use") {
		t.Errorf("retire the active SP key: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "POST", "/api/admin/certificates/"+strings.TrimPrefix(next.ID, "cert:")+"/promote", ""); rec.Code != 409 {
		t.Errorf("promote twice: %d %s", rec.Code, rec.Body)
	}

	// generate a key pair, then discard it: the active one never changes
	rec = reqDo(h, admin, "POST", "/api/admin/certificates/generate", jsonStr(map[string]string{"connection_id": conn.ID.String()}))
	var gen certView
	_ = json.Unmarshal(rec.Body.Bytes(), &gen)
	if rec.Code != 201 || gen.Status != "next" || gen.KeyAlgorithm != "RSA-2048" || strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Fatalf("generate: %d %s", rec.Code, rec.Body)
	}
	if strings.Count(metadata(h, conn.ID).Body.String(), "<X509Certificate ") != 2 {
		t.Error("a generated key is not published in the metadata")
	}
	if rec := reqDo(h, admin, "POST", "/api/admin/certificates/"+strings.TrimPrefix(gen.ID, "cert:")+"/retire", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"status":"retired"`) {
		t.Errorf("discard: %d %s", rec.Code, rec.Body)
	}
	if strings.Count(metadata(h, conn.ID).Body.String(), "<X509Certificate ") != 1 {
		t.Error("a discarded key is still published")
	}
	if rec := reqDo(h, admin, "POST", "/api/admin/certificates/generate", jsonStr(map[string]string{"connection_id": "nope"})); rec.Code != 422 {
		t.Errorf("generate for a bad id: %d", rec.Code)
	}
	if rec := reqDo(h, admin, "POST", "/api/admin/certificates/generate", jsonStr(map[string]string{"connection_id": connA.ID.String()})); rec.Code != 404 {
		t.Errorf("generate for A's connection: %d %s", rec.Code, rec.Body)
	}

	// another tenant's certificate id looks nonexistent
	if rec := reqDo(h, adminA, "POST", "/api/admin/certificates/"+strings.TrimPrefix(up1.ID, "cert:")+"/retire", ""); rec.Code != 404 {
		t.Errorf("A retires B's certificate: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "POST", "/api/admin/certificates/"+strings.TrimPrefix(up1.ID, "cert:")+"/retire", ""); rec.Code != 200 {
		t.Errorf("retire: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "POST", "/api/admin/certificates/"+strings.TrimPrefix(up1.ID, "cert:")+"/retire", ""); rec.Code != 409 {
		t.Errorf("retire twice: %d", rec.Code)
	}
	_ = f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		if k, _ := tx.CertificateKey(strings.TrimPrefix(up1.ID, "cert:")); len(k) != 0 {
			t.Error("a retired certificate keeps its key")
		}
		return nil
	})

	// every change is in the audit ledger, with no key material
	actions := map[string]int{}
	_ = f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		evs, err := tx.AuditLog(0)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range evs {
			actions[e.Action]++
			if b, _ := json.Marshal(e.Detail); strings.Contains(string(b), "PRIVATE KEY") {
				t.Errorf("audit event %s holds key material", e.Action)
			}
		}
		return nil
	})
	for a, n := range map[string]int{"certificate.uploaded": 2, "certificate.generated": 1, "certificate.promoted": 1, "certificate.retired": 2} {
		if actions[a] != n {
			t.Errorf("%d %s events, want %d (%v)", actions[a], a, n, actions)
		}
	}
}

func certsOf(vs []certView, purpose string) []certView {
	var out []certView
	for _, v := range vs {
		if v.Purpose == purpose {
			out = append(out, v)
		}
	}
	return out
}

// TestCertificateExpiryAlerts: the daily queue job raises an alert through the alerts engine 30 and 7 days
// before a certificate expires, once per threshold, and clears it when the certificate is rotated.
func TestCertificateExpiryAlerts(t *testing.T) {
	f := storetest.TwoTenants(t)
	sl := testSealer()
	srv := newIsolationServerWith(f, func(c *Config) { c.Sealer = sl })
	now := storetest.Now
	day := 24 * time.Hour
	add := func(tn tenancy.ID, label string, left time.Duration, status string) string {
		id := uuid.NewString()
		c := &store.TenantCertificate{ID: id, Purpose: store.CertSigning, Label: label, Status: status, CertPEM: "x", Subject: "CN=" + label,
			Issuer: "CN=ca", NotBefore: now.Add(-365 * day), NotAfter: now.Add(left), Fingerprint: strings.Repeat(label[:1], 64),
			KeyAlgorithm: "RSA-2048", SigAlgorithm: "SHA256-RSA", CreatedBy: "t", CreatedAt: now}
		if status != store.CertRetired {
			c.KeySealed = []byte("k")
		}
		if err := f.DB.InTenant(context.Background(), tn, func(tx *store.TenantTx) error { return tx.InsertCertificate(c) }); err != nil {
			t.Fatal(err)
		}
		return id
	}
	add(f.B.ID, "far", 90*day, store.CertActive)
	add(f.B.ID, "month", 20*day, store.CertActive)
	week := add(f.B.ID, "week", 5*day, store.CertActive)
	add(f.B.ID, "gone", -3*day, store.CertActive)
	add(f.B.ID, "retired", 2*day, store.CertRetired)
	add(f.A.ID, "other", 3*day, store.CertActive)

	run := func(at time.Time) {
		t.Helper()
		srv.clock = func() time.Time { return at }
		if _, err := srv.queueCertificateExpiry(audit.WithSystemActor(context.Background(), "certificate.sweeper"), queue.Job{Tenant: f.B.ID}); err != nil {
			t.Fatal(err)
		}
	}
	titles := func() map[string]int {
		out := map[string]int{}
		_ = f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
			as, err := tx.LiveAlertsOfRule("certificate_expiry")
			if err != nil {
				t.Fatal(err)
			}
			for _, a := range as {
				out[a.Title]++
			}
			return nil
		})
		return out
	}
	run(now)
	got := titles()
	if len(got) != 3 || got[`Certificate "month" expires in 20 days`] != 1 || got[`Certificate "week" expires in 5 days`] != 1 || got[`Certificate "gone" expired 3 days ago`] != 1 {
		t.Fatalf("alerts after the first run: %v", got)
	}
	run(now)
	if g := titles(); len(g) != 3 {
		t.Errorf("a second run the same day duplicated alerts: %v", g)
	}
	// 16 days later "month" is at 4 days: its 30-day alert gives way to the 7-day one
	run(now.Add(16 * day))
	got = titles()
	if got[`Certificate "month" expires in 4 days`] != 1 || got[`Certificate "month" expires in 20 days`] != 0 {
		t.Errorf("30 to 7 day transition: %v", got)
	}
	// rotating (retiring) the certificate clears its alert
	if err := f.DB.InTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error { return tx.RetireCertificate(week, now) }); err != nil {
		t.Fatal(err)
	}
	run(now.Add(16 * day))
	for title := range titles() {
		if strings.Contains(title, `"week"`) {
			t.Errorf("the alert of a retired certificate is still live: %s", title)
		}
	}
	// tenant A's certificate raised nothing for B, and the rule is the engine's, so it can be switched off
	_ = f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		for _, r := range alerts.Rules {
			if r.ID == "certificate_expiry" && r.Kind != "scheduled" {
				t.Errorf("rule kind %q", r.Kind)
			}
		}
		if _, _, err := alerts.RunScheduled(tx, now, "no_such_rule"); err == nil {
			t.Error("an unknown scheduled rule ran")
		}
		return nil
	})
	if !contains(jobs.Kinds, jobs.CertificateExpiry) || !contains(srv.Queue().Kinds(), jobs.CertificateExpiry) {
		t.Error("the certificate expiry job is not registered with the queue")
	}
}

// testChain makes a root, an intermediate and a leaf signed by it (ECDSA P-256) and returns their PEM and the leaf key.
func testChain(t *testing.T, now time.Time) (leaf, inter, root, leafKey string) {
	t.Helper()
	mk := func(cn string, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (string, *x509.Certificate, *ecdsa.PrivateKey) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, NotBefore: now.Add(-time.Hour),
			NotAfter: now.AddDate(1, 0, 0), BasicConstraintsValid: true, IsCA: isCA, DNSNames: []string{cn + ".example"}}
		issuer, signer := tmpl, key
		if parent != nil {
			issuer, signer = parent, parentKey
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, key.Public(), signer)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), c, key
	}
	rootPEM, rootC, rootK := mk("root", true, nil, nil)
	interPEM, interC, interK := mk("inter", true, rootC, rootK)
	leafPEM, _, leafK := mk("leaf", false, interC, interK)
	kb, err := x509.MarshalPKCS8PrivateKey(leafK)
	if err != nil {
		t.Fatal(err)
	}
	return leafPEM, interPEM, rootPEM, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}))
}

// An mTLS upload may be a chain with trust anchors; it is handed to the connection it names, shows its chain and
// anchors in the inventory, and the audit event records counts but no PEM or key.
func TestCertificatesAPI_MTLSChainAndTrustAnchors(t *testing.T) {
	f := storetest.TwoTenants(t)
	sl := testSealer()
	h := newIsolationServerWith(f, func(c *Config) { c.Sealer = sl }).Handler()
	now := storetest.Now
	admin := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, now)
	leaf, inter, root, key := testChain(t, now)
	connB := f.B.Refs["connection:ad"]
	post := func(m map[string]any) *httptest.ResponseRecorder {
		return reqDo(h, admin, "POST", "/api/admin/certificates", jsonStr(m))
	}
	// trust anchors belong to mutual-TLS uploads only; a broken chain is refused
	if rec := post(map[string]any{"purpose": "signing", "label": "x", "certificate_pem": leaf, "private_key_pem": key, "trust_anchors_pem": root}); rec.Code != 422 ||
		!strings.Contains(rec.Body.String(), "invalid_trust_anchors") {
		t.Errorf("trust anchors on a signing certificate: %d %s", rec.Code, rec.Body)
	}
	if rec := post(map[string]any{"purpose": "mtls_client", "label": "x", "certificate_pem": inter + leaf, "private_key_pem": key}); rec.Code != 422 ||
		!strings.Contains(rec.Body.String(), "bad_chain") {
		t.Errorf("a chain with the issuer first: %d %s", rec.Code, rec.Body)
	}
	if rec := post(map[string]any{"purpose": "mtls_client", "label": "x", "certificate_pem": leaf, "private_key_pem": key, "trust_anchors_pem": leaf}); rec.Code != 422 ||
		!strings.Contains(rec.Body.String(), "bad_trust_anchor") {
		t.Errorf("a leaf as trust anchor: %d %s", rec.Code, rec.Body)
	}
	rec := post(map[string]any{"purpose": "mtls_client", "label": "SCIM mTLS", "certificate_pem": leaf + inter, "private_key_pem": key,
		"trust_anchors_pem": root, "connection_id": connB})
	if rec.Code != 201 || strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Fatalf("upload: %d %s", rec.Code, rec.Body)
	}
	var v certView
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if v.ChainLength != 2 || len(v.TrustAnchors) != 1 || v.TrustAnchors[0] != "CN=root" || v.Subject != "CN=leaf" || v.Status != "active" ||
		!strings.Contains(v.UsedBy, "connection") {
		t.Errorf("view = %+v", v)
	}
	_ = f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		c, err := tx.ActiveMTLSCertificate(connB)
		if err != nil || strings.Count(c.CertPEM, "BEGIN CERTIFICATE") != 2 || strings.Count(c.TrustPEM, "BEGIN CERTIFICATE") != 1 {
			t.Errorf("the connection's certificate = %+v, %v", c, err)
		}
		evs, err := tx.AuditEvents(store.AuditFilter{Action: "certificate.uploaded"})
		for _, e := range evs {
			d := string(e.Detail)
			if strings.Contains(d, "BEGIN") || !strings.Contains(d, `"chain_length":2`) || !strings.Contains(d, `"trust_anchors":1`) {
				t.Errorf("audit detail = %s", d)
			}
		}
		return err
	})
	// another tenant's connection cannot receive a certificate, and sees none of it
	adminA := signIn(t, f.DB, f.A.ID, authtest.User{Email: "ta@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, now)
	if rec := reqDo(h, adminA, "POST", "/api/admin/certificates", jsonStr(map[string]any{"purpose": "mtls_client", "label": "x", "certificate_pem": leaf,
		"private_key_pem": key, "connection_id": connB})); rec.Code != 404 {
		t.Errorf("tenant A hands a certificate to B's connection: %d %s", rec.Code, rec.Body)
	}
	_ = f.DB.ReadTenant(context.Background(), f.A.ID, func(tx *store.TenantTx) error {
		if _, err := tx.ActiveMTLSCertificate(connB); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("tenant A reads B's connection certificate: %v", err)
		}
		return nil
	})
}
