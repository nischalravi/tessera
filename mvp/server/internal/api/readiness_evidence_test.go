package api

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// unzip reads every file of an export response.
func unzip(t *testing.T, rec *httptest.ResponseRecorder) map[string][]byte {
	t.Helper()
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/zip" {
		t.Fatalf("export: status %d, type %q: %.200s", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
	}
	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		if out[f.Name], err = io.ReadAll(rc); err != nil {
			t.Fatal(err)
		}
		_ = rc.Close()
	}
	return out
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func exportManifest(t *testing.T, files map[string][]byte) readiness.Manifest {
	t.Helper()
	var m readiness.Manifest
	if err := json.Unmarshal(files["manifest.json"], &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// evidenceTenant is a tenant with a validated and dry-run Okta connection
// (planted findings with named samples) and one skipped item.
func evidenceTenant(t *testing.T) (rdClient, string) {
	c := newRD(t)
	okta := c.validatedConn("demo-okta", "Okta (demo)", "")
	c.json("POST", "/api/connections/"+okta+"/dry-run", "", http.StatusAccepted)
	c.json("POST", "/api/connections/"+okta+"/checklist/okta.auth.oauth/skip",
		`{"reason":"Migration to an OAuth service app is planned for Q1","review_by":"2026-10-20"}`, http.StatusOK)
	return c, okta
}

func TestEvidence_ManifestHashes(t *testing.T) {
	c, okta := evidenceTenant(t)
	for _, path := range []string{"/api/connections/" + okta + "/readiness/evidence", "/api/insights/deployment-health/evidence"} {
		rec := c.do("GET", path, "")
		if cd := rec.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment; filename=") {
			t.Errorf("%s: Content-Disposition %q", path, cd)
		}
		files := unzip(t, rec)
		m := exportManifest(t, files)
		want := []string{"checklist.csv", "checks.csv", "findings.csv", "skipped.csv", "score.json"}
		if len(m.Files) != len(want) || len(files) != len(want)+1 {
			t.Fatalf("%s: manifest lists %d files, zip holds %d: %+v", path, len(m.Files), len(files), m.Files)
		}
		for i, mf := range m.Files {
			data, ok := files[mf.Name]
			if !ok || mf.Name != want[i] {
				t.Fatalf("%s: manifest file %q (want %q, in zip %v)", path, mf.Name, want[i], ok)
			}
			if got := sha(data); got != mf.SHA256 || mf.Bytes != len(data) {
				t.Errorf("%s: %s hash %s, manifest %s", path, mf.Name, got, mf.SHA256)
			}
		}
		if len(m.Templates) != 1 || m.Templates[0].Template != "okta" || len(m.Templates[0].ConfigHash) != 64 {
			t.Errorf("%s: templates %+v", path, m.Templates)
		}
		if m.Ledger.ToSeq < 1 || len(m.Ledger.ChainHead) != 64 || m.Ledger.Verify == "" || m.GeneratedAt == "" {
			t.Errorf("%s: ledger %+v", path, m.Ledger)
		}
		text := string(files["manifest.json"])
		for _, ctl := range []string{"CC6.1", "Annex A 5.15", "IPE", "8.2.6", "does not claim"} {
			if !strings.Contains(text, ctl) {
				t.Errorf("%s: control mapping lacks %q", path, ctl)
			}
		}
		// The checklist and the skipped list carry the attester and the accepted gap.
		if !strings.Contains(string(files["checklist.csv"]), "base.owner") ||
			!strings.Contains(string(files["skipped.csv"]), "okta.auth.oauth") {
			t.Errorf("%s: checklist or skipped.csv incomplete", path)
		}
	}
	if rec := c.do("GET", "/api/connections/00000000-0000-0000-0000-000000000000/readiness/evidence", ""); rec.Code != http.StatusNotFound {
		t.Errorf("unknown connection: %d", rec.Code)
	}
}

func TestEvidence_LedgerEventMatchesManifest(t *testing.T) {
	c, okta := evidenceTenant(t)
	files := unzip(t, c.do("GET", "/api/connections/"+okta+"/readiness/evidence", ""))
	m := exportManifest(t, files)
	var head, ev *store.AuditEvent
	c.read(func(tx *store.TenantTx) error {
		var err error
		if head, err = tx.AuditEventBySeq(m.Ledger.ToSeq); err != nil {
			return err
		}
		// Written in the request's transaction: the export event is the next event.
		ev, err = tx.AuditEventBySeq(m.Ledger.ToSeq + 1)
		return err
	})
	if head.Hash != m.Ledger.ChainHead {
		t.Errorf("chain head %s, manifest %s", head.Hash, m.Ledger.ChainHead)
	}
	if ev.Action != readiness.EventEvidenceExported || ev.PrevHash != m.Ledger.ChainHead {
		t.Fatalf("event %s prev %s, want %s after %s", ev.Action, ev.PrevHash, readiness.EventEvidenceExported, m.Ledger.ChainHead)
	}
	var d map[string]any
	if err := json.Unmarshal(ev.Detail, &d); err != nil {
		t.Fatal(err)
	}
	if d["manifest_sha256"] != sha(files["manifest.json"]) || d["connection_id"] != okta || d["scope"] != "connection" ||
		d["to_seq"] != float64(m.Ledger.ToSeq) || d["chain_head"] != m.Ledger.ChainHead || d["files"] != float64(6) {
		t.Errorf("event detail %v does not match the manifest", d)
	}
	if rep := c.json("POST", "/api/audit/verify", "", http.StatusOK); rep["result"] != "ok" {
		t.Errorf("ledger after the export: %v", rep)
	}
	// The tenant export is audited too.
	tf := unzip(t, c.do("GET", "/api/insights/deployment-health/evidence", ""))
	tm := exportManifest(t, tf)
	c.read(func(tx *store.TenantTx) error {
		e, err := tx.AuditEventBySeq(tm.Ledger.ToSeq + 1)
		if err != nil {
			return err
		}
		if e.Action != readiness.EventEvidenceExported || !strings.Contains(string(e.Detail), sha(tf["manifest.json"])) ||
			!strings.Contains(string(e.Detail), `"scope":"tenant"`) {
			t.Errorf("tenant export event: %s %s", e.Action, e.Detail)
		}
		return nil
	})
}

func TestEvidence_NoSamplesBeyondIds(t *testing.T) {
	c, okta := evidenceTenant(t)
	// The findings API shows samples with names; the export must not.
	var fs []readiness.FindingView
	if err := json.Unmarshal(c.do("GET", "/api/connections/"+okta+"/findings", "").Body.Bytes(), &fs); err != nil {
		t.Fatal(err)
	}
	var refs, names []string
	for _, f := range fs {
		for _, sm := range f.Samples {
			refs = append(refs, sm.Ref)
			names = append(names, sm.Name, sm.Reason)
		}
	}
	if len(refs) == 0 || !strings.Contains(strings.Join(names, "|"), "oren.whitlock@larkspur.example") {
		t.Fatalf("the planted findings have no named samples: %v", names)
	}
	files := unzip(t, c.do("GET", "/api/connections/"+okta+"/readiness/evidence", ""))
	rows, err := csv.NewReader(bytes.NewReader(files["findings.csv"])).ReadAll()
	if err != nil || len(rows) < 2 {
		t.Fatalf("findings.csv: %v (%d rows)", err, len(rows))
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		col[h] = i
	}
	for _, h := range []string{"sample_names", "sample_reasons", "name", "reason"} {
		if _, ok := col[h]; ok {
			t.Errorf("findings.csv has a %q column", h)
		}
	}
	got := 0
	for _, r := range rows[1:] {
		for _, ref := range strings.Fields(r[col["sample_refs"]]) {
			got++
			if !contains(refs, ref) {
				t.Errorf("sample ref %q is not a sample id", ref)
			}
		}
	}
	if got == 0 {
		t.Error("findings.csv carries no sample ids")
	}
	for name, data := range files {
		for _, s := range names {
			// A name that is part of an id (svc/old-migration-token) is the id.
			inRef := slices.ContainsFunc(refs, func(ref string) bool { return strings.Contains(ref, s) })
			if s != "" && !inRef && strings.Contains(string(data), s) {
				t.Errorf("%s contains sample text %q", name, s)
			}
		}
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func TestEvidence_NeedsAuditRead(t *testing.T) {
	cases := []struct {
		name string
		p    *auth.Principal
		ok   bool
	}{
		{"auditor cookie", &auth.Principal{ActiveRoles: auth.RoleSet{auth.RoleAuditor: true}}, true},
		{"admin cookie", &auth.Principal{ActiveRoles: auth.RoleSet{auth.RoleTenantAdmin: true}}, true},
		{"auditor read-only token", &auth.Principal{ActiveRoles: auth.RoleSet{auth.RoleAuditor: true},
			Scopes: auth.ScopeSet{auth.ScopeRead: true}}, false},
		{"policy admin", &auth.Principal{ActiveRoles: auth.RoleSet{auth.RolePolicyAdmin: true}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			err := requireAuditRead(r.WithContext(auth.WithPrincipal(r.Context(), tc.p)))
			if (err == nil) != tc.ok {
				t.Errorf("err = %v, want ok=%v", err, tc.ok)
			}
		})
	}
	if requireAuditRead(httptest.NewRequest("GET", "/", nil)) == nil {
		t.Error("a request without a principal passed")
	}
}

// The export of a tenant holds that tenant's rows only (the zip is
// compressed, so the generic leak scan of the route tests cannot see inside).
func TestEvidence_TenantScoped(t *testing.T) {
	f := storetest.TwoTenants(t)
	export := func(tenant tenancy.ID, path string) string {
		rec := serveOnce(isolationServer(t, f, tenant).Handler(), http.MethodGet, path, "")
		var all strings.Builder
		for name, data := range unzip(t, rec) {
			all.WriteString(name + "\n" + string(data) + "\n")
		}
		return all.String()
	}
	for _, p := range []struct{ a, b string }{
		{"/api/insights/deployment-health/evidence", "/api/insights/deployment-health/evidence"},
		{"/api/connections/" + f.A.Refs["connection:ad"] + "/readiness/evidence",
			"/api/connections/" + f.B.Refs["connection:ad"] + "/readiness/evidence"},
	} {
		if got := export(f.B.ID, p.b); !strings.Contains(got, f.B.Refs["connection:ad"]) {
			t.Fatalf("tenant B's own export %s lacks its connection; the check would never fire", p.b)
		}
		if got := export(f.A.ID, p.a); readinessLeaks(got) || strings.Contains(got, f.B.Refs["connection:ad"]) {
			t.Errorf("tenant A's export %s carries tenant B's data", p.a)
		}
	}
}
