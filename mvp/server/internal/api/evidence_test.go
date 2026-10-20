package api

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// seedEvidencePack stores a pack directly in tenant and returns its id.
func seedEvidencePack(tb testing.TB, f *storetest.Fixture, tenant tenancy.ID) string {
	tb.Helper()
	id := uuid.NewString()
	if err := f.DB.InTenant(context.Background(), tenant, func(c *store.TenantTx) error {
		return c.InsertEvidencePack(&store.EvidencePack{ID: id, Framework: "soc2", PeriodFrom: storetest.Now.Add(-24 * time.Hour),
			PeriodTo: storetest.Now, GeneratedAt: storetest.Now, GeneratedBy: "x", ManifestSHA256: "abc",
			Manifest: []byte(`{"name":"SOC 2","files":[]}`), SizeBytes: 3, Content: []byte("zip")})
	}); err != nil {
		tb.Fatal(err)
	}
	return id
}

func getJSON(t *testing.T, h http.Handler, path string, want int) map[string]any {
	t.Helper()
	rec := serveOnce(h, http.MethodGet, path, "")
	if rec.Code != want {
		t.Fatalf("GET %s = %d, want %d: %.300s", path, rec.Code, want, rec.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out
}

// TestAccessAsOfAPI: GET /api/access/as-of validates its input and answers
// from edge_history, including at the exact instant a grant began.
func TestAccessAsOfAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := isolationServer(t, f, f.B.ID).Handler()
	res := f.B.IDs["resource:aws:customer-pii"]
	url := func(q string, a ...any) string { return fmt.Sprintf("/api/access/as-of?"+q, a...) }

	for name, q := range map[string]string{
		"no parameters":     "",
		"no date":           fmt.Sprintf("resource=%d", res),
		"no resource":       "date=2026-10-08",
		"resource not int":  "resource=x&date=2026-10-08",
		"bad date":          fmt.Sprintf("resource=%d&date=yesterday", res),
		"future date":       fmt.Sprintf("resource=%d&date=2027-01-01", res),
		"future instant":    fmt.Sprintf("resource=%d&date=2026-10-08T09:30:01", res),
		"impossible date":   fmt.Sprintf("resource=%d&date=2026-13-45", res),
		"date with garbage": fmt.Sprintf("resource=%d&date=2026-10-08'%%20OR%%201=1", res),
	} {
		t.Run("invalid "+name, func(t *testing.T) {
			if rec := serveOnce(h, http.MethodGet, "/api/access/as-of?"+q, ""); rec.Code != http.StatusUnprocessableEntity {
				t.Errorf("status %d: %.200s", rec.Code, rec.Body.String())
			}
		})
	}

	missing := serveOnce(h, http.MethodGet, url("resource=%d&date=2026-10-08", missingID), "")
	cross := serveOnce(h, http.MethodGet, url("resource=%d&date=2026-10-08", f.A.IDs["resource:aws:customer-pii"]), "")
	if missing.Code != http.StatusNotFound || cross.Code != missing.Code || cross.Body.String() == "" ||
		strings.ReplaceAll(cross.Body.String(), fmt.Sprint(f.A.IDs["resource:aws:customer-pii"]), "<id>") !=
			strings.ReplaceAll(missing.Body.String(), fmt.Sprint(missingID), "<id>") {
		t.Errorf("tenant A's resource is distinguishable from a missing one: %d %s / %d %s", cross.Code, cross.Body, missing.Code, missing.Body)
	}

	// the fixture's grants were ingested at storetest.Now: held at that instant, not a microsecond before
	at := func(date string) map[string]any {
		return getJSON(t, h, url("resource=%d&date=%s", res, date), http.StatusOK)
	}
	if got := at("2026-10-08T09:29:59.999999"); got["count"] != float64(0) {
		t.Errorf("a microsecond before the grants existed: count = %v", got["count"])
	}
	got := at("2026-10-08T09:30:00")
	if got["count"].(float64) == 0 || got["as_of"] != "2026-10-08T09:30:00" {
		t.Fatalf("at the instant the grants began: %v", got)
	}
	if leaks(fmt.Sprint(got)) {
		t.Error("as-of leaks tenant A data")
	}
	first := got["identities"].([]any)[0].(map[string]any)
	perm := first["permissions"].([]any)[0].(map[string]any)
	path := perm["paths"].([]any)[0].(map[string]any)
	if path["text"] == "" || len(path["steps"].([]any)) < 3 {
		t.Errorf("an as-of answer carries no path: %v", perm)
	}
	// a date means the end of that day, which today is now
	if today := at("2026-10-08"); today["count"] != got["count"] || today["as_of"] != "2026-10-08T09:30:00" {
		t.Errorf("date-only today = %v", today)
	}
	if yesterday := at("2026-10-07"); yesterday["count"] != float64(0) || yesterday["as_of"] != "2026-10-07T23:59:59.999999" {
		t.Errorf("date-only yesterday = %v", yesterday)
	}
}

// TestEvidenceAPI: generate, list, fetch and download a pack; the ZIP
// matches the manifest hash the API and the audit ledger state; bad input is
// refused; and nothing is stored when it is.
func TestEvidenceAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := isolationServer(t, f, f.B.ID).Handler()

	post := func(body string) *httptest.ResponseRecorder {
		return serveOnce(h, http.MethodPost, "/api/evidence/packs", body)
	}
	for name, body := range map[string]string{
		"no body":           ``,
		"unknown framework": `{"framework":"hipaa","from":"2026-01-01","to":"2026-06-30"}`,
		"no dates":          `{"framework":"soc2"}`,
		"bad from":          `{"framework":"soc2","from":"January","to":"2026-06-30"}`,
		"bad to":            `{"framework":"soc2","from":"2026-01-01","to":"2026-02-30"}`,
		"reversed":          `{"framework":"soc2","from":"2026-06-30","to":"2026-01-01"}`,
		"starts in future":  `{"framework":"soc2","from":"2026-11-01","to":"2026-12-01"}`,
		"too long":          `{"framework":"soc2","from":"2020-01-01","to":"2026-06-30"}`,
		"extra field":       `{"framework":"soc2","from":"2026-01-01","to":"2026-06-30","tenant":"x"}`,
	} {
		t.Run("invalid "+name, func(t *testing.T) {
			if rec := post(body); rec.Code != http.StatusUnprocessableEntity && rec.Code != http.StatusBadRequest {
				t.Errorf("status %d: %.200s", rec.Code, rec.Body.String())
			}
		})
	}
	if list := getJSON(t, h, "/api/evidence/packs", http.StatusOK); len(list["packs"].([]any)) != 0 {
		t.Fatalf("a refused request stored a pack: %v", list["packs"])
	}

	rec := post(`{"framework":"pci_dss_v4","from":"2026-07-01","to":"2026-10-08"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST = %d: %.300s", rec.Code, rec.Body.String())
	}
	var created map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	id, sum := created["id"].(string), created["manifest_sha256"].(string)
	if created["framework"] != "pci_dss_v4" || created["period_from"] != "2026-07-01T00:00:00" ||
		created["period_to"] != "2026-10-08T09:30:00" || len(sum) != 64 || created["manifest"] == nil {
		t.Errorf("created = %v", created)
	}
	if leaks(rec.Body.String()) {
		t.Error("the pack response leaks tenant A data")
	}

	list := getJSON(t, h, "/api/evidence/packs", http.StatusOK)
	if packs := list["packs"].([]any); len(packs) != 1 || packs[0].(map[string]any)["id"] != id || len(list["frameworks"].([]any)) != 4 {
		t.Errorf("list = %v", list)
	}
	if detail := getJSON(t, h, "/api/evidence/packs/"+id, http.StatusOK); detail["manifest_sha256"] != sum {
		t.Errorf("detail = %v", detail)
	}

	dl := serveOnce(h, http.MethodGet, "/api/evidence/packs/"+id+"/download", "")
	if dl.Code != http.StatusOK || dl.Header().Get("Content-Type") != "application/zip" ||
		!strings.HasPrefix(dl.Header().Get("Content-Disposition"), "attachment; filename=\"tessera-evidence-pci_dss_v4-20260701-20261008") ||
		dl.Header().Get("X-Tessera-Manifest-SHA256") != sum {
		t.Fatalf("download: %d %v", dl.Code, dl.Header())
	}
	zr, err := zip.NewReader(bytes.NewReader(dl.Body.Bytes()), int64(dl.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	for _, zf := range zr.File {
		if zf.Name != "manifest.json" {
			continue
		}
		rc, _ := zf.Open()
		b, _ := io.ReadAll(rc)
		_ = rc.Close()
		if s := sha256.Sum256(b); hex.EncodeToString(s[:]) != sum {
			t.Errorf("manifest.json hashes to %x, the API says %s", s, sum)
		}
		if leaks(string(b)) {
			t.Error("the manifest leaks tenant A data")
		}
	}

	// the ledger event is in the same transaction: the pack and its event
	// exist together, and the event carries the manifest hash
	var found *store.AuditEvent
	if err := f.DB.ReadTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		evs, err := c.AuditEvents(store.AuditFilter{Action: "evidence.pack_generated"})
		if err != nil {
			return err
		}
		if len(evs) != 1 {
			t.Fatalf("%d evidence.pack_generated events, want 1", len(evs))
		}
		found = evs[0]
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if found.TargetID == nil || *found.TargetID != id || !strings.Contains(string(found.Detail), sum) ||
		found.ActorType == "" || found.RequestID == nil {
		t.Errorf("ledger event = %+v detail %s", found, found.Detail)
	}
}

// TestEvidenceAPI_CrossTenant: tenant A's pack, named by id from tenant B, is
// indistinguishable from a missing one, on every route that takes an id.
func TestEvidenceAPI_CrossTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	aPack := seedEvidencePack(t, f, f.A.ID)
	h := isolationServer(t, f, f.B.ID).Handler()
	for _, suffix := range []string{"", "/download"} {
		cross := serveOnce(h, http.MethodGet, "/api/evidence/packs/"+aPack+suffix, "")
		missing := serveOnce(h, http.MethodGet, "/api/evidence/packs/"+uuid.NewString()+suffix, "")
		notUUID := serveOnce(h, http.MethodGet, "/api/evidence/packs/1"+suffix, "")
		if cross.Code != http.StatusNotFound || cross.Body.String() != missing.Body.String() || notUUID.Code != http.StatusNotFound {
			t.Errorf("GET pack%s: A's = %d %s, missing = %d %s, not a uuid = %d", suffix, cross.Code, cross.Body, missing.Code,
				missing.Body, notUUID.Code)
		}
	}
	if list := getJSON(t, h, "/api/evidence/packs", http.StatusOK); len(list["packs"].([]any)) != 0 {
		t.Errorf("tenant B lists tenant A's packs: %v", list["packs"])
	}
}
