package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/archive"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Log retention and the archive over HTTP (issue #298): who may read the
// catalogue, verify and export a segment, that a tenant never reaches another's
// segment, that a tampered one is reported and never exported, and that the
// retention setting changes only through two admins and a step-up.
func TestArchiveAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	sealer := testSealer()
	local, err := archive.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// the archive runs in 2030: everything in the fixture is past its retention
	far := time.Date(2030, 6, 1, 9, 0, 0, 0, time.UTC)
	svc := &archive.Service{DB: f.DB, Sealer: sealer, Store: local, Clock: func() time.Time { return far }, AuditBatch: 25}
	ctx := context.Background()
	if err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		return c.InsertJobRun(&store.JobRun{ID: "old-run", Kind: "sync", Trigger: "manual", Status: "succeeded", Actor: "a",
			StartedAt: storetest.Now.Add(-1000 * 24 * time.Hour)})
	}); err != nil {
		t.Fatal(err)
	}
	if res, err := svc.RunTenant(ctx, f.A.ID); err != nil || res.Total() == 0 {
		t.Fatalf("archive run = %+v, %v", res, err)
	}
	srv := newIsolationServerWith(f, func(c *Config) { c.Sealer, c.Archive = sealer, svc })
	h := srv.Handler()
	phr := authtest.Phr
	admin := signIn(t, f.DB, f.A.ID, authtest.User{Email: "ada@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, phr, storetest.Now)
	admin2 := signIn(t, f.DB, f.A.ID, authtest.User{Email: "ben@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, phr, storetest.Now)
	stale := signIn(t, f.DB, f.A.ID, authtest.User{Email: "old@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}, storetest.Now)
	auditor := signIn(t, f.DB, f.A.ID, authtest.User{Email: "au@a.example", Roles: []auth.Role{auth.RoleAuditor}}, phr, storetest.Now)
	viewer := signIn(t, f.DB, f.A.ID, authtest.User{Email: "v@a.example", Roles: []auth.Role{auth.RoleViewer}}, phr, storetest.Now)
	adminB := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, phr, storetest.Now)

	// retention: five classes with their defaults and floors, and the archive's state
	var ret struct {
		Archive  archiveStatus `json:"archive"`
		Settings []struct {
			Class   string `json:"class"`
			Days    int    `json:"days"`
			Default int    `json:"default_days"`
			Min     int    `json:"min_days"`
			Custom  bool   `json:"custom"`
		} `json:"settings"`
	}
	rec := corrDo(h, auditor, "GET", "/api/admin/retention", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &ret); err != nil || rec.Code != 200 || len(ret.Settings) != 5 || !ret.Archive.Enabled || ret.Archive.Location != "local" {
		t.Fatalf("retention: %d %s", rec.Code, rec.Body)
	}
	if s := ret.Settings[0]; s.Class != "audit" || s.Days != 730 || s.Min != 365 || s.Custom {
		t.Errorf("audit retention = %+v", s)
	}
	if rec := corrDo(h, viewer, "GET", "/api/admin/retention", ""); rec.Code != http.StatusForbidden {
		t.Errorf("a viewer read the retention: %d", rec.Code)
	}

	// the catalogue: the auditor reads it, the viewer does not, another tenant sees none of it
	list := func(l authtest.Login, query string) (int, []segmentView) {
		rec := corrDo(h, l, "GET", "/api/admin/archive/segments"+query, "")
		var out struct {
			Segments []segmentView `json:"segments"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out.Segments
	}
	code, segs := list(auditor, "")
	if code != 200 || len(segs) < 2 {
		t.Fatalf("segments: %d %v", code, segs)
	}
	if code, _ := list(viewer, ""); code != http.StatusForbidden {
		t.Errorf("a viewer listed the archive: %d", code)
	}
	if code, bs := list(adminB, ""); code != 200 || len(bs) != 0 {
		t.Errorf("tenant B sees %d segments (%d)", len(bs), code)
	}
	if code, one := list(auditor, "?class=job_runs&status=purged"); code != 200 || len(one) != 1 || one[0].Count != 1 {
		t.Errorf("job run segments = %d %+v", code, one)
	}
	for _, bad := range []string{"?class=nope", "?status=nope", "?limit=0", "?limit=x"} {
		if code, _ := list(auditor, bad); code != http.StatusUnprocessableEntity {
			t.Errorf("GET segments%s = %d", bad, code)
		}
	}
	var audSeg segmentView
	for _, g := range segs {
		if g.Class == "audit" {
			audSeg = g
		}
	}
	if audSeg.ID == "" || audSeg.Status != "purged" || audSeg.FirstHash == "" || audSeg.SHA256 == "" {
		t.Fatalf("audit segment = %+v", audSeg)
	}
	base := "/api/admin/archive/segments/" + audSeg.ID

	// verify: the auditor may; the viewer and another tenant may not reach it
	rec = corrDo(h, auditor, "POST", base+"/verify", "")
	var chk archive.SegmentCheck
	if err := json.Unmarshal(rec.Body.Bytes(), &chk); err != nil || rec.Code != 200 || !chk.OK || chk.Records != audSeg.Count {
		t.Fatalf("verify: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(h, viewer, "POST", base+"/verify", ""); rec.Code != http.StatusForbidden {
		t.Errorf("a viewer verified a segment: %d", rec.Code)
	}
	for _, path := range []string{base + "/verify", base + "/export"} {
		method := "POST"
		if strings.HasSuffix(path, "export") {
			method = "GET"
		}
		if rec := corrDo(h, adminB, method, path, ""); rec.Code != http.StatusNotFound {
			t.Errorf("tenant B reached tenant A's segment (%s): %d", path, rec.Code)
		}
		if rec := corrDo(h, admin, method, strings.Replace(path, audSeg.ID, "not-an-id", 1), ""); rec.Code != http.StatusNotFound {
			t.Errorf("a malformed segment id (%s): %d", path, rec.Code)
		}
	}

	// export: a fresh step-up, NDJSON of the segment's events, audited
	if rec := corrDo(h, stale, "GET", base+"/export", ""); rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Errorf("a stale sign-in exported: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(h, viewer, "GET", base+"/export", ""); rec.Code != http.StatusForbidden {
		t.Errorf("a viewer exported: %d", rec.Code)
	}
	rec = corrDo(h, admin, "GET", base+"/export", "")
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/x-ndjson") ||
		int64(bytes.Count(rec.Body.Bytes(), []byte("\n"))) != audSeg.Count || !strings.Contains(rec.Header().Get("Content-Disposition"), audSeg.ID) {
		t.Fatalf("export: %d %q %d lines", rec.Code, rec.Header().Get("Content-Type"), bytes.Count(rec.Body.Bytes(), []byte("\n")))
	}
	var acts []string
	if err := f.DB.ReadTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		evs, err := c.AuditEvents(store.AuditFilter{Limit: 200})
		for _, e := range evs {
			acts = append(acts, e.Action)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"archive.segment.checked", "archive.segment.exported", "audit.archived", "archive.purged"} {
		found := false
		for _, a := range acts {
			found = found || a == want
		}
		if !found {
			t.Errorf("the ledger has no %s event", want)
		}
	}

	// the whole chain, archived range included, verifies through the audit route
	rec = corrDo(h, admin, "POST", "/api/audit/verify", `{}`)
	var rep map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &rep)
	if rec.Code != 200 || rep["result"] != "ok" || rep["archived_events"] == nil || rep["archived_events"].(float64) < 1 {
		t.Errorf("audit verify with the archive: %d %s", rec.Code, rec.Body)
	}

	// a tampered segment is reported and never exported
	p := filepath.Join(local.Dir, filepath.FromSlash(objectKeyOf(t, f, audSeg.ID)))
	orig, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), orig...)
	bad[len(bad)/3] ^= 0x40
	if err := os.WriteFile(p, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	rec = corrDo(h, auditor, "POST", base+"/verify", "")
	chk = archive.SegmentCheck{}
	if err := json.Unmarshal(rec.Body.Bytes(), &chk); err != nil || rec.Code != 200 || chk.OK || chk.Problem == "" {
		t.Errorf("verify of a tampered segment: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(h, admin, "GET", base+"/export", ""); rec.Code != http.StatusConflict || bytes.Contains(rec.Body.Bytes(), []byte(`"hash"`)) {
		t.Errorf("a tampered segment was exported: %d", rec.Code)
	}
	rec = corrDo(h, admin, "POST", "/api/audit/verify", `{}`)
	rep = nil
	_ = json.Unmarshal(rec.Body.Bytes(), &rep)
	if rep["result"] != "failed" {
		t.Errorf("audit verify with a tampered archive: %s", rec.Body)
	}
	if err := os.WriteFile(p, orig, 0o600); err != nil {
		t.Fatal(err)
	}

	// retention changes through the change requests: two admins, a step-up, the floors
	post := func(l authtest.Login, path, body string) (int, map[string]any) {
		rec := corrDo(h, l, "POST", path, body)
		var v map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &v)
		return rec.Code, v
	}
	for _, body := range []string{`{"audit_days":364}`, `{"job_runs_days":1}`, `{}`, `{"audit_days":4000}`} {
		if code, _ := post(admin, "/api/admin/change-requests", `{"type":"retention.update","payload":`+body+`}`); code != http.StatusUnprocessableEntity {
			t.Errorf("retention.update %s = %d", body, code)
		}
	}
	if code, _ := post(stale, "/api/admin/change-requests", `{"type":"retention.update","payload":{"audit_days":400}}`); code != http.StatusUnauthorized {
		t.Errorf("a stale sign-in filed a retention change: %d", code)
	}
	if code, _ := post(viewer, "/api/admin/change-requests", `{"type":"retention.update","payload":{"audit_days":400}}`); code != http.StatusForbidden {
		t.Errorf("a viewer filed a retention change: %d", code)
	}
	code, created := post(admin, "/api/admin/change-requests", `{"type":"retention.update","payload":{"audit_days":400,"job_runs_days":45}}`)
	if code != http.StatusCreated || created["status"] != "pending_approval" || created["two_person"] != true {
		t.Fatalf("filed: %d %v", code, created)
	}
	id, hash := asString(created["id"]), asString(created["payload_hash"])
	if code, v := post(admin, "/api/admin/change-requests/"+id+"/approve", fmt.Sprintf(`{"payload_hash":%q}`, hash)); code != http.StatusForbidden {
		t.Errorf("the requester approved their own change: %d %v", code, v)
	}
	rec = corrDo(h, auditor, "GET", "/api/admin/retention", "")
	_ = json.Unmarshal(rec.Body.Bytes(), &ret)
	if ret.Settings[0].Days != 730 {
		t.Errorf("retention changed before the approval: %+v", ret.Settings[0])
	}
	if code, v := post(admin2, "/api/admin/change-requests/"+id+"/approve", fmt.Sprintf(`{"payload_hash":%q}`, hash)); code != http.StatusOK || v["status"] != "applied" {
		t.Fatalf("approve: %d %v", code, v)
	}
	rec = corrDo(h, auditor, "GET", "/api/admin/retention", "")
	_ = json.Unmarshal(rec.Body.Bytes(), &ret)
	if s := ret.Settings[0]; s.Days != 400 || !s.Custom {
		t.Errorf("audit retention after the change = %+v", s)
	}
	if s := ret.Settings[3]; s.Class != "job_runs" || s.Days != 45 {
		t.Errorf("job run retention after the change = %+v", s)
	}
	// tenant B's retention is untouched
	rec = corrDo(h, adminB, "GET", "/api/admin/retention", "")
	_ = json.Unmarshal(rec.Body.Bytes(), &ret)
	if ret.Settings[0].Days != 730 || ret.Settings[0].Custom {
		t.Errorf("tenant B's retention changed: %+v", ret.Settings[0])
	}

	// no archive configured: the page says so and the actions are 503
	off := newIsolationServerWith(f, func(c *Config) { c.Sealer = sealer }).Handler()
	rec = corrDo(off, auditor, "GET", "/api/admin/archive/segments", "")
	var st struct {
		Archive archiveStatus `json:"archive"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil || rec.Code != 200 || st.Archive.Enabled {
		t.Errorf("segments with archiving off: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(off, auditor, "POST", base+"/verify", ""); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("verify with archiving off: %d", rec.Code)
	}
}

func objectKeyOf(t *testing.T, f *storetest.Fixture, segmentID string) string {
	t.Helper()
	var key string
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		g, err := c.ArchiveSegment(segmentID)
		if err == nil {
			key = g.ObjectKey
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return key
}
