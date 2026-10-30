package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// The evidence of a revocation and the metrics of the loop through the API (issue #666, LP-10): the record holds the
// usage window, confidence, simulation diff and verified re-read; a restore adds its trigger and the false-positive
// label, and the metrics count it.
func TestLPEvidenceAPI(t *testing.T) {
	w := lpOn(t)
	id, at := w.lpRevoked()

	e := w.c.json("GET", "/api/lp/revocations/"+id+"/evidence", "", http.StatusOK).(map[string]any)
	if e["schema"] != "tessera.lp-evidence/1" || e["revocation_id"] != id || e["state"] != "revoked" || len(asString(e["sha256"])) != 64 {
		t.Fatalf("evidence = %v", e)
	}
	uw := e["usage_window"].(map[string]any)
	if uw["unused_days"].(float64) < 1 || asString(uw["snapshot_id"]) == "" {
		t.Errorf("usage window = %v", uw)
	}
	if lvl := e["confidence"].(map[string]any)["level"]; lvl != "high" && lvl != "medium" {
		t.Errorf("confidence = %v", e["confidence"])
	}
	if e["verification"].(map[string]any)["ok"] != true || e["simulation"].(map[string]any)["lost"] == nil {
		t.Errorf("verification %v, simulation %v", e["verification"], e["simulation"])
	}
	if rr := e["reread"].(map[string]any); rr["verified"] != true || len(asString(rr["expected_sha256"])) != 64 {
		t.Errorf("reread = %v", rr)
	}
	if e["restore"] != nil || e["false_positive"] != nil {
		t.Errorf("a revoked grant has no restore: %v", e)
	}

	// the test clock is frozen before the revocation ran (sessions are not valid later): ask for a period that holds it
	list := w.c.json("GET", "/api/lp/evidence?from=2026-10-01&to=2026-12-31", "", http.StatusOK).(map[string]any)
	items := list["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["sha256"] != e["sha256"] {
		t.Fatalf("export = %v", list)
	}
	w.executedAt(id, testkit.Now.Add(-time.Hour))
	m := w.c.json("GET", "/api/lp/metrics", "", http.StatusOK).(map[string]any)["metrics"].(map[string]any)
	if m["executed"].(float64) != 1 || m["staged"].(float64) != 1 || m["false_positive_percent"].(float64) != 0 || m["median_restore_seconds"] != nil {
		t.Errorf("metrics = %v", m)
	}

	// put it back: the restore and the label are in the record, and the rate follows
	w.c.json("POST", "/api/lp/revocations/"+id+"/restore", `{}`, http.StatusAccepted)
	w.runAt(at)
	w.lpTick(at.Add(2 * time.Minute))
	if st := w.lpState(id); st != "restored" {
		t.Fatalf("state = %s", st)
	}
	e = w.c.json("GET", "/api/lp/revocations/"+id+"/evidence", "", http.StatusOK).(map[string]any)
	rs, fp := e["restore"].(map[string]any), e["false_positive"].(map[string]any)
	if rs["trigger"] != "admin" || rs["latency_seconds"] == nil || fp["source"] != "admin" {
		t.Errorf("restore %v, false positive %v", rs, fp)
	}
	m = w.c.json("GET", "/api/lp/metrics?days=365", "", http.StatusOK).(map[string]any)["metrics"].(map[string]any)
	if m["false_positive_percent"].(float64) != 100 || m["restores"].(float64) != 1 || m["median_restore_seconds"] == nil {
		t.Errorf("metrics after the restore = %v", m)
	}
}

func TestLPEvidenceAPI_Input(t *testing.T) {
	w := lpOn(t)
	for _, tc := range []struct {
		path string
		want int
	}{
		{"/api/lp/evidence?from=nope", http.StatusUnprocessableEntity},
		{"/api/lp/evidence?to=nope", http.StatusUnprocessableEntity},
		{"/api/lp/evidence?from=2026-10-10&to=2026-10-01", http.StatusUnprocessableEntity},
		{"/api/lp/evidence?from=2020-01-01&to=2026-10-01", http.StatusUnprocessableEntity},
		{"/api/lp/evidence?limit=0", http.StatusUnprocessableEntity},
		{"/api/lp/evidence?limit=5001", http.StatusUnprocessableEntity},
		{"/api/lp/evidence?from=2026-01-01&to=2026-10-01&limit=10", http.StatusOK},
		{"/api/lp/metrics?days=0", http.StatusUnprocessableEntity},
		{"/api/lp/metrics?days=366", http.StatusUnprocessableEntity},
		{"/api/lp/metrics?days=x", http.StatusUnprocessableEntity},
		{"/api/lp/metrics?days=30", http.StatusOK},
		{"/api/lp/revocations/does-not-exist/evidence", http.StatusNotFound},
		{"/api/lp/revocations/..%2Fx/evidence", http.StatusNotFound},
	} {
		if r := w.c.do("GET", tc.path, ""); r.Code != tc.want {
			t.Errorf("GET %s: %d %s, want %d", tc.path, r.Code, strings.TrimSpace(r.Body.String()), tc.want)
		}
	}
	// nothing was revoked: an empty export and zero rates, not an error
	m := w.c.json("GET", "/api/lp/metrics", "", http.StatusOK).(map[string]any)["metrics"].(map[string]any)
	if m["executed"].(float64) != 0 || m["false_positive_percent"].(float64) != 0 {
		t.Errorf("metrics = %v", m)
	}
}

// executedAt moves the time the revocation was carried out, so that it falls before the frozen clock of the tests.
func (w *awsWB) executedAt(id string, at time.Time) {
	w.t.Helper()
	testkit.Write(w.t, w.st, func(tx *store.TenantTx) error {
		r, err := tx.LPRevocation(id)
		if err != nil {
			return err
		}
		r.ExecutedAt = &at
		return tx.UpdateLPRevocation(r, r.State, testkit.Now)
	})
}
