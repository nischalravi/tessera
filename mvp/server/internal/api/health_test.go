package api

import (
	"net/http"
	"strings"
	"testing"
)

func TestSummary_ReadinessBlock(t *testing.T) {
	c := newRD(t)
	// Without the opt-in the summary is exactly the recorded response (parity).
	plain := c.json("GET", "/api/summary", "", http.StatusOK)
	if _, ok := plain["readiness"]; ok {
		t.Fatal("readiness block without include=readiness")
	}
	r := c.json("GET", "/api/summary?include=readiness", "", http.StatusOK)["readiness"].(map[string]any)
	if r["score"] != nil || r["connections"] != float64(0) {
		t.Errorf("empty tenant: %v", r)
	}
	okta := c.validatedConn("demo-okta", "Okta (demo)", "")
	c.json("POST", "/api/connections/"+okta+"/dry-run", "", http.StatusAccepted)
	r = c.json("GET", "/api/summary?include=readiness", "", http.StatusOK)["readiness"].(map[string]any)
	if r["score"] == nil || r["band"] == "" || r["needs_attention"].(float64) < 1 || r["draft"] != float64(1) {
		t.Fatalf("readiness block: %v", r)
	}
	top := r["top"].([]any)
	if len(top) == 0 || len(top) > 3 {
		t.Fatalf("top entries: %v", top)
	}
	found := false
	for _, e := range top {
		if strings.Contains(e.(map[string]any)["sentence"].(string), "Oren Whitlock left 20 days ago") {
			found = true
		}
	}
	if !found {
		t.Errorf("Home card does not show the missed Okta leaver: %v", top)
	}
}

func TestDeploymentHealth_API(t *testing.T) {
	c := newRD(t)
	d := c.json("GET", "/api/insights/deployment-health", "", http.StatusOK)
	if d["tenant"].(map[string]any)["score"] != nil || len(d["connections"].([]any)) != 0 {
		t.Fatalf("empty dashboard: %v", d)
	}
	okta := c.validatedConn("demo-okta", "Okta (demo)", "")
	c.json("POST", "/api/connections/"+okta+"/dry-run", "", http.StatusAccepted)
	c.json("POST", "/api/connections/"+okta+"/checklist/okta.auth.oauth/skip", `{"reason":"Migration to an OAuth service app is planned for Q1","review_by":"2026-10-20"}`, http.StatusOK)
	d = c.json("GET", "/api/insights/deployment-health", "", http.StatusOK)
	tenant := d["tenant"].(map[string]any)
	if tenant["score"] == nil || !strings.Contains(tenant["hr_source"].(string), "Workday") {
		t.Errorf("tenant: %v", tenant)
	}
	conns := d["connections"].([]any)
	row := conns[0].(map[string]any)
	if len(conns) != 1 || row["counted"] != true || row["state"] != "validated" || row["score"] != tenant["score"] {
		t.Errorf("connections: %v", conns)
	}
	// Needs attention: the leaver sentence, ranked, with a Fix link to the finding.
	var oren map[string]any
	var skip map[string]any
	for _, e := range d["needs_attention"].([]any) {
		m := e.(map[string]any)
		if strings.HasPrefix(m["sentence"].(string), "Oren Whitlock left 20 days ago and is still active in Okta") {
			oren = m
		}
		if m["kind"] == "skip" {
			skip = m
		}
	}
	if oren == nil || oren["severity"] != "high" || oren["fix"].(map[string]any)["kind"] != "finding" || oren["blocks_activation"] != true {
		t.Errorf("Oren entry: %v", oren)
	}
	if skip == nil || !strings.Contains(skip["sentence"].(string), "skipped by j.rivera@larkspur.example") ||
		!strings.Contains(skip["sentence"].(string), "review due in 12 days") {
		t.Errorf("skip entry: %v", skip)
	}
	skipped := d["skipped"].([]any)
	if len(skipped) != 1 || skipped[0].(map[string]any)["item_id"] != "okta.auth.oauth" {
		t.Errorf("skipped: %v", skipped)
	}
	kpis := d["kpis"].(map[string]any)
	if kpis["accounts_correlated_pct"] != float64(100) || kpis["open_critical_high"].(float64) < 1 || kpis["connections_in_setup"] != float64(1) {
		t.Errorf("kpis: %v", kpis)
	}
	// One connection's health: the breakdown explains the score.
	h := c.json("GET", "/api/connections/"+okta+"/health", "", http.StatusOK)
	b := h["breakdown"].(map[string]any)
	if b["score"] != row["score"] || b["checklist"] == nil || b["penalty"] == nil {
		t.Errorf("health: %v", b)
	}
	// The list endpoint carries the score too.
	v := c.json("GET", "/api/connections/"+okta, "", http.StatusOK)
	if v["score"].(map[string]any)["score"] != row["score"] {
		t.Errorf("connection score: %v", v["score"])
	}
	// Re-run: validation for every connection, and the tenant score is recorded.
	rr := c.json("POST", "/api/insights/deployment-health/rerun", `{"reconcile":true}`, http.StatusOK)
	res := rr["results"].([]any)[0].(map[string]any)
	if res["validation_run_id"] == nil || res["dry_run_id"] == nil {
		t.Errorf("rerun: %v", res)
	}
	if n := c.count("SELECT count(*) FROM readiness_scores WHERE scope = 'tenant'"); n != 1 {
		t.Errorf("tenant score series: %d rows", n)
	}
	if n := c.count("SELECT count(*) FROM readiness_scores WHERE scope = 'connection'"); n == 0 {
		t.Error("connection score series is empty")
	}
}

// Every deployment-readiness route is documented in /api/readiness/openapi.json.
func TestReadinessOpenAPI_CoversRoutes(t *testing.T) {
	c := newRD(t)
	doc := c.json("GET", "/api/readiness/openapi.json", "", http.StatusOK)
	paths := doc["paths"].(map[string]any)
	srv := New(Config{Store: c.st, Policies: nil})
	n := 0
	for _, rt := range srv.routes {
		path := "/" + strings.Join(rt.segs, "/")
		if !strings.HasPrefix(path, "/api/connections") && !strings.HasPrefix(path, "/api/readiness") && !strings.HasPrefix(path, "/api/insights") {
			continue
		}
		if path == "/api/readiness/openapi.json" {
			continue
		}
		n++
		ops, ok := paths[path].(map[string]any)
		if !ok || ops[strings.ToLower(rt.method)] == nil {
			t.Errorf("%s %s is not documented", rt.method, path)
		}
	}
	if n != 24 {
		t.Errorf("%d readiness routes registered, want 24", n)
	}
}
