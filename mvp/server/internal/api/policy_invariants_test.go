package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/seed"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

func getBody(t *testing.T, h http.Handler, path string) []byte {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d: %.300s", path, rec.Code, rec.Body.String())
	}
	return rec.Body.Bytes()
}

// withoutSource drops the "source" of each listed policy (the YAML text is
// the Cedar text once a tenant has its own bundle).
func withoutSource(t *testing.T, body []byte) []map[string]any {
	t.Helper()
	var ps []map[string]any
	if err := json.Unmarshal(body, &ps); err != nil {
		t.Fatal(err)
	}
	for _, p := range ps {
		delete(p, "source")
	}
	return ps
}

// A tenant whose bundle holds the Cedar port of every shipped YAML policy gets
// the same /api/violations bytes and the same /api/policies listing (but for
// each policy's source text) as the tenant on the embedded YAML (AC-3).
func TestCedarInvariantsKeepAPIOutputs(t *testing.T) {
	srv := newSeededServer(t)
	h := srv.Handler()
	wantViol := getBody(t, h, "/api/violations")
	wantPols := getBody(t, h, "/api/policies")
	if len(wantViol) < 100 {
		t.Fatalf("the seed has no violations: %s", wantViol)
	}

	files, err := srv.Server.policies()
	if err != nil {
		t.Fatal(err)
	}
	ported := 0
	err = srv.store.InTenant(context.Background(), seed.LarkspurID, func(c *store.TenantTx) error {
		for _, p := range files {
			text, err := policy.ToCedar(p)
			if err != nil {
				continue // separation_of_duties: a SoD risk
			}
			if _, err := policy.ImportInvariant(c, p.ID, []byte(text), "", "test", testkit.Now); err != nil {
				return err
			}
			ported++
		}
		return nil
	})
	if err != nil || ported < 6 {
		t.Fatalf("imported %d invariants: %v", ported, err)
	}

	if got := getBody(t, h, "/api/violations"); string(got) != string(wantViol) {
		t.Errorf("/api/violations changed with the Cedar bundle:\nwant %.600s\ngot  %.600s", wantViol, got)
	}
	got := getBody(t, h, "/api/policies")
	w, g := withoutSource(t, wantPols), withoutSource(t, got)
	wb, _ := json.Marshal(w)
	gb, _ := json.Marshal(g)
	if string(wb) != string(gb) {
		t.Errorf("/api/policies changed with the Cedar bundle:\nwant %.600s\ngot  %.600s", wb, gb)
	}
	var listed []struct {
		ID     string `json:"id"`
		Source string `json:"source"`
	}
	if err := json.Unmarshal(got, &listed); err != nil {
		t.Fatal(err)
	}
	cedar := 0
	for _, p := range listed {
		if len(p.Source) > 0 && p.Source[0] == '@' {
			cedar++
		}
	}
	if cedar != ported {
		t.Errorf("%d policies are listed with Cedar source, want %d", cedar, ported)
	}

	// a tenant-only invariant is listed and evaluated; a broken source puts the tenant back on the YAML
	err = srv.store.InTenant(context.Background(), seed.LarkspurID, func(c *store.TenantTx) error {
		_, err := policy.ImportInvariant(c, "mine", []byte(`@id("mine") @name("Mine") @severity("low") forbid (principal, action == Tessera::Action::"reach", resource) when { principal.status == "terminated" };`),
			"", "test", testkit.Now)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	var mine int
	var vs []struct {
		PolicyID string `json:"policy_id"`
	}
	if err := json.Unmarshal(getBody(t, h, "/api/violations"), &vs); err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		if v.PolicyID == "mine" {
			mine++
		}
	}
	if mine == 0 {
		t.Error("the tenant's own invariant found nothing")
	}
	err = srv.store.InTenant(context.Background(), seed.LarkspurID, func(c *store.TenantTx) error {
		_, err := c.PutPolicySource(&store.PolicySource{Kind: store.PolicyKindInvariant, Key: "broken", Cedar: "forbid (", Status: store.PolicyActive, UpdatedBy: "test"}, testkit.Now)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := getBody(t, h, "/api/violations"); string(got) != string(wantViol) {
		t.Errorf("a bundle that does not load did not fall back to the embedded YAML:\n%.400s", got)
	}
}
