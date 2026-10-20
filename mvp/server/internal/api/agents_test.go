package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// TestAgentsAPI: the admin routes of the Directory Agent. Issuing a code shows
// it once (never listed again, never in the audit event), a duplicate or
// invalid name is refused, revoking is audited, and tenant B's agent is
// indistinguishable from a missing one for tenant A.
func TestAgentsAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	ha := isolationServer(t, f, f.A.ID).Handler()
	hb := isolationServer(t, f, f.B.ID).Handler()

	rec := serveOnce(ha, http.MethodPost, "/api/agents", `{"name":"dc-agent"}`)
	if rec.Code != http.StatusCreated || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("create: %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	var created struct {
		Code      string `json:"code"`
		ExpiresAt string `json:"expires_at"`
		Agent     struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"agent"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || !strings.HasPrefix(created.Code, "tdae_") ||
		created.Agent.Status != "pending" || created.Agent.Name != "dc-agent" || created.ExpiresAt == "" {
		t.Fatalf("create body: %v %s", err, rec.Body)
	}

	// the list never shows the code or a key pin
	list := serveOnce(ha, http.MethodGet, "/api/agents", "")
	if list.Code != 200 || !strings.Contains(list.Body.String(), created.Agent.ID) || strings.Contains(list.Body.String(), created.Code) ||
		strings.Contains(list.Body.String(), "cert_pin") || strings.Contains(list.Body.String(), "token_hash") {
		t.Errorf("list: %d %s", list.Code, list.Body)
	}
	// tenant B sees none of it
	if lb := serveOnce(hb, http.MethodGet, "/api/agents", ""); lb.Code != 200 || strings.Contains(lb.Body.String(), created.Agent.ID) ||
		strings.TrimSpace(lb.Body.String()) != "[]" {
		t.Errorf("tenant B's list: %d %s", lb.Code, lb.Body)
	}

	// validation
	if rec := serveOnce(ha, http.MethodPost, "/api/agents", `{"name":"dc-agent"}`); rec.Code != http.StatusConflict ||
		!strings.Contains(rec.Body.String(), "name_taken") {
		t.Errorf("duplicate name: %d %s", rec.Code, rec.Body)
	}
	for _, body := range []string{`{"name":""}`, `{"name":"a/b"}`, `{"name":"` + strings.Repeat("a", 65) + `"}`, `{}`,
		`{"name":"x","extra":1}`, ``, `[]`} {
		if rec := serveOnce(ha, http.MethodPost, "/api/agents", body); rec.Code < 400 || rec.Code >= 500 {
			t.Errorf("body %q: %d %s", body, rec.Code, rec.Body)
		}
	}
	// same name in the other tenant is fine
	if rec := serveOnce(hb, http.MethodPost, "/api/agents", `{"name":"dc-agent"}`); rec.Code != http.StatusCreated {
		t.Errorf("tenant B's same name: %d %s", rec.Code, rec.Body)
	}

	// tenant B's agent id, revoked as tenant A, answers as a missing id does
	var other struct {
		Agent struct {
			ID string `json:"id"`
		} `json:"agent"`
	}
	list2 := serveOnce(hb, http.MethodGet, "/api/agents", "")
	var bAgents []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(list2.Body.Bytes(), &bAgents); err != nil || len(bAgents) != 1 {
		t.Fatalf("tenant B's agents: %v %s", err, list2.Body)
	}
	other.Agent.ID = bAgents[0].ID
	cross := serveOnce(ha, http.MethodPost, "/api/agents/"+other.Agent.ID+"/revoke", "")
	missing := serveOnce(ha, http.MethodPost, "/api/agents/"+missingUUID+"/revoke", "")
	norm := func(s, id string) string { return strings.ReplaceAll(s, id, "<id>") }
	if cross.Code != http.StatusNotFound || cross.Code != missing.Code ||
		norm(cross.Body.String(), other.Agent.ID) != norm(missing.Body.String(), missingUUID) {
		t.Errorf("tenant B's agent as A: %d %s; missing: %d %s", cross.Code, cross.Body, missing.Code, missing.Body)
	}
	if rec := serveOnce(ha, http.MethodPost, "/api/agents/not-a-uuid/revoke", ""); rec.Code != http.StatusNotFound {
		t.Errorf("malformed id: %d", rec.Code)
	}
	// B's agent is untouched
	if lb := serveOnce(hb, http.MethodGet, "/api/agents", ""); !strings.Contains(lb.Body.String(), `"status":"pending"`) {
		t.Errorf("tenant B's agent changed: %s", lb.Body)
	}

	// revoke our own
	rev := serveOnce(ha, http.MethodPost, "/api/agents/"+created.Agent.ID+"/revoke", "")
	if rev.Code != 200 || !strings.Contains(rev.Body.String(), `"status":"revoked"`) {
		t.Fatalf("revoke: %d %s", rev.Code, rev.Body)
	}
	if rec := serveOnce(ha, http.MethodPost, "/api/agents/"+created.Agent.ID+"/revoke", ""); rec.Code != http.StatusNotFound {
		t.Errorf("second revoke: %d %s", rec.Code, rec.Body)
	}

	// audit: domain events in the same transaction, without the code
	got := auditActions(t, f, f.A.ID)
	if got["agent.enrolment_issued"] != 1 || got["agent.revoked"] != 1 {
		t.Errorf("audit actions: %v", got)
	}
	if err := f.DB.ReadTenant(t.Context(), f.A.ID, func(c *store.TenantTx) error {
		evs, err := c.AuditEvents(store.AuditFilter{IncludeHTTP: true})
		for _, e := range evs {
			if strings.Contains(string(e.Detail), created.Code) {
				t.Errorf("%s carries the enrolment code", e.Action)
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
