package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

func agentByName(t *testing.T, v any, name string) map[string]any {
	t.Helper()
	for _, a := range v.([]any) {
		if m := a.(map[string]any); m["name"] == name {
			return m
		}
	}
	t.Fatalf("no agent %q in %v", name, v)
	return nil
}

func containsAny(v any, s string) bool {
	for _, x := range v.([]any) {
		if x == s {
			return true
		}
	}
	return false
}

// The agent inventory is the demo company's ai_agent identities, now with where
// each came from and who sponsors it.
func TestAgentInventory(t *testing.T) {
	c := client{t, testServer(t, testkit.Demo(t))}
	agents := c.json("GET", "/api/ai-agents", "", 200)
	nhi := c.json("GET", "/api/nhi?type=ai_agent", "", 200)
	if len(agents.([]any)) == 0 || len(agents.([]any)) != len(nhi.([]any)) {
		t.Fatalf("agents = %d, nhi ai_agents = %d", len(agents.([]any)), len(nhi.([]any)))
	}
	status := map[any]int{}
	for _, a := range agents.([]any) {
		m := a.(map[string]any)
		if m["source"] != "okta" || m["source_kind"] != "okta_service_app" || m["creator"] == nil || m["sponsor"] == nil {
			t.Errorf("demo agent = %v", m)
		}
		status[m["sponsor_status"]]++
		// a sponsor who is not active (the demo has one agent whose sponsor left) is a violation
		if m["sponsor_status"] == "inactive" != containsAny(m["violations"], "nhi-ownership") {
			t.Errorf("sponsor_status %v with violations %v", m["sponsor_status"], m["violations"])
		}
	}
	if status["active"] == 0 || status["inactive"] == 0 {
		t.Errorf("sponsor statuses = %v, want both active and inactive in the demo", status)
	}
	// the demo's Support Copilot reaches PII through a Snowflake role: an existing policy flags it
	support := agentByName(t, agents, "Support Copilot")
	if !containsAny(support["violations"], "ai-agents-no-pii") {
		t.Errorf("support copilot violations = %v", support["violations"])
	}
}

// An agent without an active sponsor raises nhi-ownership, and the inventory
// says why.
func TestAgentSponsorStatus(t *testing.T) {
	st := testkit.Demo(t)
	testkit.Write(t, st, func(tx *store.TenantTx) error {
		idents, err := tx.Identities()
		if err != nil {
			return err
		}
		byName := map[string]*store.Identity{}
		for _, i := range idents {
			byName[i.Name] = i
		}
		if err := tx.SetIdentityOwner(byName["Support Copilot"].ID, nil); err != nil {
			return err
		}
		return tx.TerminateIdentity(*byName["Code Review Bot"].OwnerID, testkit.Now)
	})
	c := client{t, testServer(t, st)}
	agents := c.json("GET", "/api/ai-agents", "", 200)
	if a := agentByName(t, agents, "Support Copilot"); a["sponsor_status"] != "none" || a["sponsor"] != nil ||
		!containsAny(a["violations"], "nhi-ownership") {
		t.Errorf("agent with no sponsor = %v", a)
	}
	if a := agentByName(t, agents, "Code Review Bot"); a["sponsor_status"] != "inactive" || !containsAny(a["violations"], "nhi-ownership") {
		t.Errorf("agent whose sponsor left = %v", a)
	}
	if a := agentByName(t, agents, "Finance Recon Agent"); a["sponsor_status"] != "active" || containsAny(a["violations"], "nhi-ownership") {
		t.Errorf("agent with an active sponsor = %v", a)
	}
}

func TestMCPFindingsAPI(t *testing.T) {
	c := client{t, testServer(t, testkit.Demo(t))}
	all := c.json("GET", "/api/ai-agents/mcp-findings", "", 200).([]any)
	if len(all) != 5 {
		t.Fatalf("findings = %d", len(all))
	}
	creds := c.json("GET", "/api/ai-agents/mcp-findings?kind=agent_credential", "", 200).([]any)
	servers := c.json("GET", "/api/ai-agents/mcp-findings?kind=mcp_server", "", 200).([]any)
	if len(creds) != 2 || len(servers) != 3 {
		t.Errorf("credentials %d, servers %d", len(creds), len(servers))
	}
	for _, f := range creds {
		m := f.(map[string]any)
		if m["secret_type"] == nil || len(m["fingerprint"].(string)) != 16 || m["path"] == nil || m["location"] == nil {
			t.Errorf("credential finding = %v", m)
		}
		for k := range m {
			if k == "value" || k == "secret" || k == "match" {
				t.Errorf("a finding carries a %q field", k)
			}
		}
	}
	// owners: a committer who is a person, a CODEOWNERS team, nobody
	byLoc := map[string]map[string]any{}
	for _, f := range all {
		m := f.(map[string]any)
		byLoc[m["path"].(string)+" "+m["location"].(string)] = m
	}
	if o := at(byLoc[".mcp.json mcpServers.github"], "owner"); at(o, "source") != "committer" || at(o, "identity", "name") == nil {
		t.Errorf("committer-owned finding owner = %v", o)
	}
	if o := at(byLoc[".cursor/mcp.json mcpServers.warehouse"], "owner"); at(o, "source") != "codeowners" || at(o, "identity") != nil ||
		at(o, "ref") != "github-team:larkspur/data" {
		t.Errorf("team-owned finding owner = %v", o)
	}
	if o := at(byLoc["tools/mcp.json servers.ops"], "owner"); at(o, "source") != "none" || at(o, "ref") != nil {
		t.Errorf("unowned finding owner = %v", o)
	}
	rec := c.do("GET", "/api/ai-agents/mcp-findings?kind=bogus", "")
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("bad kind: status %d", rec.Code)
	}
}

// Tenant B never sees tenant A's agents or findings.
func TestAgentRoutesAreTenantScoped(t *testing.T) {
	f := storetest.TwoTenants(t)
	for path, own := range map[string]string{"/api/ai-agents": "Helper Bot", "/api/ai-agents/mcp-findings": "github-scan"} {
		a := serveOnce(isolationServer(t, f, f.A.ID).Handler(), http.MethodGet, path, "")
		if a.Code != 200 || !leaks(a.Body.String()) {
			t.Errorf("as A, %s: %d, sentinel visible = %v (positive control)", path, a.Code, leaks(a.Body.String()))
		}
		b := serveOnce(isolationServer(t, f, f.B.ID).Handler(), http.MethodGet, path, "")
		if b.Code != 200 || leaks(b.Body.String()) || strings.Contains(b.Body.String(), "tenant-a") {
			t.Errorf("as B, %s: %d %.300s", path, b.Code, b.Body.String())
		}
		if !strings.Contains(b.Body.String(), own) {
			t.Errorf("as B, %s shows none of B's own rows: %.200s", path, b.Body.String())
		}
	}
}
