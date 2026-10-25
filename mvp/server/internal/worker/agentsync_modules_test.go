package worker_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/agent"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/worker"
)

const (
	racfConfig = `{"host":"zos.corp.example","port":636,"bind_dn":"racfid=TESSERA,profiletype=USER,cn=RACFA","base_dns":["cn=RACFA"]}`
	ibmiConfig = `{"host":"as400.corp.example","port":9471,"bind_dn":"TESSERA"}`
)

// TestQueueAgentSyncs_Modules: a racf or ibmi connection bound to an active
// agent queues a sync job that names its module; an ldap one names none; a
// racf connection with a sealed (server-held) credential queues nothing, as a
// module reads only on the agent. The payload carries no secret.
func TestQueueAgentSyncs_Modules(t *testing.T) {
	e := newEnv(t, tenantA)
	a := e.addAgent(t, tenantA, "mf-agent", false)
	cl := e.addConn(t, tenantA, "corp-ldap", "ldap", "agent:"+a+"/svc", ldapConfig)
	cr := e.addConn(t, tenantA, "zos", "racf", "agent:"+a+"/racf", racfConfig)
	ci := e.addConn(t, tenantA, "iseries", "ibmi", "agent:"+a+"/ibmi", ibmiConfig)
	e.addConn(t, tenantA, "zos-sealed", "racf", "sealed:abc", racfConfig)
	if n := e.queueSyncs(t, tenantA, "w1"); n != 3 {
		t.Fatalf("queued %d jobs, want 3", n)
	}
	want := map[string]string{cl: "", cr: agent.ModuleRACF, ci: agent.ModuleIBMi}
	for _, j := range e.agentJobs(t, tenantA) {
		var spec agent.SyncSpec
		if err := json.Unmarshal([]byte(j.Payload), &spec); err != nil || spec.Validate() != nil {
			t.Fatalf("payload %s: %v", j.Payload, err)
		}
		if m, ok := want[j.ConnectionID]; !ok || spec.Module != m {
			t.Errorf("connection %s: module %q, want %q", j.ConnectionID, spec.Module, m)
		}
		if strings.Contains(j.Payload, "password") || strings.Contains(j.Payload, "secret") {
			t.Errorf("the payload carries a secret: %s", j.Payload)
		}
		delete(want, j.ConnectionID)
	}
	if len(want) != 0 {
		t.Errorf("no job for %v", want)
	}
}

// TestRecordAgentSync_Module: a module's listing is ingested like any other,
// its privileged groups keep the flag, and only the attributes the module
// declares (or the connection maps) are taken from it.
func TestRecordAgentSync_Module(t *testing.T) {
	e := newEnv(t, tenantA)
	a := e.addAgent(t, tenantA, "mf-agent", false)
	conn := e.addConn(t, tenantA, "zos", "racf", "agent:"+a+"/racf", racfConfig)
	res := &agent.SyncResult{
		Accounts: []agent.SyncAccount{{ExternalID: "racfid=IBMUSER,profiletype=USER,cn=RACFA", Username: "IBMUSER", Status: "active",
			Extra: []agent.SyncExtra{{Scope: "account", Target: "racfOwner", Value: "SYS1"}, {Scope: "account", Target: "evil", Value: "x"}}}},
		Groups:  []agent.SyncGroup{{ExternalID: "racf-attr:SPECIAL", Name: "RACF SPECIAL attribute", Privileged: true}},
		Members: []agent.SyncMember{{Account: "racfid=IBMUSER,profiletype=USER,cn=RACFA", Group: "racf-attr:SPECIAL"}},
	}
	if err := e.db.InTenant(t.Context(), tenantA, func(tx *store.TenantTx) error {
		_, err := worker.RecordAgentSync(tx, e.clk.Now(), &store.AgentJob{ID: "job-1", AgentID: a, ConnectionID: conn},
			agent.SyncSpec{System: "zos", Module: agent.ModuleRACF}, res)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.db.ReadTenant(t.Context(), tenantA, func(tx *store.TenantTx) error {
		as, err := tx.Accounts()
		if err != nil || len(as) != 1 || as[0].System != "zos" || as[0].Username != "IBMUSER" {
			t.Errorf("accounts: %v %v", as, err)
		}
		gs, err := tx.Groups()
		if err != nil || len(gs) != 1 || gs[0].Name != "RACF SPECIAL attribute" || !gs[0].Privileged {
			t.Errorf("groups: %v %v", gs, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestModuleAttribute(t *testing.T) {
	for module, attrs := range agent.ModuleAccountAttrs {
		for _, a := range attrs {
			if !agent.ModuleAttribute(module, a) {
				t.Errorf("%s.%s", module, a)
			}
		}
		if agent.ModuleAttribute(module, "evil") || agent.ModuleAttribute("", attrs[0]) {
			t.Errorf("%s accepts an attribute it does not declare", module)
		}
	}
}
