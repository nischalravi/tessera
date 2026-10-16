package readiness

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/agent"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// agentSvc is a live-capable service wired to an agent service over the same
// database, and the id of an active agent of the test tenant.
func agentSvc(t *testing.T) (st Scope, s *Service, ag *agent.Service, agentID string) {
	t.Helper()
	st, s = newStore(t), liveSvc(t)
	ag = &agent.Service{DB: st.DB, Hub: agent.NewHub(nil), Clock: clockAt(t0)}
	s.Runner.Live.Agents = ag
	agentID = store.NewID()
	write(t, st, func(c *store.TenantTx) error {
		if err := c.InsertDirectoryAgent(&store.DirectoryAgent{ID: agentID, Name: "dc-agent", CreatedBy: "admin", CreatedAt: t0}); err != nil {
			return err
		}
		return c.ActivateDirectoryAgent(agentID, strings.Repeat("c", 64), store.AgentTelemetry{Version: agent.Version}, t0)
	})
	return st, s, ag, agentID
}

func newLDAP(t *testing.T, s *Service, st Scope) string {
	t.Helper()
	var id string
	write(t, st, func(c *store.TenantTx) error {
		b, err := s.Create(c, CreateInput{Name: "Corp LDAP", ConnectorType: "ldap", System: "corp-ldap", Config: json.RawMessage(ldapCfg)}, "admin", t0)
		id = b.Conn.ID
		return err
	})
	return id
}

// TestLive_AgentCredentialReference: agent:<id>/<name> must name an active
// agent of the tenant; the connection is then probed through the agent (typed
// operations, no direct dial, no stored secret); a revoked agent fails the run
// closed instead of falling back to a direct dial.
func TestLive_AgentCredentialReference(t *testing.T) {
	st, s, ag, agentID := agentSvc(t)
	id := newLDAP(t, s, st)
	set := func(ref string) error {
		return st.Write(context.Background(), func(c *store.TenantTx) error {
			_, err := s.SetCredential(c, id, CredentialInput{Reference: ref}, "admin", t0)
			return err
		})
	}
	for ref, code := range map[string]string{
		"agent:" + store.NewID() + "/svc":                  "unknown_agent",
		"agent:" + agentID + "/../etc":                     "invalid_credential",
		"agent:" + agentID:                                 "invalid_credential",
		"agent:" + agentID + "/a b":                        "invalid_credential",
		"agent:" + agentID + "/" + strings.Repeat("x", 65): "invalid_credential",
	} {
		var re *Error
		if err := set(ref); !errors.As(err, &re) || re.Code != code {
			t.Errorf("%q: %v (want %s)", ref, err, code)
		}
	}
	ref := "agent:" + agentID + "/svc-ldap"
	if err := set(ref); err != nil {
		t.Fatal(err)
	}
	// The run binds the agent and builds a RemoteProber, with no secret here.
	read(t, st, func(c *store.TenantTx) error {
		b, err := s.Current(c, id, t0)
		if err != nil {
			return err
		}
		if err := s.loadCredential(c, b); err != nil {
			return err
		}
		if b.cred != "" || b.agentID != agentID || b.agentCred != "svc-ldap" {
			t.Errorf("bundle: cred %q agent %q/%q", b.cred, b.agentID, b.agentCred)
		}
		p, err := s.Runner.withDefaults().ProberFor(b, t0)
		if _, ok := p.(*agent.RemoteProber); !ok || err != nil {
			t.Errorf("prober: %T %v", p, err)
		}
		return nil
	})
	// The agent is offline (nothing polls): checks report an error naming the
	// agent, never a direct dial to the private host.
	write(t, st, func(c *store.TenantTx) error {
		for _, item := range []string{"base.owner", "base.correlation.key", "base.stale.threshold"} {
			if _, err := s.Attest(c, id, item, "checked in the console", "admin", t0); err != nil {
				return err
			}
		}
		_, err := s.Transition(c, id, store.StateReadyToValidate, "admin", t0)
		return err
	})
	v, err := s.Validate(context.Background(), st, id, "admin", clockAt(t0))
	if err != nil {
		t.Fatal(err)
	}
	if v.Simulated {
		t.Error("an agent run is labelled simulated")
	}
	if r := resultFor(v, "ldap.tls.ldaps", "tls_handshake"); r == nil || r.Status != "error" || !strings.Contains(r.Message, "Directory Agent is offline") {
		t.Errorf("tls_handshake: %+v", r)
	}

	// Without the agent link a reference to an agent has no prober.
	s.Runner.Live.Agents = nil
	read(t, st, func(c *store.TenantTx) error {
		b, _ := s.Current(c, id, t0)
		if err := s.loadCredential(c, b); err != nil {
			t.Errorf("loadCredential without an agent link: %v", err)
		}
		if p, err := s.Runner.withDefaults().ProberFor(b, t0); err == nil || p != nil {
			t.Errorf("a prober without an agent link: %T %v", p, err)
		}
		return nil
	})
	s.Runner.Live.Agents = ag

	// Revoked: the run fails closed.
	write(t, st, func(c *store.TenantTx) error { return ag.Revoke(c, agentID, "admin", t0) })
	read(t, st, func(c *store.TenantTx) error {
		b, _ := s.Current(c, id, t0)
		err := s.loadCredential(c, b)
		if err == nil || !strings.Contains(err.Error(), "revoked") {
			t.Errorf("revoked agent: %v", err)
		}
		return nil
	})
	if err := set("agent:" + agentID + "/another"); err == nil {
		t.Error("a credential reference to a revoked agent was accepted")
	}
}

// TestLive_AgentNeverDialsDirectly: even in dev with the private-target
// allowlist, a connection that names an agent is not dialed by the server.
func TestLive_AgentNeverDialsDirectly(t *testing.T) {
	st, s, _, agentID := agentSvc(t)
	s.Runner.Live.Env = config.Dev
	id := newLDAP(t, s, st)
	write(t, st, func(c *store.TenantTx) error {
		_, err := s.SetCredential(c, id, CredentialInput{Reference: "agent:" + agentID + "/svc"}, "admin", t0)
		return err
	})
	read(t, st, func(c *store.TenantTx) error {
		b, _ := s.Current(c, id, t0)
		if err := s.loadCredential(c, b); err != nil {
			t.Fatal(err)
		}
		p, ok, err := s.Runner.Live.liveProber(b, t0)
		if _, isAgent := p.(*agent.RemoteProber); !ok || !isAgent || err != nil {
			t.Errorf("%T %v %v", p, ok, err)
		}
		return nil
	})
}
