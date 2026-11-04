package wire_test

import (
	"context"
	"maps"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed/wire"
)

// The MCP, Bedrock, Vertex, Foundry, Copilot Studio and Agentforce connectors are built from the stored
// config (issue #814): they are marked connection-backed (they replace the env-configured connector of the
// system), read the same data, take a dev endpoint override only in dev, and a refusal never echoes the
// credential.
func TestAgentPlatformConnectorsAreConnectionBacked(t *testing.T) {
	mp, mn, _ := mcpRig(t)
	bp, bn, _ := brRig(t)
	type rig struct {
		p      governed.Params
		n      governed.Net
		system string
		key    string // the dev override of the base URL, when the type has one
	}
	rigs := []rig{{mp, mn, "mcp", "TESSERA_MCP_URL"}, {bp, bn, "aws-bedrock", ""}}
	for name, key := range map[string]string{"vertex": "", "foundry": "TESSERA_FOUNDRY_ENDPOINT", "copilot": "TESSERA_COPILOT_URL", "agentforce": "TESSERA_AGENTFORCE_BASE_URL"} {
		r := agentRigs[name](t)
		rigs = append(rigs, rig{r.p, r.n, r.system, key})
	}
	for _, tc := range rigs {
		t.Run(tc.p.Type, func(t *testing.T) {
			cn, err := wire.Connector(tc.p, tc.n)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := cn.(connectors.ConnectionBacked); !ok || cn.System() != tc.system {
				t.Errorf("connector %T (system %q) is not marked as connection-backed", cn, cn.System())
			}
			if res, err := cn.Discover(context.Background()); err != nil || res.Stats == nil {
				t.Fatalf("res = %+v, err = %v", res, err)
			}
			if tc.key != "" {
				// the dev override replaces the stored base URL
				real := tc.p.BaseURL
				q, n := tc.p, tc.n
				q.BaseURL = "https://other.example.com"
				n.Endpoints = maps.Clone(tc.n.Endpoints)
				if n.Endpoints == nil {
					n.Endpoints = map[string]string{}
				}
				n.Endpoints[tc.key] = real
				if _, err := wire.Connector(q, n); err != nil {
					t.Errorf("dev override: %v", err)
				}
			}
			// outside dev any override is refused; the error does not echo the credential
			n := tc.n
			n.RT = connsync.Runtime{Env: config.Prod}
			if len(n.Endpoints) == 0 {
				n.Endpoints = map[string]string{"TESSERA_MCP_URL": "https://x.example"}
			}
			if _, err := wire.Connector(tc.p, n); err == nil || !strings.Contains(err.Error(), "refused outside dev") || strings.Contains(err.Error(), tc.p.Secret) {
				t.Errorf("prod with an override: %v", err)
			}
		})
	}
}

// Hosts a connector would not open are refused with the credential kept out of the error.
func TestAgentPlatformStoredHostsAreChecked(t *testing.T) {
	mp, mn, _ := mcpRig(t)
	for _, tc := range []struct {
		name, typ, url string
	}{
		{"mcp metadata", governed.MCP, "https://169.254.169.254/mcp"},
		{"foundry other host", governed.Foundry, "https://evil.example.com/api/projects/x"},
		{"copilot other host", governed.Copilot, "https://evil.example.com"},
		{"agentforce other host", governed.Agentforce, "https://evil.example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, n := mp, mn
			n.Endpoints = nil
			switch tc.typ {
			case governed.Foundry:
				r := foundryRig(t)
				p, n = r.p, r.n
			case governed.Copilot:
				r := copilotRig(t)
				p, n = r.p, r.n
			case governed.Agentforce:
				r := agentforceRig(t)
				p, n = r.p, r.n
			}
			n.Endpoints = nil
			n.RT = connsync.Runtime{Env: config.Prod}
			p.BaseURL = tc.url
			if _, err := wire.Connector(p, n); err == nil || strings.Contains(err.Error(), p.Secret) {
				t.Errorf("accepted or echoed the credential: %v", err)
			}
		})
	}
}

// A missing credential fails closed: the connector does not open, so the env-configured one is not read.
func TestAgentPlatformsRefuseAMissingCredential(t *testing.T) {
	mp, mn, _ := mcpRig(t)
	bp, bn, _ := brRig(t)
	rigs := []agentRig{{p: mp, n: mn}, {p: bp, n: bn}}
	for name, mk := range agentRigs {
		_ = name
		rigs = append(rigs, mk(t))
	}
	for _, r := range rigs {
		r.p.Secret = ""
		if _, err := wire.Connector(r.p, r.n); err == nil || !strings.Contains(err.Error(), "no stored credential") {
			t.Errorf("%s: %v", r.p.Type, err)
		}
	}
}

// AgentCore is built from the stored snapshot name (confined to the tenant's directory), is marked
// connection-backed, and is refused in production like the env-configured one.
func TestAgentCoreIsConnectionBacked(t *testing.T) {
	p := agentcoreRig(t)
	n := governed.Net{RT: connsync.Runtime{Env: config.Dev}}
	cn, err := wire.Connector(p, n)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cn.(connectors.ConnectionBacked); !ok || cn.System() != "aws-agentcore" {
		t.Errorf("connector %T (system %q) is not marked as connection-backed", cn, cn.System())
	}
	if res, err := cn.Discover(context.Background()); err != nil || len(res.Agents) != 3 {
		t.Errorf("discover = %+v, %v", res, err)
	}
	prod := p
	prod.Prod = true
	if _, err := wire.Connector(prod, n); err == nil || !strings.Contains(err.Error(), "prod") {
		t.Errorf("prod: %v", err)
	}
	n.RT = connsync.Runtime{Env: config.Prod}
	if _, err := wire.Connector(p, n); err == nil {
		t.Error("prod runtime accepted")
	}
	p.Settings = map[string]string{"snapshot": "../x.json"}
	if _, err := wire.Connector(p, governed.Net{}); err == nil {
		t.Error("a snapshot outside the tenant directory accepted")
	}
}
