package wire_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/bedrockagents/bedrockfake"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed/wire"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/mcpserver/mcpfake"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/checks"
)

const (
	mcpToken     = "mcp-token-secret-value"
	brAKID       = "AKIAIOSFODNN7EXAMPLE"
	brSecret     = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	brAgentARN   = "arn:aws:bedrock:us-east-1:123456789012:agent/AGENT00001"
	brRoleARN    = "arn:aws:iam::123456789012:role/agent-role"
	brCredential = `{"access_key_id":"` + brAKID + `","secret_access_key":"` + brSecret + `"}`
)

func mcpRig(t *testing.T) (governed.Params, governed.Net, *mcpfake.Fake) {
	t.Helper()
	tr := true
	fk := mcpfake.New(mcpToken, mcpfake.Tool{Name: "search", ReadOnly: &tr}, mcpfake.Tool{Name: "run_command"})
	srv, n := serve(t, fk)
	return governed.Params{Type: governed.MCP, BaseURL: srv.URL + "/mcp", Settings: map[string]string{"owner": "olu@acme.example"}, Secret: mcpToken}, n, fk
}

func TestMCPProberAndConnector(t *testing.T) {
	p, n, fk := mcpRig(t)
	pr := prober(t, p, n)
	wantPass(t, pr, "mcp", "endpoint_reachable", "auth_ok", "read_probe")
	for _, m := range fk.Methods() {
		if m != "initialize" && m != "notifications/initialized" && m != "tools/list" {
			t.Errorf("the probe sent %s", m)
		}
	}
	auth, err := pr.Authenticate(context.Background())
	if err != nil || !auth.OK || auth.Mode != "bearer_token" {
		t.Errorf("auth = %+v, %v", auth, err)
	}
	s, err := pr.Sample(context.Background(), connectors.SampleQuery{Op: "probe"})
	if err != nil || !s.Available || s.PerClass["tool"] != 2 {
		t.Errorf("sample = %+v, %v", s, err)
	}
	cn, err := wire.Connector(p, n)
	if err != nil {
		t.Fatal(err)
	}
	res, err := cn.Discover(context.Background())
	if err != nil || cn.System() != "mcp" || len(res.Identities) != 1 || len(res.Permissions) != 2 || res.Stats == nil || res.Identities[0].Owner == nil {
		t.Fatalf("discover = %+v, %v", res, err)
	}
	priv := 0
	for _, pm := range res.Permissions {
		if pm.Privileged {
			priv++
		}
	}
	if priv != 1 {
		t.Errorf("%d privileged tools, want run_command only", priv)
	}
	// a header-named key
	p.Settings["auth_header"] = "X-Api-Key"
	if _, err := wire.Prober(p, n); err != nil {
		t.Errorf("api key header: %v", err)
	}
}

func TestMCPProber_WrongToken(t *testing.T) {
	p, n, _ := mcpRig(t)
	p.Secret = "not-the-token"
	if r := run(t, prober(t, p, n), "auth_ok", checks.Env{TemplateID: "mcp"}); r.Status != checks.Fail {
		t.Errorf("auth_ok with a wrong token: %s %s", r.Status, r.Message)
	}
}

func TestMCPHostIsChecked(t *testing.T) {
	p, n, _ := mcpRig(t)
	n.RT = connsync.Runtime{Env: config.Prod}
	for _, u := range []string{"http://tools.acme.example/mcp", "https://u:p@tools.acme.example/mcp", "https://127.0.0.1/mcp", "https://tools.acme.example/mcp?x=1"} {
		p.BaseURL = u
		if _, err := wire.Prober(p, n); err == nil {
			t.Errorf("%s accepted in prod", u)
		}
		if _, err := wire.Connector(p, n); err == nil {
			t.Errorf("connector accepted %s in prod", u)
		}
	}
	p.BaseURL = "https://tools.acme.example/mcp"
	if _, err := wire.Prober(p, n); err != nil {
		t.Errorf("a public https host in prod: %v", err)
	}
}

func brRig(t *testing.T) (governed.Params, governed.Net, *bedrockfake.Fake) {
	t.Helper()
	fk := bedrockfake.New(brAKID, brSecret, "", "us-east-1", bedrockfake.Agent{ID: "AGENT00001", Name: "support-bot", ARN: brAgentARN, Status: "PREPARED",
		Role: brRoleARN, Model: "anthropic.claude-3-haiku", Tags: map[string]string{"sponsor": "pat@acme.example"},
		Groups: []bedrockfake.Group{{ID: "GRP0000001", Name: "code", State: "ENABLED", Signature: "AMAZON.CodeInterpreter"}},
		KBs:    []bedrockfake.KB{{ID: "KB00000001", State: "ENABLED"}}})
	srv, n := serve(t, fk)
	n.Endpoints = map[string]string{"TESSERA_BEDROCK_AGENT_URL": srv.URL}
	return governed.Params{Type: governed.Bedrock, Settings: map[string]string{"region": "us-east-1"}, Secret: brCredential}, n, fk
}

func TestBedrockProberAndConnector(t *testing.T) {
	p, n, fk := brRig(t)
	pr := prober(t, p, n)
	wantPass(t, pr, "bedrock", "auth_ok", "read_probe")
	auth, err := pr.Authenticate(context.Background())
	if err != nil || !auth.OK || auth.Mode != "sigv4_access_key" || auth.Identity != brAKID {
		t.Errorf("auth = %+v, %v", auth, err)
	}
	s, err := pr.Sample(context.Background(), connectors.SampleQuery{Op: "probe"})
	if err != nil || !s.Available || s.PerClass["agent"] != 1 {
		t.Errorf("sample = %+v, %v", s, err)
	}
	cn, err := wire.Connector(p, n)
	if err != nil {
		t.Fatal(err)
	}
	res, err := cn.Discover(context.Background())
	if err != nil || cn.System() != "aws-bedrock" || len(res.Agents) != 1 || res.Stats == nil || res.Identities[0].Owner == nil || res.Identities[0].Owner.Email != "pat@acme.example" {
		t.Fatalf("discover = %+v, %v", res, err)
	}
	if fk.Writes() != 0 || fk.BadSignatures() != 0 {
		t.Errorf("writes %d, bad signatures %d", fk.Writes(), fk.BadSignatures())
	}
}

func TestBedrockProber_WrongSecret(t *testing.T) {
	p, n, _ := brRig(t)
	p.Secret = strings.Replace(brCredential, brSecret, "x"+brSecret, 1)
	if r := run(t, prober(t, p, n), "auth_ok", checks.Env{TemplateID: "bedrock"}); r.Status != checks.Fail {
		t.Errorf("auth_ok with a wrong secret: %s %s", r.Status, r.Message)
	}
}

// The endpoint is the region's public one in production: an override is a dev setting, refused by the
// wiring in any other runtime and absent from every connection.
func TestBedrockEndpointOverrideIsRefusedOutsideDev(t *testing.T) {
	p, n, _ := brRig(t)
	for _, env := range []string{config.Prod, config.Test} {
		n.RT = connsync.Runtime{Env: env}
		if _, err := wire.Prober(p, n); err == nil || !strings.Contains(err.Error(), "refused outside dev") {
			t.Errorf("%s prober: %v", env, err)
		}
		if _, err := wire.Connector(p, n); err == nil {
			t.Errorf("%s connector accepted an override", env)
		}
	}
	n.RT, n.Endpoints = connsync.Runtime{Env: config.Prod}, nil
	if _, err := wire.Prober(p, n); err != nil {
		t.Errorf("prod without overrides: %v", err)
	}
	n.Endpoints = map[string]string{"TESSERA_BEDROCK_OTHER": "https://x.example"}
	n.RT = connsync.Runtime{Env: config.Dev}
	if _, err := wire.Prober(p, n); err == nil {
		t.Error("an unknown override key was accepted")
	}
}

func TestAgentPlatformParamsNeverPrintTheSecret(t *testing.T) {
	for _, p := range []governed.Params{
		{Type: governed.MCP, BaseURL: "https://tools.acme.example/mcp", Settings: map[string]string{"owner": "a@b.c"}, Secret: "TOP-SECRET-VALUE"},
		{Type: governed.Bedrock, Settings: map[string]string{"region": "us-east-1"}, Secret: "TOP-SECRET-VALUE"},
	} {
		for _, f := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if got := fmt.Sprintf(f, p); strings.Contains(got, "TOP-SECRET-VALUE") {
				t.Errorf("%s %s prints the secret: %s", p.Type, f, got)
			}
		}
		env, err := p.Env()
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"TESSERA_MCP_TOKEN", "TESSERA_BEDROCK_CREDENTIAL"} {
			if v := env(k); v != "" && (strings.Contains(v, "TOP-SECRET") || !strings.HasPrefix(v, "env:")) {
				t.Errorf("%s = %q", k, v)
			}
		}
		if v := env("TESSERA_BEDROCK_AGENT_URL"); v != "" {
			t.Errorf("a connection carries an endpoint override: %q", v)
		}
	}
}
