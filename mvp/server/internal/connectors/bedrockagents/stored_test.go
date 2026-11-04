package bedrockagents_test

import (
	"context"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/bedrockagents"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// FromStored reads the region from the stored config and the keys from the credential; only the dev
// override replaces the endpoint, and a refusal never echoes the credential.
func TestFromStored(t *testing.T) {
	r := newRig(t, "", nil)
	noEnv := func(string) string { return "" }
	hc, _ := safehttp.NewForTest(t, connsynctest.New(t, r.fake).Options(0))
	env := func(k string) string {
		if k == "TESSERA_BEDROCK_AGENT_URL" {
			return r.cfg.AgentURL
		}
		return ""
	}
	c, err := bedrockagents.FromStored(bedrockagents.Stored{Region: region, Credential: credJSON("")}, env, connsynctest.Runtime, hc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := c.Discover(context.Background()); err != nil || len(res.Agents) == 0 || c.System() != "aws-bedrock" {
		t.Errorf("Discover = %v, %v", res, err)
	}
	prod := connsync.Runtime{Env: "prod"}
	if _, err := bedrockagents.FromStored(bedrockagents.Stored{Region: region, Credential: credJSON("")}, env, prod, hc, nil); err == nil {
		t.Error("an endpoint override was accepted in prod")
	}
	for name, s := range map[string]bedrockagents.Stored{
		"no credential": {Region: region},
		"no region":     {Credential: credJSON("")},
		"bad region":    {Region: "us-east-1/../x", Credential: credJSON("")},
		"not json":      {Region: region, Credential: "AKIA-not-json-" + secret},
	} {
		if _, err := bedrockagents.FromStored(s, noEnv, prod, hc, nil); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), secret) {
			t.Errorf("%s: the error echoes the credential: %v", name, err)
		}
	}
}
