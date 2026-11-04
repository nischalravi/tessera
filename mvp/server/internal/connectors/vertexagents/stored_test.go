package vertexagents_test

import (
	"context"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/vertexagents"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/vertexagents/vertexfake"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// FromStored reads the project, location and owner from the stored config and the key from the credential;
// the dev overrides apply only when the caller passes them, and a refusal never echoes the credential.
func TestFromStored(t *testing.T) {
	r := newRig(t, nil)
	noEnv := func(string) string { return "" }
	hc, _ := safehttp.NewForTest(t, r.srv.Options(0))
	env := func(k string) string {
		switch k {
		case "TESSERA_VERTEX_API_URL":
			return r.srv.URL
		case "TESSERA_VERTEX_TOKEN_URL":
			return r.srv.URL + "/token"
		}
		return ""
	}
	key := vertexfake.Key(sa)
	c, err := vertexagents.FromStored(vertexagents.Stored{ProjectID: project, Location: loc, Owner: "olu@acme.example", Credential: key}, env, connsynctest.Runtime, hc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := c.Discover(context.Background()); err != nil || len(res.Agents) != 3 || c.System() != "gcp-vertex" {
		t.Errorf("Discover = %v, %v", res, err)
	}
	prod := connsync.Runtime{Env: "prod"}
	if _, err := vertexagents.FromStored(vertexagents.Stored{ProjectID: project, Location: loc, Credential: key}, env, prod, hc, nil); err == nil {
		t.Error("endpoint overrides were accepted in prod")
	}
	for name, s := range map[string]vertexagents.Stored{
		"no credential": {ProjectID: project, Location: loc},
		"no project":    {Location: loc, Credential: key},
		"no location":   {ProjectID: project, Credential: key},
		"bad owner":     {ProjectID: project, Location: loc, Owner: "not an email", Credential: key},
		"not a key":     {ProjectID: project, Location: loc, Credential: "not-json-secret-value"},
	} {
		if _, err := vertexagents.FromStored(s, noEnv, prod, hc, nil); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "not-json-secret-value") {
			t.Errorf("%s: the error echoes the credential: %v", name, err)
		}
	}
}
