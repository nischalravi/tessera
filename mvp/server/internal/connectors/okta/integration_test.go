package okta

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// Integration test against an Okta developer org (needs-human). It is skipped
// unless the variables below are set, so CI makes no live call.
//
//	TESSERA_OKTA_DEV_ORG_URL       https://dev-123456.okta.com
//	TESSERA_OKTA_DEV_API_TOKEN     an SSWS token of a read-only admin, or
//	TESSERA_OKTA_DEV_CLIENT_ID + TESSERA_OKTA_DEV_PRIVATE_KEY_FILE [+ TESSERA_OKTA_DEV_KEY_ID]
//
// Run: go test ./internal/connectors/okta -run Integration -v
func TestIntegrationDevOrg(t *testing.T) {
	org := os.Getenv("TESSERA_OKTA_DEV_ORG_URL")
	if org == "" {
		t.Skip("TESSERA_OKTA_DEV_ORG_URL is not set: skipping the live Okta developer org test (needs-human)")
	}
	cfg := Config{OrgURL: org, EmitIdentities: true, ClientID: os.Getenv("TESSERA_OKTA_DEV_CLIENT_ID"), KeyID: os.Getenv("TESSERA_OKTA_DEV_KEY_ID")}
	if tok := os.Getenv("TESSERA_OKTA_DEV_API_TOKEN"); tok != "" {
		cfg.APIToken = connsync.NewSecret(tok)
	}
	if f := os.Getenv("TESSERA_OKTA_DEV_PRIVATE_KEY_FILE"); f != "" {
		k, err := connsync.ResolveSecret("file:"+f, os.Getenv)
		if err != nil {
			t.Fatal(err)
		}
		cfg.PrivateKey = k
	}
	rt := connsync.Runtime{Env: "prod"}
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: "prod", Timeout: 30 * time.Second, MaxBodyBytes: 16 << 20})
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(cfg, rt, hc, nil)
	if err != nil {
		t.Fatal(err)
	}
	ms := &connsync.MemoryStore{}
	ctx, cancel := context.WithTimeout(connsync.WithStore(context.Background(), ms), 10*time.Minute)
	defer cancel()
	res, err := c.Discover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Accounts) == 0 || len(res.Identities) == 0 {
		t.Errorf("a developer org always has users: accounts=%d identities=%d", len(res.Accounts), len(res.Identities))
	}
	t.Logf("full: %d accounts, %d groups, %d resources, %d edges", len(res.Accounts), len(res.Groups), len(res.Resources), len(res.Edges))
	res2, err := c.Discover(ctx) // incremental from the checkpoint
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.Accounts) != len(res.Accounts) {
		t.Errorf("incremental sync changed the account count: %d -> %d", len(res.Accounts), len(res2.Accounts))
	}
	n := 0
	if err := c.StreamEvents(ctx, nil, func(connectors.Event) error { n++; return nil }); err != nil {
		t.Fatal(err)
	}
	t.Logf("usage events: %d", n)
}
