package entra

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// Integration test against an Entra developer tenant (needs-human). It is
// skipped unless the variables below are set, so CI makes no live call.
//
//	TESSERA_ENTRA_DEV_TENANT_ID      directory (tenant) GUID
//	TESSERA_ENTRA_DEV_CLIENT_ID      application (client) id
//	TESSERA_ENTRA_DEV_CLIENT_SECRET  the client secret
//
// Run: go test ./internal/connectors/entra -run Integration -v
func TestIntegrationDevTenant(t *testing.T) {
	tenant := os.Getenv("TESSERA_ENTRA_DEV_TENANT_ID")
	if tenant == "" {
		t.Skip("TESSERA_ENTRA_DEV_TENANT_ID is not set: skipping the live Entra developer tenant test (needs-human)")
	}
	cfg := Config{TenantID: tenant, ClientID: os.Getenv("TESSERA_ENTRA_DEV_CLIENT_ID"),
		ClientSecret: connsync.NewSecret(os.Getenv("TESSERA_ENTRA_DEV_CLIENT_SECRET")), EmitIdentities: true, SignInActivity: true}
	rt := connsync.RuntimeFromEnv(os.Getenv)
	hc, err := connsync.NewHTTPClient(rt, safehttp.Options{})
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
		t.Errorf("a developer tenant always has users: accounts=%d identities=%d", len(res.Accounts), len(res.Identities))
	}
	t.Logf("full: %d accounts, %d groups, %d resources, %d edges", len(res.Accounts), len(res.Groups), len(res.Resources), len(res.Edges))
	res2, err := c.Discover(ctx) // delta from the stored links
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
