package workday

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// Integration test against a Workday implementation tenant (needs-human). It
// is skipped unless the variables below are set, so CI makes no live call.
//
//	TESSERA_WORKDAY_DEV_BASE_URL       services host, https://wd2-impl-services1.workday.com
//	TESSERA_WORKDAY_DEV_TENANT         tenant name
//	TESSERA_WORKDAY_DEV_CLIENT_ID      API client id
//	TESSERA_WORKDAY_DEV_CLIENT_SECRET  the API client secret
//	TESSERA_WORKDAY_DEV_REFRESH_TOKEN  optional: a refresh token (else client credentials)
//	TESSERA_WORKDAY_DEV_WORKERS_PATH   optional: workers path or custom report
//	TESSERA_WORKDAY_DEV_EVENTS_PATH    optional: events path or custom report
//
// Run: go test ./internal/connectors/workday -run Integration -v
func TestIntegrationDevTenant(t *testing.T) {
	base := os.Getenv("TESSERA_WORKDAY_DEV_BASE_URL")
	if base == "" {
		t.Skip("TESSERA_WORKDAY_DEV_BASE_URL is not set: skipping the live Workday tenant test (needs-human)")
	}
	cfg := Config{BaseURL: base, Tenant: os.Getenv("TESSERA_WORKDAY_DEV_TENANT"), ClientID: os.Getenv("TESSERA_WORKDAY_DEV_CLIENT_ID"),
		ClientSecret: connsync.NewSecret(os.Getenv("TESSERA_WORKDAY_DEV_CLIENT_SECRET")), EmitIdentities: true,
		WorkersPath: os.Getenv("TESSERA_WORKDAY_DEV_WORKERS_PATH"), EventsPath: os.Getenv("TESSERA_WORKDAY_DEV_EVENTS_PATH")}
	if r := os.Getenv("TESSERA_WORKDAY_DEV_REFRESH_TOKEN"); r != "" {
		cfg.RefreshToken = connsync.NewSecret(r)
	}
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
		t.Errorf("an implementation tenant always has workers: accounts=%d identities=%d", len(res.Accounts), len(res.Identities))
	}
	t.Logf("full: %d identities, %d accounts, %d groups", len(res.Identities), len(res.Accounts), len(res.Groups))
	res2, err := c.Discover(ctx) // from the stored watermark
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.Accounts) < len(res.Accounts) {
		t.Errorf("incremental sync lost accounts: %d -> %d", len(res.Accounts), len(res2.Accounts))
	}
	n := 0
	if err := c.StreamEvents(ctx, nil, func(connectors.Event) error { n++; return nil }); err != nil {
		t.Fatal(err)
	}
	t.Logf("HRIS events: %d", n)
}
