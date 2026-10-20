package google

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// Integration test against a Google Workspace developer domain (needs-human).
// It is skipped unless the variables below are set, so CI makes no live call.
//
//	TESSERA_GOOGLE_DEV_KEY_FILE     path to the service account JSON key file
//	TESSERA_GOOGLE_DEV_ADMIN_EMAIL  administrator to impersonate (domain-wide delegation
//	                                granted for the read-only scopes in the README)
//
// Run: go test ./internal/connectors/google -run Integration -v
func TestIntegrationDevDomain(t *testing.T) {
	keyFile := os.Getenv("TESSERA_GOOGLE_DEV_KEY_FILE")
	if keyFile == "" {
		t.Skip("TESSERA_GOOGLE_DEV_KEY_FILE is not set: skipping the live Google Workspace test (needs-human)")
	}
	sec, err := connsync.ResolveSecret("file:"+keyFile, os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{AdminEmail: os.Getenv("TESSERA_GOOGLE_DEV_ADMIN_EMAIL"), EmitIdentities: true, Groups: true, Roles: true}
	if cfg.ServiceAccountEmail, cfg.PrivateKey, cfg.KeyID, err = parseServiceAccountKey(sec.Reveal()); err != nil {
		t.Fatal(err)
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
		t.Errorf("a Workspace domain always has users: accounts=%d identities=%d", len(res.Accounts), len(res.Identities))
	}
	t.Logf("full: %d accounts, %d groups, %d edges", len(res.Accounts), len(res.Groups), len(res.Edges))
	res2, err := c.Discover(ctx) // incremental from the stored snapshot
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.Accounts) != len(res.Accounts) {
		t.Errorf("incremental sync changed the account count: %d -> %d", len(res.Accounts), len(res2.Accounts))
	}
}
