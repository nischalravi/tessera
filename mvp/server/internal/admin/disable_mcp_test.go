package admin_test

import (
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// TestDisableUserRevokesMCPTokens: disabling a user revokes, in the same
// transaction, the MCP tokens of the identity the user is linked to; another
// identity's tokens are untouched.
func TestDisableUserRevokesMCPTokens(t *testing.T) {
	h := newHarness(t)
	now := h.clk.now()
	var aliceID, bobID, botID int64
	mk := func(ext, typ string) int64 {
		var id int64
		h.tx(func(tx *store.TenantTx) (err error) {
			id, err = tx.InsertIdentity(&store.Identity{TenantID: tenantID, ExternalID: ext, Name: ext, Type: typ, Status: "active", CreatedAt: now})
			return err
		})
		return id
	}
	aliceID, bobID, botID = mk("alice", "person"), mk("bob", "person"), mk("bot", "ai_agent")
	admins := h.admins("root1", "root2", "root3")
	email := "alice@acme.example"
	u := &store.PlatformUser{TenantID: tenantID, Email: &email, DisplayName: "alice", IdentityID: &aliceID, CreatedAt: now}
	h.tx(func(tx *store.TenantTx) error {
		if err := tx.InsertPlatformUser(u); err != nil {
			return err
		}
		cl := &store.MCPClient{ClientID: "https://client.example/a.json", Name: "c", RedirectURIs: `["https://client.example/cb"]`,
			JWKS: `{"keys":[]}`, DocSHA256: "0000000000000000000000000000000000000000000000000000000000000000", ExpiresAt: now.Add(time.Hour)}
		if err := tx.UpsertMCPClient(cl, now); err != nil {
			return err
		}
		if err := tx.SetMCPClient(cl.ClientID, &botID, "active", now); err != nil {
			return err
		}
		res := &store.MCPResource{Resource: "https://mcp.example/mcp", Name: "r", SecretHash: strings.Repeat("0", 64), CreatedBy: "t", CreatedAt: now}
		if err := tx.InsertMCPResource(res); err != nil {
			return err
		}
		for jti, sub := range map[string]int64{"jti-alice": aliceID, "jti-bob": bobID} {
			if err := tx.InsertMCPToken(&store.MCPToken{JTI: jti, ClientID: cl.ClientID, SubjectID: sub, AgentID: botID,
				Audience: res.Resource, Scope: "a:b:c", Act: "null", GrantType: "token_exchange", PolicyVersion: "p",
				IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}); err != nil {
				return err
			}
		}
		return nil
	})
	if _, err := h.svc.DisableUser(h.ctx, h.as(admins[0]), u.ID, "left"); err != nil {
		t.Fatal(err)
	}
	h.tx(func(tx *store.TenantTx) error {
		a, err := tx.MCPToken("jti-alice")
		if err != nil {
			return err
		}
		if a.RevokedAt == nil || a.RevokedReason != auth.RevokedUserDisabled {
			t.Errorf("alice's token %+v, want revoked with %q", a, auth.RevokedUserDisabled)
		}
		b, err := tx.MCPToken("jti-bob")
		if err != nil {
			return err
		}
		if b.RevokedAt != nil {
			t.Errorf("bob's token was revoked: %+v", b)
		}
		return nil
	})
}
