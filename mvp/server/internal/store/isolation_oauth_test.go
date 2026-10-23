package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// OAuth authorization server isolation (design §7.4, §14.4): a tenant sees
// and changes only its own API clients, device grants and refresh tokens;
// another tenant's ids and hashes look nonexistent, and rows that reference
// another tenant's rows are refused.

type oauthRows struct {
	auth    authRows
	cli     *store.APIClient
	machine *store.APIClient
	grant   *store.DeviceGrant
	rt      *store.RefreshToken
}

func seedOAuthRows(t *testing.T, db *store.DB, tid tenancy.ID, tag byte) oauthRows {
	t.Helper()
	now := storetest.Now
	r := oauthRows{auth: seedAuthRows(t, db, tid, tag)}
	err := db.InTenant(context.Background(), tid, func(c *store.TenantTx) error {
		r.cli = &store.APIClient{ClientID: "tessera-cli", Name: "Tessera CLI", Kind: store.ClientFirstPartyCLI,
			GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"}, TokenEndpointAuthMethod: "none",
			DPoPRequired: true, AllowedScopes: []string{"tessera:read"}, CreatedAt: now}
		if err := c.InsertAPIClient(r.cli); err != nil {
			return err
		}
		r.machine = &store.APIClient{ClientID: "tsc_only" + string(tag), Name: "ETL", Kind: store.ClientMachine,
			GrantTypes: []string{"client_credentials"}, TokenEndpointAuthMethod: "private_key_jwt", DPoPRequired: true,
			AllowedScopes: []string{"tessera:read"}, Roles: []string{"viewer"}, OwnerUserID: &r.auth.user.ID, CreatedAt: now}
		if err := c.InsertAPIClient(r.machine); err != nil {
			return err
		}
		r.grant = &store.DeviceGrant{ClientID: "tessera-cli", DeviceCodeHash: hexHash(tag + 10), UserCodeHash: hexHash(tag + 11),
			Scope: "tessera:read", Interval: 5, CreatedAt: now, ExpiresAt: now.Add(300 * time.Second)}
		if err := c.InsertDeviceGrant(r.grant); err != nil {
			return err
		}
		r.rt = &store.RefreshToken{TokenHash: hexHash(tag + 12), FamilyID: uuid.New(), SessionID: r.auth.session.ID,
			UserID: r.auth.user.ID, ClientID: "tessera-cli", DPoPJKT: "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
			Scope: "tessera:read", IssuedAt: now, ExpiresAt: now.Add(12 * time.Hour), AbsoluteExpiresAt: now.Add(24 * time.Hour)}
		return c.InsertRefreshToken(r.rt)
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func oauthFixture(t *testing.T) (*storetest.Fixture, oauthRows, oauthRows) {
	t.Helper()
	f := storetest.TwoTenants(t)
	return f, seedOAuthRows(t, f.DB, f.A.ID, 'a'), seedOAuthRows(t, f.DB, f.B.ID, 'b')
}

// oauthMutations change one of A's rows; run in B they must fail with
// ErrNotFound and leave A's row alone.
var oauthMutations = map[string]func(c *store.TenantTx, a oauthRows) error{
	"TouchAPIClient": func(c *store.TenantTx, a oauthRows) error {
		return c.TouchAPIClient("tsc_onlya", storetest.Now)
	},
	"SetAPIClientKeys": func(c *store.TenantTx, a oauthRows) error {
		return c.SetAPIClientKeys("tsc_onlya", []byte(`{"keys":[]}`))
	},
	"SetAPIClientStatus": func(c *store.TenantTx, a oauthRows) error {
		return c.SetAPIClientStatus("tsc_onlya", store.ClientDisabled)
	},
	"PollDeviceGrant": func(c *store.TenantTx, a oauthRows) error {
		return c.PollDeviceGrant(a.grant.ID, storetest.Now, 10)
	},
	"ApproveDeviceGrant": func(c *store.TenantTx, a oauthRows) error {
		return c.ApproveDeviceGrant(a.grant.ID, a.auth.user.ID, a.auth.ctx.ID, a.auth.session.ID, storetest.Now)
	},
	"DenyDeviceGrant": func(c *store.TenantTx, a oauthRows) error {
		return c.DenyDeviceGrant(a.grant.ID, a.auth.user.ID, storetest.Now)
	},
	"ExpireDeviceGrant":  func(c *store.TenantTx, a oauthRows) error { return c.ExpireDeviceGrant(a.grant.ID) },
	"ConsumeDeviceGrant": func(c *store.TenantTx, a oauthRows) error { return c.ConsumeDeviceGrant(a.grant.ID, storetest.Now) },
	"UseRefreshToken":    func(c *store.TenantTx, a oauthRows) error { return c.UseRefreshToken(a.rt.ID, storetest.Now) },
}

func TestIsolation_OAuthRows(t *testing.T) {
	f, a, b := oauthFixture(t)
	inB(t, f, func(c *store.TenantTx) error {
		// both tenants have a "tessera-cli": B resolves its own
		cli, err := c.APIClientByClientID("tessera-cli")
		if err != nil || cli.ID != b.cli.ID || cli.TenantID != f.B.ID {
			t.Errorf("APIClientByClientID in B: %+v %v", cli, err)
		}
		cs, err := c.APIClients()
		if err != nil || len(cs) != 2 {
			t.Errorf("APIClients in B: %d %v", len(cs), err)
		}
		for _, x := range cs {
			if x.TenantID != f.B.ID || x.ID == a.cli.ID || x.ID == a.machine.ID {
				t.Errorf("APIClients in B returned %+v", x)
			}
		}
		for name, get := range map[string]func() error{
			"APIClientByClientID(A's machine)": func() error { _, err := c.APIClientByClientID(a.machine.ClientID); return err },
			"DeviceGrant":                      func() error { _, err := c.DeviceGrant(a.grant.ID); return err },
			"DeviceGrantByDeviceCodeHash": func() error {
				_, err := c.DeviceGrantByDeviceCodeHash(a.grant.DeviceCodeHash)
				return err
			},
			"PendingDeviceGrantByUserCodeHash": func() error {
				_, err := c.PendingDeviceGrantByUserCodeHash(a.grant.UserCodeHash, storetest.Now)
				return err
			},
			"RefreshTokenByHash": func() error { _, err := c.RefreshTokenByHash(a.rt.TokenHash); return err },
		} {
			if err := get(); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("%s of A's row in B = %v, want ErrNotFound", name, err)
			}
		}
		if ts, err := c.RefreshTokensByFamily(a.rt.FamilyID); err != nil || len(ts) != 0 {
			t.Errorf("RefreshTokensByFamily(A's family) in B = %d %v, want none", len(ts), err)
		}
		if n, err := c.RevokeRefreshFamily(a.rt.FamilyID, "x", storetest.Now); err != nil || n != 0 {
			t.Errorf("RevokeRefreshFamily(A's family) in B revoked %d (%v)", n, err)
		}
		if n, err := c.RevokeSessionRefreshTokens(a.auth.session.ID, "x", storetest.Now); err != nil || n != 0 {
			t.Errorf("RevokeSessionRefreshTokens(A's session) in B revoked %d (%v)", n, err)
		}
		if n, err := c.RevokeUserRefreshTokens(a.auth.user.ID, "x", storetest.Now); err != nil || n != 0 {
			t.Errorf("RevokeUserRefreshTokens(A's user) in B revoked %d (%v)", n, err)
		}
		// expiring stale grants in B leaves A's alone
		if n, err := c.ExpireStaleDeviceGrants(storetest.Now.Add(time.Hour)); err != nil || n != 1 {
			t.Errorf("ExpireStaleDeviceGrants in B = %d %v, want only B's grant", n, err)
		}
		return nil
	})
	for name, fn := range oauthMutations {
		t.Run(name, func(t *testing.T) {
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return fn(c, a) })
			if !errors.Is(err, store.ErrNotFound) {
				t.Errorf("%s(A's row) in B = %v, want ErrNotFound", name, err)
			}
		})
	}
	// A's rows are untouched
	err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		g, err := c.DeviceGrant(a.grant.ID)
		if err != nil || g.Status != store.DevicePending || g.LastPolledAt != nil || g.Interval != 5 || g.ApprovedByUserID != nil {
			t.Errorf("A's device grant changed: %+v %v", g, err)
		}
		rt, err := c.RefreshTokenByHash(a.rt.TokenHash)
		if err != nil || rt.UsedAt != nil || rt.RevokedAt != nil {
			t.Errorf("A's refresh token changed: %+v %v", rt, err)
		}
		m, err := c.APIClientByClientID(a.machine.ClientID)
		if err != nil || m.LastUsedAt != nil || m.OwnerUserID == nil || *m.OwnerUserID != a.auth.user.ID ||
			len(m.Roles) != 1 || m.Roles[0] != "viewer" {
			t.Errorf("A's machine client changed: %+v %v", m, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestIsolation_OAuthInsertsRefused: a row stamped with another tenant, or
// referencing another tenant's row, is refused.
func TestIsolation_OAuthInsertsRefused(t *testing.T) {
	f, a, b := oauthFixture(t)
	now := storetest.Now
	crossTenant := map[string]func(c *store.TenantTx) error{
		"InsertAPIClient/stamped": func(c *store.TenantTx) error {
			return c.InsertAPIClient(&store.APIClient{TenantID: f.A.ID, ClientID: "x1x", Name: "x", Kind: store.ClientFirstPartyCLI,
				TokenEndpointAuthMethod: "none", DPoPRequired: true, CreatedAt: now})
		},
		"InsertAPIClient/owner is A's user": func(c *store.TenantTx) error {
			return c.InsertAPIClient(&store.APIClient{ClientID: "x2x", Name: "x", Kind: store.ClientMachine,
				TokenEndpointAuthMethod: "private_key_jwt", DPoPRequired: true, OwnerUserID: &a.auth.user.ID, CreatedAt: now})
		},
		"InsertDeviceGrant/stamped": func(c *store.TenantTx) error {
			return c.InsertDeviceGrant(&store.DeviceGrant{TenantID: f.A.ID, ClientID: "tessera-cli", DeviceCodeHash: hexHash('1'),
				UserCodeHash: hexHash('2'), Scope: "x", Interval: 5, CreatedAt: now, ExpiresAt: now})
		},
		"InsertRefreshToken/stamped": func(c *store.TenantTx) error {
			return c.InsertRefreshToken(&store.RefreshToken{TenantID: f.A.ID, TokenHash: hexHash('3'), FamilyID: uuid.New(),
				SessionID: b.auth.session.ID, UserID: b.auth.user.ID, ClientID: "tessera-cli", DPoPJKT: b.rt.DPoPJKT,
				Scope: "x", IssuedAt: now, ExpiresAt: now, AbsoluteExpiresAt: now})
		},
		"InsertRefreshToken/references A's session": func(c *store.TenantTx) error {
			return c.InsertRefreshToken(&store.RefreshToken{TokenHash: hexHash('4'), FamilyID: uuid.New(),
				SessionID: a.auth.session.ID, UserID: b.auth.user.ID, ClientID: "tessera-cli", DPoPJKT: b.rt.DPoPJKT,
				Scope: "x", IssuedAt: now, ExpiresAt: now, AbsoluteExpiresAt: now})
		},
		"InsertRefreshToken/references A's user": func(c *store.TenantTx) error {
			return c.InsertRefreshToken(&store.RefreshToken{TokenHash: hexHash('5'), FamilyID: uuid.New(),
				SessionID: b.auth.session.ID, UserID: a.auth.user.ID, ClientID: "tessera-cli", DPoPJKT: b.rt.DPoPJKT,
				Scope: "x", IssuedAt: now, ExpiresAt: now, AbsoluteExpiresAt: now})
		},
		"InsertRefreshToken/parent in A": func(c *store.TenantTx) error {
			return c.InsertRefreshToken(&store.RefreshToken{TokenHash: hexHash('6'), FamilyID: a.rt.FamilyID, ParentID: &a.rt.ID,
				SessionID: b.auth.session.ID, UserID: b.auth.user.ID, ClientID: "tessera-cli", DPoPJKT: b.rt.DPoPJKT,
				Scope: "x", IssuedAt: now, ExpiresAt: now, AbsoluteExpiresAt: now})
		},
		"ApproveDeviceGrant/by A's user": func(c *store.TenantTx) error {
			return c.ApproveDeviceGrant(b.grant.ID, a.auth.user.ID, b.auth.ctx.ID, b.auth.session.ID, now)
		},
		"ApproveDeviceGrant/A's session": func(c *store.TenantTx) error {
			return c.ApproveDeviceGrant(b.grant.ID, b.auth.user.ID, b.auth.ctx.ID, a.auth.session.ID, now)
		},
	}
	for name, fn := range crossTenant {
		t.Run(name, func(t *testing.T) {
			err := f.DB.InTenant(context.Background(), f.B.ID, fn)
			if !errors.Is(err, store.ErrCrossTenant) {
				t.Errorf("%s in B = %v, want ErrCrossTenant", name, err)
			}
		})
	}
	// a device grant naming a client that only A has fails the foreign key
	t.Run("InsertDeviceGrant/A's client", func(t *testing.T) {
		err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
			return c.InsertDeviceGrant(&store.DeviceGrant{ClientID: a.machine.ClientID, DeviceCodeHash: hexHash('7'),
				UserCodeHash: hexHash('8'), Scope: "x", Interval: 5, CreatedAt: now, ExpiresAt: now})
		})
		if err == nil {
			t.Error("a device grant for another tenant's client was accepted")
		}
	})
}

// TestOAuthSchemaRules: the schema's backstops (one pending user code per
// tenant, duplicate client ids, the machine-owner and CLI-client rules) and
// the single-use and rotation updates.
func TestOAuthSchemaRules(t *testing.T) {
	f, _, b := oauthFixture(t)
	now := storetest.Now
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		if err := c.InsertAPIClient(&store.APIClient{ClientID: "tessera-cli", Name: "dup", Kind: store.ClientFirstPartyCLI,
			TokenEndpointAuthMethod: "none", DPoPRequired: true, CreatedAt: now}); !errors.Is(err, store.ErrDuplicate) {
			t.Errorf("duplicate client id: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, fn := range map[string]func(c *store.TenantTx) error{
		"machine client without an owner": func(c *store.TenantTx) error {
			return c.InsertAPIClient(&store.APIClient{ClientID: "tsc_noowner", Name: "x", Kind: store.ClientMachine,
				TokenEndpointAuthMethod: "private_key_jwt", DPoPRequired: true, CreatedAt: now})
		},
		"CLI client without DPoP": func(c *store.TenantTx) error {
			return c.InsertAPIClient(&store.APIClient{ClientID: "cli-nodpop", Name: "x", Kind: store.ClientFirstPartyCLI,
				TokenEndpointAuthMethod: "none", DPoPRequired: false, CreatedAt: now})
		},
		"the same pending user code twice": func(c *store.TenantTx) error {
			return c.InsertDeviceGrant(&store.DeviceGrant{ClientID: "tessera-cli", DeviceCodeHash: hexHash('9'),
				UserCodeHash: b.grant.UserCodeHash, Scope: "x", Interval: 5, CreatedAt: now, ExpiresAt: now.Add(time.Minute)})
		},
		"a refresh token idle expiry past the absolute": func(c *store.TenantTx) error {
			return c.InsertRefreshToken(&store.RefreshToken{TokenHash: hexHash('a'), FamilyID: uuid.New(),
				SessionID: b.auth.session.ID, UserID: b.auth.user.ID, ClientID: "tessera-cli", DPoPJKT: b.rt.DPoPJKT,
				Scope: "x", IssuedAt: now, ExpiresAt: now.Add(2 * time.Hour), AbsoluteExpiresAt: now.Add(time.Hour)})
		},
		"a refresh token hash twice": func(c *store.TenantTx) error {
			return c.InsertRefreshToken(&store.RefreshToken{TokenHash: b.rt.TokenHash, FamilyID: uuid.New(),
				SessionID: b.auth.session.ID, UserID: b.auth.user.ID, ClientID: "tessera-cli", DPoPJKT: b.rt.DPoPJKT,
				Scope: "x", IssuedAt: now, ExpiresAt: now, AbsoluteExpiresAt: now})
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := f.DB.InTenant(context.Background(), f.B.ID, fn); err == nil {
				t.Errorf("%s was accepted", name)
			}
		})
	}
	err = f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		// an expired grant frees its user code and cannot be found or approved
		late := now.Add(10 * time.Minute)
		if _, err := c.PendingDeviceGrantByUserCodeHash(b.grant.UserCodeHash, late); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("expired grant found by user code: %v", err)
		}
		if err := c.ApproveDeviceGrant(b.grant.ID, b.auth.user.ID, b.auth.ctx.ID, b.auth.session.ID, late); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("expired grant approved: %v", err)
		}
		// approve once, consume once
		if err := c.ApproveDeviceGrant(b.grant.ID, b.auth.user.ID, b.auth.ctx.ID, b.auth.session.ID, now); err != nil {
			t.Fatal(err)
		}
		if err := c.ApproveDeviceGrant(b.grant.ID, b.auth.user.ID, b.auth.ctx.ID, b.auth.session.ID, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("approved twice: %v", err)
		}
		if err := c.ConsumeDeviceGrant(b.grant.ID, now); err != nil {
			t.Fatal(err)
		}
		if err := c.ConsumeDeviceGrant(b.grant.ID, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("consumed twice: %v", err)
		}
		// rotation: a token is used once; its family is revoked as a unit
		if err := c.UseRefreshToken(b.rt.ID, now); err != nil {
			t.Fatal(err)
		}
		if err := c.UseRefreshToken(b.rt.ID, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("refresh token used twice: %v", err)
		}
		child := &store.RefreshToken{TokenHash: hexHash('b'), FamilyID: b.rt.FamilyID, ParentID: &b.rt.ID,
			SessionID: b.auth.session.ID, UserID: b.auth.user.ID, ClientID: "tessera-cli", DPoPJKT: b.rt.DPoPJKT, Scope: "x",
			IssuedAt: now, ExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour)}
		if err := c.InsertRefreshToken(child); err != nil {
			t.Fatal(err)
		}
		if n, err := c.RevokeRefreshFamily(b.rt.FamilyID, "rt_reuse", now); err != nil || n != 2 {
			t.Errorf("RevokeRefreshFamily revoked %d (%v), want 2", n, err)
		}
		ts, err := c.RefreshTokensByFamily(b.rt.FamilyID)
		if err != nil || len(ts) != 2 || ts[0].RevokedAt == nil || ts[1].RevokedAt == nil || *ts[1].RevokedReason != "rt_reuse" {
			t.Errorf("family after revoke: %+v %v", ts, err)
		}
		if err := c.UseRefreshToken(child.ID, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a revoked token was used: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func oauthCovered() map[string]bool {
	out := map[string]bool{}
	for k := range oauthMutations {
		out[k] = true
	}
	for _, k := range []string{"InsertAPIClient", "APIClientByClientID", "APIClients", "InsertDeviceGrant", "DeviceGrant",
		"DeviceGrantByDeviceCodeHash", "PendingDeviceGrantByUserCodeHash", "ExpireStaleDeviceGrants", "InsertRefreshToken",
		"RefreshTokenByHash", "RefreshTokensByFamily", "RevokeRefreshFamily", "RevokeSessionRefreshTokens", "RevokeUserRefreshTokens"} {
		out[k] = true // TestIsolation_OAuthRows, TestIsolation_OAuthInsertsRefused
	}
	return out
}
