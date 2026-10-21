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

// Auth-core isolation (design §7.4, §14.4): a tenant sees and changes only
// its own IdP connections, users, logins, roles, authentication contexts,
// sessions and login transactions; another tenant's ids look nonexistent,
// and rows that reference another tenant's rows are refused by the guard
// triggers.

// authRows are one tenant's auth rows.
type authRows struct {
	conn    *store.IdPConnection
	user    *store.PlatformUser
	login   *store.ExternalLogin
	role    *store.RoleAssignment
	ctx     *store.AuthnContextRecord
	session *store.Session
	txn     *store.LoginTransaction
	inv     *store.BootstrapInvitation
	hash    string
}

func hexHash(c byte) string {
	b := make([]byte, 64)
	for i := range b {
		b[i] = c
	}
	return string(b)
}

func seedAuthRows(t *testing.T, db *store.DB, tid tenancy.ID, tag byte) authRows {
	t.Helper()
	now := storetest.Now
	var r authRows
	err := db.InTenant(context.Background(), tid, func(c *store.TenantTx) error {
		iss, cid := "https://idp.example/"+string(tag), "client"
		r.conn = &store.IdPConnection{Name: "conn " + string(tag), Protocol: "oidc", Profile: store.ProfileDevMock,
			Status: "active", Issuer: &iss, ClientID: &cid, CreatedAt: now, UpdatedAt: now}
		if err := c.InsertIdPConnection(r.conn); err != nil {
			return err
		}
		email := string(tag) + "@example.com"
		r.user = &store.PlatformUser{Email: &email, DisplayName: "user " + string(tag), CreatedAt: now}
		if err := c.InsertPlatformUser(r.user); err != nil {
			return err
		}
		r.login = &store.ExternalLogin{UserID: r.user.ID, IdPConnectionID: r.conn.ID, Issuer: iss, Subject: "sub-" + string(tag),
			CreatedAt: now}
		if err := c.InsertExternalLogin(r.login); err != nil {
			return err
		}
		r.role = &store.RoleAssignment{UserID: r.user.ID, Role: store.RoleTenantAdmin, Source: store.RoleSourceBootstrap, CreatedAt: now}
		if err := c.InsertRoleAssignment(r.role); err != nil {
			return err
		}
		r.ctx = &store.AuthnContextRecord{UserID: r.user.ID, IdPConnectionID: &r.conn.ID, Protocol: "oidc", Purpose: "login",
			AAL: 2, PhishingResistant: true, PhrBasis: "acr", TesseraACR: "urn:tessera:acr:phr", AuthTime: now,
			MappingProfile: "dev_mock", MappingVersion: 1, ClaimsSHA256: "x", CreatedAt: now}
		if err := c.InsertAuthnContext(r.ctx); err != nil {
			return err
		}
		r.hash = hexHash(tag)
		csrf := "csrf-" + string(tag)
		r.session = &store.Session{UserID: r.user.ID, Kind: store.SessionBrowser, SecretHash: &r.hash, CSRFSecret: &csrf,
			InitialAuthnContextID: r.ctx.ID, CurrentAuthnContextID: r.ctx.ID, CreatedAt: now, LastActivityAt: now,
			IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(24 * time.Hour)}
		if err := c.InsertSession(r.session); err != nil {
			return err
		}
		r.inv = &store.BootstrapInvitation{CodeHash: hexHash(tag + 2), IdPConnectionID: r.conn.ID, Email: email,
			CreatedBy: "op", CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour)}
		if err := c.InsertBootstrapInvitation(r.inv); err != nil {
			return err
		}
		r.txn = &store.LoginTransaction{CookieHash: hexHash(tag + 1), IdPConnectionID: r.conn.ID, Purpose: "bootstrap",
			BootstrapInvitationID: &r.inv.ID, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute)}
		return c.InsertLoginTransaction(r.txn)
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func authFixture(t *testing.T) (*storetest.Fixture, authRows, authRows) {
	t.Helper()
	f := storetest.TwoTenants(t)
	return f, seedAuthRows(t, f.DB, f.A.ID, 'a'), seedAuthRows(t, f.DB, f.B.ID, 'b')
}

// authMutations change one of A's rows; run in B they must fail (ErrNotFound
// or ErrSessionInactive) and leave A's row alone.
var authMutations = map[string]func(c *store.TenantTx, a authRows) error{
	"SetUserLastLogin":     func(c *store.TenantTx, a authRows) error { return c.SetUserLastLogin(a.user.ID, storetest.Now) },
	"DisableUser":          func(c *store.TenantTx, a authRows) error { return c.DisableUser(a.user.ID, "x", storetest.Now) },
	"DeleteRoleAssignment": func(c *store.TenantTx, a authRows) error { return c.DeleteRoleAssignment(a.role.ID) },
	"TouchSession": func(c *store.TenantTx, a authRows) error {
		return c.TouchSession(a.session.ID, storetest.Now, storetest.Now.Add(time.Hour))
	},
	"RotateSession": func(c *store.TenantTx, a authRows) error {
		return c.RotateSession(a.session.ID, hexHash('z'), "c", a.ctx.ID, storetest.Now, storetest.Now.Add(time.Hour))
	},
	"RevokeSession": func(c *store.TenantTx, a authRows) error { return c.RevokeSession(a.session.ID, "x", storetest.Now) },
	"ExpireSession": func(c *store.TenantTx, a authRows) error { return c.ExpireSession(a.session.ID) },
	"ConsumeLoginTransaction": func(c *store.TenantTx, a authRows) error {
		return c.ConsumeLoginTransaction(a.txn.ID, storetest.Now)
	},
	"ConsumeBootstrapInvitation": func(c *store.TenantTx, a authRows) error {
		return c.ConsumeBootstrapInvitation(a.inv.ID, a.user.ID, storetest.Now)
	},
}

func TestIsolation_AuthRows(t *testing.T) {
	f, a, b := authFixture(t)
	inB(t, f, func(c *store.TenantTx) error {
		conns, err := c.IdPConnections()
		if err != nil || len(conns) != 1 || conns[0].ID != b.conn.ID {
			t.Errorf("IdPConnections in B: %v %v", conns, err)
		}
		users, err := c.PlatformUsers()
		if err != nil || len(users) != 1 || users[0].ID != b.user.ID {
			t.Errorf("PlatformUsers in B: %v %v", users, err)
		}
		// another tenant's user is no one in B: never the same actor as B's user (#402)
		if same, err := c.SameActor(a.user.ID.String(), b.user.ID.String()); err != nil || same {
			t.Errorf("SameActor(A's user, B's user) in B = %v, %v", same, err)
		}
		if n, err := c.CountIdPConnectionsByProfile(store.ProfileDevMock); err != nil || n != 1 {
			t.Errorf("CountIdPConnectionsByProfile in B = %d %v, want 1", n, err)
		}
		for name, get := range map[string]func() error{
			"IdPConnection":       func() error { _, err := c.IdPConnection(a.conn.ID); return err },
			"PlatformUser":        func() error { _, err := c.PlatformUser(a.user.ID); return err },
			"AuthnContext":        func() error { _, err := c.AuthnContext(a.ctx.ID); return err },
			"Session":             func() error { _, err := c.Session(a.session.ID); return err },
			"LoginTransaction":    func() error { _, err := c.LoginTransaction(a.txn.ID); return err },
			"BootstrapInvitation": func() error { _, err := c.BootstrapInvitation(a.inv.ID); return err },
			"BootstrapInvitationByCodeHash": func() error {
				_, err := c.BootstrapInvitationByCodeHash(a.inv.CodeHash)
				return err
			},
			"ExternalLoginBySubject": func() error {
				_, err := c.ExternalLoginBySubject(a.conn.ID, a.login.Subject)
				return err
			},
		} {
			if err := get(); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("%s of A's row in B = %v, want ErrNotFound", name, err)
			}
		}
		for name, list := range map[string]func() (int, error){
			"SessionsForUser":       func() (int, error) { x, err := c.SessionsForUser(a.user.ID); return len(x), err },
			"RoleAssignments":       func() (int, error) { x, err := c.RoleAssignments(a.user.ID); return len(x), err },
			"ExternalLoginsForUser": func() (int, error) { x, err := c.ExternalLoginsForUser(a.user.ID); return len(x), err },
		} {
			if n, err := list(); err != nil || n != 0 {
				t.Errorf("%s(A's user) in B = %d %v, want none", name, n, err)
			}
		}
		if n, err := c.RevokeUserSessions(a.user.ID, "x", storetest.Now); err != nil || n != 0 {
			t.Errorf("RevokeUserSessions(A's user) in B revoked %d (%v)", n, err)
		}
		// own rows are visible
		if s, err := c.Session(b.session.ID); err != nil || s.TenantID != f.B.ID {
			t.Errorf("own session: %v", err)
		}
		return nil
	})
	for name, fn := range authMutations {
		t.Run(name, func(t *testing.T) {
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return fn(c, a) })
			if !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrSessionInactive) {
				t.Errorf("%s(A's row) in B = %v, want not found", name, err)
			}
		})
	}
	// A's rows are untouched
	err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		u, err := c.PlatformUser(a.user.ID)
		if err != nil || u.Status != "active" || u.LastLoginAt != nil {
			t.Errorf("A's user changed: %+v %v", u, err)
		}
		s, err := c.Session(a.session.ID)
		if err != nil || s.Status != store.SessionActive || *s.SecretHash != a.hash {
			t.Errorf("A's session changed: %+v %v", s, err)
		}
		if rs, err := c.RoleAssignments(a.user.ID); err != nil || len(rs) != 1 {
			t.Errorf("A's role changed: %v %v", rs, err)
		}
		x, err := c.LoginTransaction(a.txn.ID)
		if err != nil || x.ConsumedAt != nil || x.BootstrapInvitationID == nil || *x.BootstrapInvitationID != a.inv.ID {
			t.Errorf("A's login transaction consumed or changed: %+v %v", x, err)
		}
		if inv, err := c.BootstrapInvitation(a.inv.ID); err != nil || inv.ConsumedAt != nil {
			t.Errorf("A's invitation consumed: %+v %v", inv, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestIsolation_AuthInsertsRefused: a row stamped with another tenant, or
// referencing another tenant's row, is refused.
func TestIsolation_AuthInsertsRefused(t *testing.T) {
	f, a, b := authFixture(t)
	now := storetest.Now
	inserts := map[string]func(c *store.TenantTx) error{
		"InsertIdPConnection": func(c *store.TenantTx) error {
			return c.InsertIdPConnection(&store.IdPConnection{TenantID: f.A.ID, Name: "x", Protocol: "oidc",
				Profile: store.ProfileOkta, CreatedAt: now, UpdatedAt: now})
		},
		"InsertPlatformUser": func(c *store.TenantTx) error {
			return c.InsertPlatformUser(&store.PlatformUser{TenantID: f.A.ID, DisplayName: "x", CreatedAt: now})
		},
		"InsertExternalLogin/stamped": func(c *store.TenantTx) error {
			return c.InsertExternalLogin(&store.ExternalLogin{TenantID: f.A.ID, UserID: b.user.ID, IdPConnectionID: b.conn.ID,
				Issuer: "x", Subject: "x", CreatedAt: now})
		},
		"InsertExternalLogin/references A's user": func(c *store.TenantTx) error {
			return c.InsertExternalLogin(&store.ExternalLogin{UserID: a.user.ID, IdPConnectionID: b.conn.ID, Issuer: "x",
				Subject: "x2", CreatedAt: now})
		},
		"InsertRoleAssignment/references A's user": func(c *store.TenantTx) error {
			return c.InsertRoleAssignment(&store.RoleAssignment{UserID: a.user.ID, Role: store.RoleViewer,
				Source: store.RoleSourceManual, CreatedAt: now})
		},
		"InsertRoleAssignment/stamped": func(c *store.TenantTx) error {
			return c.InsertRoleAssignment(&store.RoleAssignment{TenantID: f.A.ID, UserID: b.user.ID, Role: store.RoleViewer,
				Source: store.RoleSourceManual, CreatedAt: now})
		},
		"InsertAuthnContext/references A's user": func(c *store.TenantTx) error {
			return c.InsertAuthnContext(&store.AuthnContextRecord{UserID: a.user.ID, Protocol: "oidc", Purpose: "login",
				AAL: 1, PhrBasis: "none", TesseraACR: "urn:tessera:acr:aal1", AuthTime: now, MappingProfile: "x",
				MappingVersion: 1, ClaimsSHA256: "x", CreatedAt: now})
		},
		"InsertSession/references A's context": func(c *store.TenantTx) error {
			h, csrf := hexHash('q'), "c"
			return c.InsertSession(&store.Session{UserID: b.user.ID, Kind: store.SessionBrowser, SecretHash: &h, CSRFSecret: &csrf,
				InitialAuthnContextID: a.ctx.ID, CurrentAuthnContextID: a.ctx.ID, CreatedAt: now, LastActivityAt: now,
				IdleExpiresAt: now, AbsoluteExpiresAt: now})
		},
		"InsertSession/stamped": func(c *store.TenantTx) error {
			h, csrf := hexHash('r'), "c"
			return c.InsertSession(&store.Session{TenantID: f.A.ID, UserID: b.user.ID, Kind: store.SessionBrowser, SecretHash: &h,
				CSRFSecret: &csrf, InitialAuthnContextID: b.ctx.ID, CurrentAuthnContextID: b.ctx.ID, CreatedAt: now,
				LastActivityAt: now, IdleExpiresAt: now, AbsoluteExpiresAt: now})
		},
		"InsertLoginTransaction/references A's connection": func(c *store.TenantTx) error {
			return c.InsertLoginTransaction(&store.LoginTransaction{CookieHash: hexHash('s'), IdPConnectionID: a.conn.ID,
				Purpose: "login", CreatedAt: now, ExpiresAt: now})
		},
		"InsertBootstrapInvitation/references A's connection": func(c *store.TenantTx) error {
			return c.InsertBootstrapInvitation(&store.BootstrapInvitation{CodeHash: hexHash('w'), IdPConnectionID: a.conn.ID,
				Email: "x@b.example", CreatedBy: "op", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
		},
		"InsertBootstrapInvitation/stamped": func(c *store.TenantTx) error {
			return c.InsertBootstrapInvitation(&store.BootstrapInvitation{TenantID: f.A.ID, CodeHash: hexHash('x'),
				IdPConnectionID: b.conn.ID, Email: "x@b.example", CreatedBy: "op", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
		},
		"InsertLoginTransaction/references A's invitation": func(c *store.TenantTx) error {
			return c.InsertLoginTransaction(&store.LoginTransaction{CookieHash: hexHash('y'), IdPConnectionID: b.conn.ID,
				Purpose: "bootstrap", BootstrapInvitationID: &a.inv.ID, CreatedAt: now, ExpiresAt: now})
		},
		"ConsumeBootstrapInvitation/by A's user": func(c *store.TenantTx) error {
			return c.ConsumeBootstrapInvitation(b.inv.ID, a.user.ID, now)
		},
		"SaveRequest/decided by A's user": func(c *store.TenantTx) error {
			r, err := c.Request(f.B.IDs["request:pending"])
			if err != nil {
				return err
			}
			id := a.user.ID
			r.DecidedByUserID = &id
			return c.SaveRequest(r)
		},
		"DecideItem/by A's user": func(c *store.TenantTx) error {
			_, err := c.DecideItem(f.B.IDs["item"], "keep", nil, now, store.UserRef{ID: a.user.ID, Display: "x"})
			return err
		},
		"MarkHrisEventExecuted/by A's user": func(c *store.TenantTx) error {
			return c.MarkHrisEventExecuted(f.B.IDs["hris:leaver"], now, store.UserRef{ID: a.user.ID})
		},
	}
	for name, fn := range inserts {
		t.Run(name, func(t *testing.T) {
			err := f.DB.InTenant(context.Background(), f.B.ID, fn)
			if !errors.Is(err, store.ErrCrossTenant) {
				t.Errorf("%s in B = %v, want ErrCrossTenant", name, err)
			}
		})
	}
}

// TestAuthSchemaRules: the schema's backstops for E1 (no admin role from an
// IdP group; admin roles only by bootstrap or change request) and session
// hash uniqueness.
func TestAuthSchemaRules(t *testing.T) {
	f, _, b := authFixture(t)
	now := storetest.Now
	for name, fn := range map[string]func(c *store.TenantTx) error{
		"admin role from an IdP group": func(c *store.TenantTx) error {
			return c.InsertRoleAssignment(&store.RoleAssignment{UserID: b.user.ID, Role: store.RolePolicyAdmin,
				Source: store.RoleSourceIdPGroup, CreatedAt: now})
		},
		"admin role without a change request": func(c *store.TenantTx) error {
			return c.InsertRoleAssignment(&store.RoleAssignment{UserID: b.user.ID, Role: store.RolePolicyAdmin,
				Source: store.RoleSourceManual, CreatedAt: now})
		},
		"phishing resistance without a basis": func(c *store.TenantTx) error {
			return c.InsertAuthnContext(&store.AuthnContextRecord{UserID: b.user.ID, Protocol: "oidc", Purpose: "login",
				AAL: 2, PhishingResistant: true, PhrBasis: "none", TesseraACR: "urn:tessera:acr:phr", AuthTime: now,
				MappingProfile: "x", MappingVersion: 1, ClaimsSHA256: "x", CreatedAt: now})
		},
		"break-glass enrolment without a change request": func(c *store.TenantTx) error {
			return c.InsertRoleAssignment(&store.RoleAssignment{UserID: b.user.ID, Role: store.RoleBreakGlass,
				Source: store.RoleSourceManual, CreatedAt: now})
		},
		"break-glass role from the break-glass source without a change request": func(c *store.TenantTx) error {
			return c.InsertRoleAssignment(&store.RoleAssignment{UserID: b.user.ID, Role: store.RoleBreakGlass,
				Source: store.RoleSourceBreakGlass, CreatedAt: now})
		},
		"a login transaction returning off-site with a backslash": func(c *store.TenantTx) error {
			return c.InsertLoginTransaction(&store.LoginTransaction{CookieHash: hexHash('u'), IdPConnectionID: b.conn.ID,
				Purpose: "login", ReturnTo: "/\\evil.example/", CreatedAt: now, ExpiresAt: now})
		},
		"a login transaction returning to a path with a control character": func(c *store.TenantTx) error {
			return c.InsertLoginTransaction(&store.LoginTransaction{CookieHash: hexHash('v'), IdPConnectionID: b.conn.ID,
				Purpose: "login", ReturnTo: "/\t/evil.example/", CreatedAt: now, ExpiresAt: now})
		},
		"a login transaction returning off-site": func(c *store.TenantTx) error {
			return c.InsertLoginTransaction(&store.LoginTransaction{CookieHash: hexHash('t'), IdPConnectionID: b.conn.ID,
				Purpose: "login", ReturnTo: "//evil.example/", CreatedAt: now, ExpiresAt: now})
		},
	} {
		if err := f.DB.InTenant(context.Background(), f.B.ID, fn); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// a session hash is unique across tenants
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		h, csrf := hexHash('a'), "c" // tenant A's session hash
		return c.InsertSession(&store.Session{UserID: b.user.ID, Kind: store.SessionBrowser, SecretHash: &h, CSRFSecret: &csrf,
			InitialAuthnContextID: b.ctx.ID, CurrentAuthnContextID: b.ctx.ID, CreatedAt: now, LastActivityAt: now,
			IdleExpiresAt: now, AbsoluteExpiresAt: now})
	})
	if !errors.Is(err, store.ErrDuplicate) {
		t.Errorf("duplicate session hash: %v, want ErrDuplicate", err)
	}
	// a login transaction is consumed once, and not after it expires
	if err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		if err := c.ConsumeLoginTransaction(b.txn.ID, now); err != nil {
			return err
		}
		if err := c.ConsumeLoginTransaction(b.txn.ID, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("second consume: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestHashLookups: the two §14.2 lookups resolve a hash to (tenant, id) and
// nothing else, and an unknown or malformed hash is not found.
func TestHashLookups(t *testing.T) {
	f, a, b := authFixture(t)
	err := f.DB.ReadSystem(context.Background(), "test", func(s *store.SystemTx) error {
		for _, r := range []struct {
			rows   authRows
			tenant tenancy.ID
		}{{a, f.A.ID}, {b, f.B.ID}} {
			tid, sid, err := s.LookupSessionBySecretHash(r.rows.hash)
			if err != nil || tid != r.tenant || sid != r.rows.session.ID {
				t.Errorf("session lookup: %s %s %v", tid, sid, err)
			}
			tid, xid, err := s.LookupLoginTxnByCookieHash(r.rows.txn.CookieHash)
			if err != nil || tid != r.tenant || xid != r.rows.txn.ID {
				t.Errorf("login txn lookup: %s %s %v", tid, xid, err)
			}
		}
		for _, h := range []string{hexHash('9'), "", "short", a.hash + "0"} {
			if _, id, err := s.LookupSessionBySecretHash(h); !errors.Is(err, store.ErrNotFound) || id != uuid.Nil {
				t.Errorf("lookup %q: %v", h, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func authCovered() map[string]bool {
	out := map[string]bool{}
	for k := range authMutations {
		out[k] = true
	}
	for _, k := range []string{"SameActor", "IdPConnections", "PlatformUsers", "CountIdPConnectionsByProfile", "IdPConnection",
		"PlatformUser", "AuthnContext", "Session", "LoginTransaction", "ExternalLoginBySubject", "SessionsForUser",
		"RoleAssignments", "ExternalLoginsForUser", "RevokeUserSessions", "InsertIdPConnection", "InsertPlatformUser",
		"InsertExternalLogin", "InsertRoleAssignment", "InsertAuthnContext", "InsertSession", "InsertLoginTransaction",
		"BootstrapInvitation", "BootstrapInvitationByCodeHash", "InsertBootstrapInvitation"} {
		out[k] = true // TestIsolation_AuthRows, TestIsolation_AuthInsertsRefused
	}
	out["InvalidateCredentials"] = true // TestIsolation_InvalidateCredentials
	return out
}

// TestIsolation_InvalidateCredentials: the restore hook in tenant B revokes
// B's sessions, login transactions, unconsumed invitations and access-token
// keys, and changes nothing of A's.
func TestIsolation_InvalidateCredentials(t *testing.T) {
	f, a, b := authFixture(t)
	seedKeys(t, f)
	at := storetest.Now.Add(time.Hour)
	inB(t, f, func(c *store.TenantTx) error {
		n, err := c.InvalidateCredentials("restore", at)
		if err != nil {
			t.Fatal(err)
		}
		if want := (store.CredentialsInvalidated{Sessions: 1, LoginTransactions: 1, Invitations: 1, SigningKeys: 2}); n != want {
			t.Errorf("B counts %+v, want %+v", n, want)
		}
		if s, err := c.Session(b.session.ID); err != nil || s.Status != "revoked" || s.RevokedReason == nil || *s.RevokedReason != "restore" {
			t.Errorf("B session after: %+v %v", s, err)
		}
		if _, err := c.LoginTransaction(b.txn.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B login transaction after: %v", err)
		}
		if _, err := c.BootstrapInvitation(b.inv.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B invitation after: %v", err)
		}
		return nil
	})
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		if s, err := c.Session(a.session.ID); err != nil || s.Status != "active" || s.RevokedReason != nil {
			t.Errorf("A session touched: %+v %v", s, err)
		}
		if _, err := c.LoginTransaction(a.txn.ID); err != nil {
			t.Errorf("A login transaction touched: %v", err)
		}
		if inv, err := c.BootstrapInvitation(a.inv.ID); err != nil || inv.ConsumedAt != nil {
			t.Errorf("A invitation touched: %+v %v", inv, err)
		}
		ks, err := c.SigningKeys(store.KeyPurposeAccessToken)
		if err != nil || len(ks) != 2 {
			t.Fatalf("A keys: %v %v", ks, err)
		}
		for _, k := range ks {
			if k.Status == store.KeyRevoked {
				t.Errorf("A key %s revoked by B's call", k.KID)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestBootstrapInvitationSingleUse: an invitation is consumed once, never
// after it expires, and the code is stored only as its hash.
func TestBootstrapInvitationSingleUse(t *testing.T) {
	f, a, _ := authFixture(t)
	now := storetest.Now
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		if err := c.ConsumeBootstrapInvitation(a.inv.ID, a.user.ID, now.Add(25*time.Hour)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("consume after expiry: %v", err)
		}
		if err := c.ConsumeBootstrapInvitation(a.inv.ID, a.user.ID, now); err != nil {
			t.Fatal(err)
		}
		if err := c.ConsumeBootstrapInvitation(a.inv.ID, a.user.ID, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("second consume: %v", err)
		}
		got, err := c.BootstrapInvitationByCodeHash(a.inv.CodeHash)
		if err != nil || got.ConsumedAt == nil || got.ConsumedByUserID == nil || *got.ConsumedByUserID != a.user.ID {
			t.Errorf("after consume: %+v %v", got, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
