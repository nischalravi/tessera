package seed_test

import (
	"context"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/devidp"
	"github.com/nischalravi/tessera/mvp/server/internal/devidp/devidptest"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/seed"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// TestSeedUsersMatchDevIdP keeps the bootstrap users in step with the dev
// IdP's users.yaml: same subjects, emails, tenants and roles.
func TestSeedUsersMatchDevIdP(t *testing.T) {
	idp, err := devidp.DefaultUsers()
	if err != nil {
		t.Fatal(err)
	}
	seeded := map[string]seed.User{}
	tenantOf := map[string]string{}
	for _, u := range seed.LarkspurUsers {
		seeded[u.Subject], tenantOf[u.Subject] = u, seed.LarkspurSlug
	}
	for _, u := range seed.GlobexUsers {
		seeded[u.Subject], tenantOf[u.Subject] = u, seed.GlobexSlug
	}
	if len(seeded) != len(idp) {
		t.Errorf("%d seeded users, %d dev IdP users", len(seeded), len(idp))
	}
	for _, u := range idp {
		s, ok := seeded[u.Sub]
		if !ok {
			t.Errorf("dev IdP user %s is not seeded", u.Sub)
			continue
		}
		if s.Email != u.Email || tenantOf[u.Sub] != u.Tenant || !slices.Equal(s.Roles, u.Roles) {
			t.Errorf("%s: seeded %+v (%s), dev IdP %+v", u.Sub, s, tenantOf[u.Sub], u)
		}
	}
}

// TestSeedDevIdPConnection: WithDevIdP seeds an active dev_mock connection
// and the bootstrap users with their (connection, subject) links and roles,
// and writes no audit event (a fresh ledger keeps its recorded ids).
func TestSeedDevIdPConnection(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)
	db, err := store.Open(ctx, store.TestTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tenants := seed.WithDevIdP([]seed.Tenant{seed.Globex(now)}, "http://127.0.0.1:8001")
	if _, err := seed.Run(ctx, db, now, nil, tenants); err != nil {
		t.Fatal(err)
	}
	err = db.ReadTenant(ctx, seed.GlobexID, func(tx *store.TenantTx) error {
		conns, err := tx.IdPConnections()
		if err != nil {
			return err
		}
		if len(conns) != 1 || conns[0].Profile != store.ProfileDevMock || conns[0].Status != "active" ||
			*conns[0].Issuer != "http://127.0.0.1:8001" {
			t.Errorf("connections %+v", conns)
		}
		l, err := tx.ExternalLoginBySubject(conns[0].ID, "00u-gina-globex")
		if err != nil {
			return err
		}
		roles, err := tx.RoleAssignments(l.UserID)
		if err != nil {
			return err
		}
		if len(roles) != 1 || roles[0].Role != store.RoleTenantAdmin || roles[0].Source != store.RoleSourceBootstrap {
			t.Errorf("roles %+v", roles)
		}
		log, err := tx.AuditLog(-1)
		for _, e := range log {
			if e.Action != "review.campaign_created" {
				t.Errorf("seeding the auth rows wrote %s", e.Action)
			}
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	// without WithDevIdP there is no connection and no user
	db2, err := store.Open(ctx, store.TestTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	if _, err := seed.Run(ctx, db2, now, nil, []seed.Tenant{{ID: seed.GlobexID, Slug: "globex", Name: "G",
		Connectors: []connectors.Connector{connectors.Tiny{Now: now}}}}); err != nil {
		t.Fatal(err)
	}
	if err := db2.ReadTenant(ctx, seed.GlobexID, func(tx *store.TenantTx) error {
		users, err := tx.PlatformUsers()
		if len(users) != 0 {
			t.Errorf("users seeded without a dev IdP: %d", len(users))
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// TestSeedDevIdPSAMLConnection: with the dev IdP's SAML certificate, a
// dev_mock SAML connection pinning it is seeded too, with a sealed SP key,
// and each bootstrap user is linked to both connections.
func TestSeedDevIdPSAMLConnection(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)
	db, err := store.Open(ctx, store.TestTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	idp := devidptest.Start(t, devidp.Config{})
	sealer, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	tenants := seed.WithDevIdPClient([]seed.Tenant{seed.Globex(now)}, idp.URL,
		seed.DevIdPClient{Sealer: sealer, Secret: "s", SAMLCert: idp.SAMLCertificatePEM()})
	if _, err := seed.Run(ctx, db, now, nil, tenants); err != nil {
		t.Fatal(err)
	}
	err = db.ReadTenant(ctx, seed.GlobexID, func(tx *store.TenantTx) error {
		conns, err := tx.IdPConnections()
		if err != nil {
			return err
		}
		var sc *store.IdPConnection
		for _, c := range conns {
			if c.Protocol == "saml" {
				sc = c
			}
		}
		if len(conns) != 2 || sc == nil || *sc.IdPEntityID != idp.SAMLEntityID() || *sc.IdPSSOURL != idp.SAMLSSOURL() ||
			sc.SPCertPEM == nil || sc.Status != "active" {
			t.Fatalf("connections %+v", conns)
		}
		if _, err := sealer.Open(sc.SPKeyEnc, auth.SPKeyAAD(seed.GlobexID, sc.ID)); err != nil {
			t.Errorf("SP key: %v", err)
		}
		_, err = tx.ExternalLoginBySubject(sc.ID, "00u-gina-globex")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestDevGitHubIDMatchesDevIdP: the seed links users to the ids the dev
// IdP's GitHub emulation reports.
func TestDevGitHubIDMatchesDevIdP(t *testing.T) {
	for _, u := range append(slices.Clone(seed.LarkspurUsers), seed.GlobexUsers...) {
		if got, want := seed.DevGitHubID(u.Subject), strconv.FormatInt(devidp.GitHubID(u.Subject), 10); got != want {
			t.Errorf("%s: %s, dev IdP %s", u.Subject, got, want)
		}
	}
}

// TestLarkspurHasTwoContainHolders: re-enabling an identity linked to a
// Tessera user needs a second holder of identities.contain (four eyes,
// #316), so the demo tenant must have at least two (#335).
func TestLarkspurHasTwoContainHolders(t *testing.T) {
	var holders []string
	for _, u := range seed.LarkspurUsers {
		for _, r := range u.Roles {
			if slices.Contains(auth.RolePermissions(auth.Role(r)), auth.PermIdentitiesContain) {
				holders = append(holders, u.Subject)
				break
			}
		}
	}
	if len(holders) < 2 {
		t.Errorf("larkspur users holding identities.contain: %v; four eyes on enable needs two", holders)
	}
}
