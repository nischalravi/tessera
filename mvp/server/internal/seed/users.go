package seed

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// User is a bootstrap platform user of a demo tenant. They mirror the dev
// IdP's users.yaml (internal/devidp; TestSeedUsersMatchDevIdP keeps the two
// in step): the same subjects, so a sign-in through the dev IdP (PR6) or the
// dev sign-in shim (PR5) resolves to them through the (connection, subject)
// link, never by email.
type User struct {
	Subject string
	Email   string
	Name    string
	Roles   []string
	// Identity is the external id of the person the user is in the demo
	// directory (empty: none), so "request access for me" has a beneficiary.
	Identity string
}

// Bootstrap users of the demo tenants (design §18.5): Alice and Ivan are
// tenant admins, Pat a policy admin, Olu an operator, Vic a viewer; Gina is
// Globex's admin. Admin roles are granted with source "bootstrap", the only
// way an admin role exists without a two-person change request.
var (
	LarkspurUsers = []User{
		{"00u-alice-admin", "alice.admin@larkspur.example", "Alice (tenant admin)", []string{store.RoleTenantAdmin}, ""},
		{"00u-ivan-admin2", "ivan.admin@larkspur.example", "Ivan (2nd admin)", []string{store.RoleTenantAdmin}, ""},
		// Pat signs in as Anders Zeller, Hana's (Vic's) manager, so Vic's requests reach Pat first (#165)
		{"00u-pat-policy", "pat.policy@larkspur.example", "Pat (policy admin)", []string{store.RolePolicyAdmin}, "emp-1011"},
		// Olu and Vic sign in as two of the demo employees (issue #164)
		{"00u-olu-operator", "olu@larkspur.example", "Olu (operator)", []string{store.RoleOperator}, "emp-1006"},
		{"00u-vic-viewer", "vic@larkspur.example", "Vic (viewer)", []string{store.RoleViewer}, "emp-1012"},
	}
	GlobexUsers = []User{
		{"00u-gina-globex", "gina@globex.example", "Gina (Globex admin)", []string{store.RoleTenantAdmin}, ""},
	}
)

// DevClientID is the dev IdP's registered client (internal/devidp).
const DevClientID = "tessera-dev"

// WithDevIdP returns tenants with a dev_mock OIDC connection to the dev IdP
// at issuer and their bootstrap users (dev and test only: cmd/tessera never
// calls it with TESSERA_ENV=prod, and prod refuses to start with a dev_mock
// connection, §18.4).
func WithDevIdP(tenants []Tenant, issuer string) []Tenant {
	out := make([]Tenant, len(tenants))
	for i, t := range tenants {
		t.DevIdP = issuer
		switch t.ID {
		case LarkspurID:
			t.Users = LarkspurUsers
		case GlobexID:
			t.Users = GlobexUsers
		}
		out[i] = t
	}
	return out
}

// DevIdPClient is the dev IdP connection's client secret, sealed into
// client_secret_enc (dev and test only).
type DevIdPClient struct {
	Sealer *seal.Sealer
	Secret string
}

// WithDevIdPClient is WithDevIdP with the client secret the dev IdP expects,
// so browser sign-in through it (PR6) works.
func WithDevIdPClient(tenants []Tenant, issuer string, client DevIdPClient) []Tenant {
	out := WithDevIdP(tenants, issuer)
	for i := range out {
		c := client
		out[i].DevIdPClient = &c
	}
	return out
}

// seedAuth creates the tenant's dev_mock connection and bootstrap users.
// It writes no audit event, so the ledger of a fresh seed is unchanged.
func seedAuth(c *store.TenantTx, t Tenant, now time.Time) error {
	if t.DevIdP == "" || len(t.Users) == 0 {
		return nil
	}
	issuer, clientID, method := t.DevIdP, DevClientID, "client_secret_basic"
	domains, err := json.Marshal([]string{t.Slug + ".example"})
	if err != nil {
		return err
	}
	conn := &store.IdPConnection{ID: uuid.New(), Name: "Dev IdP (OIDC)", Protocol: "oidc", Profile: store.ProfileDevMock,
		Status: "active", IsDefault: true, VerifiedDomains: domains, Issuer: &issuer, ClientID: &clientID,
		ClientAuthMethod: &method, PinCerts: true, JITProvisioning: false, DefaultRole: store.RoleViewer,
		CreatedAt: now, UpdatedAt: now}
	if dc := t.DevIdPClient; dc != nil && dc.Sealer != nil && dc.Secret != "" {
		if conn.ClientSecretEnc, err = dc.Sealer.Seal([]byte(dc.Secret), auth.ClientSecretAAD(c.Tenant(), conn.ID)); err != nil {
			return err
		}
	}
	if err := c.InsertIdPConnection(conn); err != nil {
		return fmt.Errorf("seed: dev IdP connection: %w", err)
	}
	for _, u := range t.Users {
		email := u.Email
		pu := &store.PlatformUser{Email: &email, DisplayName: u.Name, CreatedAt: now}
		if u.Identity != "" { // absent from worlds other than the demo directory
			if i, err := c.IdentityByExternalID(u.Identity); err == nil {
				pu.IdentityID = &i.ID
			} else if !errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("seed: identity %s for %s: %w", u.Identity, u.Subject, err)
			}
		}
		if err := c.InsertPlatformUser(pu); err != nil {
			return err
		}
		if err := c.InsertExternalLogin(&store.ExternalLogin{UserID: pu.ID, IdPConnectionID: conn.ID, Issuer: issuer,
			Subject: u.Subject, CreatedAt: now}); err != nil {
			return err
		}
		for _, r := range u.Roles {
			if err := c.InsertRoleAssignment(&store.RoleAssignment{UserID: pu.ID, Role: r,
				Source: store.RoleSourceBootstrap, CreatedAt: now}); err != nil {
				return fmt.Errorf("seed: role %s for %s: %w", r, u.Subject, err)
			}
		}
	}
	return nil
}
