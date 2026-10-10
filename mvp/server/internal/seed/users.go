package seed

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/samlsp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
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
}

// Bootstrap users of the demo tenants (design §18.5): Alice and Ivan are
// tenant admins, Pat a policy admin, Olu an operator, Vic a viewer; Gina is
// Globex's admin. Admin roles are granted with source "bootstrap", the only
// way an admin role exists without a two-person change request.
var (
	LarkspurUsers = []User{
		{"00u-alice-admin", "alice.admin@larkspur.example", "Alice (tenant admin)", []string{store.RoleTenantAdmin}},
		{"00u-ivan-admin2", "ivan.admin@larkspur.example", "Ivan (2nd admin)", []string{store.RoleTenantAdmin}},
		{"00u-pat-policy", "pat.policy@larkspur.example", "Pat (policy admin)", []string{store.RolePolicyAdmin}},
		{"00u-olu-operator", "olu@larkspur.example", "Olu (operator)", []string{store.RoleOperator}},
		{"00u-vic-viewer", "vic@larkspur.example", "Vic (viewer)", []string{store.RoleViewer}},
	}
	GlobexUsers = []User{
		{"00u-gina-globex", "gina@globex.example", "Gina (Globex admin)", []string{store.RoleTenantAdmin}},
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
// client_secret_enc (dev and test only). SAMLCert, when set, is the dev
// IdP's SAML signing certificate (PEM, tessera-devidp -print-saml-cert):
// a dev_mock SAML connection pinning it is seeded too, with an SP key
// sealed by Sealer.
type DevIdPClient struct {
	Sealer   *seal.Sealer
	Secret   string
	SAMLCert string
}

// The dev IdP's SAML class refs (internal/devidp; seed must not import it).
const (
	devSAMLClassPhrh = "urn:devidp:ac:phrh"
	devSAMLClassPhr  = "urn:devidp:ac:phr"
	devSAMLClassMFA  = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract"
)

// devSAMLConnection is the dev_mock SAML connection to the dev IdP at
// issuer: Tessera requests the dev IdP's phr/phrh/MFA class refs and trusts
// them only when requested (normalize rule 2). A phr request also accepts
// phrh (Comparison=exact admits any listed ref).
func devSAMLConnection(t tenancy.ID, issuer string, dc *DevIdPClient, domains json.RawMessage, now time.Time) (*store.IdPConnection, error) {
	entity, sso := issuer+"/saml/metadata", issuer+"/saml/sso"
	certs, err := json.Marshal([]string{dc.SAMLCert})
	if err != nil {
		return nil, err
	}
	stepUp, err := json.Marshal(map[string]any{
		string(auth.ACRPhrh): map[string][]string{"authn_context_class_refs": {devSAMLClassPhrh}},
		string(auth.ACRPhr):  map[string][]string{"authn_context_class_refs": {devSAMLClassPhr, devSAMLClassPhrh}},
		string(auth.ACRAAL2): map[string][]string{"authn_context_class_refs": {devSAMLClassMFA}}})
	if err != nil {
		return nil, err
	}
	mapping, err := json.Marshal(map[string]any{"dev_emulation": "saml",
		"phr_authn_context_class_refs":  []string{devSAMLClassPhr},
		"phrh_authn_context_class_refs": []string{devSAMLClassPhrh},
		"aal2_authn_context_class_refs": []string{devSAMLClassMFA, devSAMLClassPhr, devSAMLClassPhrh}})
	if err != nil {
		return nil, err
	}
	c := &store.IdPConnection{ID: uuid.New(), Name: "Dev IdP (SAML)", Protocol: "saml", Profile: store.ProfileDevMock,
		Status: "active", VerifiedDomains: domains, IdPEntityID: &entity, IdPSSOURL: &sso, IdPSigningCerts: certs,
		PinCerts: true, StepUpRequest: stepUp, AuthnMapping: mapping, JITProvisioning: false, DefaultRole: store.RoleViewer,
		CreatedAt: now, UpdatedAt: now}
	keyPEM, certPEM, err := samlsp.GenerateSPKey("Tessera SP "+c.ID.String(), now)
	if err != nil {
		return nil, err
	}
	if c.SPKeyEnc, err = dc.Sealer.Seal(keyPEM, auth.SPKeyAAD(t, c.ID)); err != nil {
		return nil, err
	}
	c.SPCertPEM = &certPEM
	return c, nil
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
	conns := []*store.IdPConnection{conn}
	if dc := t.DevIdPClient; dc != nil && dc.Sealer != nil && dc.SAMLCert != "" {
		sc, err := devSAMLConnection(c.Tenant(), issuer, dc, domains, now)
		if err != nil {
			return fmt.Errorf("seed: dev IdP SAML connection: %w", err)
		}
		if err := c.InsertIdPConnection(sc); err != nil {
			return fmt.Errorf("seed: dev IdP SAML connection: %w", err)
		}
		conns = append(conns, sc)
	}
	for _, u := range t.Users {
		email := u.Email
		pu := &store.PlatformUser{Email: &email, DisplayName: u.Name, CreatedAt: now}
		if err := c.InsertPlatformUser(pu); err != nil {
			return err
		}
		for _, cn := range conns {
			iss := issuer
			if cn.Protocol == "saml" {
				iss = *cn.IdPEntityID
			}
			if err := c.InsertExternalLogin(&store.ExternalLogin{UserID: pu.ID, IdPConnectionID: cn.ID, Issuer: iss,
				Subject: u.Subject, CreatedAt: now}); err != nil {
				return err
			}
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
