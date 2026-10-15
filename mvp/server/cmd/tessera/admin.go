package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/mail"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.yaml.in/yaml/v3"

	"github.com/nischalravi/tessera/mvp/server/internal/api"
	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	authnorm "github.com/nischalravi/tessera/mvp/server/internal/auth/normalize"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/oauth2rp"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/samlsp"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Operator bootstrap (design §15.3, §18.2):
//
//	tessera admin create-tenant -slug acme -name "Acme Corp"
//	tessera admin add-idp       -tenant acme -file okta.yaml [-client-secret-file path]
//	tessera admin invite-admin  -tenant acme -connection <id> -email jane@acme.com [-ttl 24h]
//
// Every command runs as the operator (the OS user) and is audited in the
// tenant's chain. invite-admin prints a one-time URL; only its hash is kept.
const adminUsage = `usage:
  tessera admin create-tenant -slug slug -name "Display name" [-db path]
  tessera admin add-idp       -tenant slug -file connection.yaml [-client-secret-file path] [-db path]
  tessera admin invite-admin  -tenant slug -connection id -email address [-ttl 24h] [-db path]`

// maxInviteTTL is the longest a bootstrap invitation may live (§15.3).
const maxInviteTTL = 24 * time.Hour

type adminEnv struct {
	ctx    context.Context
	db     *store.DB
	cfg    *config.Config
	sealer *seal.Sealer
	now    time.Time
	stdout io.Writer
}

func adminCmd(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New(adminUsage)
	}
	sub, args := args[0], args[1:]
	fset := flag.NewFlagSet("tessera admin "+sub, flag.ContinueOnError)
	fset.SetOutput(stderr)
	dbFlag := fset.String("db", dbPath(os.Getenv("TESSERA_DB")), "SQLite database path")
	var run func(e *adminEnv) error
	switch sub {
	case "create-tenant":
		slug := fset.String("slug", "", "tenant slug (^[a-z0-9][a-z0-9-]{2,39}$)")
		name := fset.String("name", "", "display name")
		run = func(e *adminEnv) error { return createTenant(e, *slug, *name) }
	case "add-idp":
		tenant := fset.String("tenant", "", "tenant slug")
		file := fset.String("file", "", "connection YAML (§18.2)")
		secretFile := fset.String("client-secret-file", "", "file holding the client secret (client_secret_basic)")
		run = func(e *adminEnv) error { return addIdP(e, *tenant, *file, *secretFile) }
	case "invite-admin":
		tenant := fset.String("tenant", "", "tenant slug")
		conn := fset.String("connection", "", "IdP connection id the admin signs in through")
		email := fset.String("email", "", "the invited admin's email at that IdP")
		ttl := fset.Duration("ttl", maxInviteTTL, "how long the invitation is valid (at most 24h)")
		run = func(e *adminEnv) error { return inviteAdmin(e, *tenant, *conn, *email, *ttl) }
	default:
		return fmt.Errorf("unknown admin command %q\n%s", sub, adminUsage)
	}
	if err := fset.Parse(args); err != nil {
		return err
	}
	if os.Getenv("TESSERA_ENV") == "" {
		return errors.New("set TESSERA_ENV=dev, test or prod")
	}
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	sealer, err := cfg.Sealer(config.DevKEKPath(*dbFlag))
	if err != nil {
		return err
	}
	db, err := store.Open(ctx, *dbFlag)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx = audit.WithOperatorActor(ctx, operatorName())
	return run(&adminEnv{ctx: ctx, db: db, cfg: cfg, sealer: sealer, now: cfg.Clock()().UTC(), stdout: stdout})
}

func createTenant(e *adminEnv, slug, name string) error {
	if !store.ValidSlug(slug) || slug == store.PlatformSlug {
		return fmt.Errorf("create-tenant: -slug %q must match ^[a-z0-9][a-z0-9-]{2,39}$", slug)
	}
	if strings.TrimSpace(name) == "" || len(name) > 200 {
		return errors.New("create-tenant: -name is required (at most 200 characters)")
	}
	var t store.Tenant
	if err := e.db.InSystem(e.ctx, "admin create-tenant "+slug, func(s *store.SystemTx) error {
		var err error
		t, err = s.CreateTenant(store.Tenant{Slug: slug, Name: strings.TrimSpace(name), CreatedAt: e.now})
		return err
	}); err != nil {
		return fmt.Errorf("create-tenant: %w", err)
	}
	if err := e.db.InTenant(e.ctx, t.ID, func(tx *store.TenantTx) error {
		_, err := audit.Record(e.ctx, tx, "tenant.created", ojson.Object{{Key: "slug", Value: t.Slug}, {Key: "name", Value: t.Name}},
			audit.At(e.now), audit.Target("tenant", t.ID.String()))
		return err
	}); err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "created tenant %s (%s)\nnext: tessera admin add-idp -tenant %s -file <connection.yaml>\n", t.Slug, t.ID, t.Slug)
	return nil
}

// idpFile is a connection file (§18.2). Unknown keys are refused, so a typo
// cannot silently weaken a setting. Secrets never live in it.
type idpFile struct {
	Name             string            `yaml:"name"`
	Protocol         string            `yaml:"protocol"`
	Profile          string            `yaml:"profile"`
	Issuer           string            `yaml:"issuer"`
	ClientID         string            `yaml:"client_id"`
	ClientAuthMethod string            `yaml:"client_auth_method"`
	Scopes           []string          `yaml:"scopes"`
	IDTokenAlgs      []string          `yaml:"id_token_algs"`
	VerifiedDomains  []string          `yaml:"verified_domains"`
	GroupsClaim      string            `yaml:"groups_claim"`
	GroupRoleMapping map[string]string `yaml:"group_role_mapping"`
	JITProvisioning  *bool             `yaml:"jit_provisioning"`
	DefaultRole      string            `yaml:"default_role"`
	Default          bool              `yaml:"default"`
	EntraTenantID    string            `yaml:"entra_tenant_id"`
	StepUpRequest    map[string]any    `yaml:"step_up_request"`
	AuthnMapping     map[string]any    `yaml:"authn_mapping"`
	// SAML (protocol: saml)
	IdPEntityID     string            `yaml:"idp_entity_id"`
	IdPSSOURL       string            `yaml:"idp_sso_url"`
	IdPSigningCerts []string          `yaml:"idp_signing_certs"` // PEM or base64 DER; pinned
	SubjectSource   string            `yaml:"subject_source"`    // nameid_persistent (default) | attribute:<name>
	AttributeMap    map[string]string `yaml:"attribute_map"`     // email, name, groups -> attribute names
	AssumePhr       bool              `yaml:"assume_phishing_resistant"`
	// OAuth 2.0-only providers (protocol: oauth2)
	AuthorizationEndpoint string `yaml:"authorization_endpoint"`
	TokenEndpoint         string `yaml:"token_endpoint"`
	UserinfoEndpoint      string `yaml:"userinfo_endpoint"`
	SubjectField          string `yaml:"subject_field"` // the user object's immutable id field ("id" for github)
}

func readIdPFile(path string) (*idpFile, error) {
	b, err := os.ReadFile(path) // #nosec G304 G703 -- a path the operator passes to their own CLI
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var f idpFile
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &f, nil
}

// validate checks a connection file and returns the store row it describes.
func (f *idpFile) connection(prod bool, now time.Time) (*store.IdPConnection, error) {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if strings.TrimSpace(f.Name) == "" {
		bad("name is required")
	}
	switch f.Protocol {
	case "oidc", "saml", "oauth2":
	default:
		bad("protocol %q: want oidc, saml or oauth2", f.Protocol)
	}
	switch {
	case f.Profile == store.ProfileDevMock:
		if prod {
			bad("profile dev_mock is refused with TESSERA_ENV=prod")
		}
	case f.Protocol == "saml" && f.Profile != store.ProfileGenericSAML:
		bad("profile %q: SAML connections use generic_saml", f.Profile)
	case f.Protocol == "oauth2" && f.Profile != store.ProfileGitHub && f.Profile != store.ProfileGenericOAuth2:
		bad("profile %q: OAuth 2.0 connections use github or generic_oauth2", f.Profile)
	case f.Protocol == "oidc" && !slices.Contains([]string{store.ProfileOkta, store.ProfileEntra, store.ProfileGoogle,
		store.ProfileGenericOIDC}, f.Profile):
		bad("profile %q: want okta, entra, google or generic_oidc", f.Profile)
	}
	if f.AssumePhr {
		bad("assume_phishing_resistant needs a two-person admin change (design §15.2); it cannot be set here")
	}
	switch f.Protocol {
	case "saml":
		f.checkSAML(prod, bad)
	case "oauth2":
		f.checkOAuth2(prod, bad)
	default:
		f.checkOIDC(prod, bad)
	}
	if f.DefaultRole == "" {
		f.DefaultRole = store.RoleViewer
	}
	if !slices.Contains([]string{store.RoleViewer, store.RoleOperator, store.RoleAuditor}, f.DefaultRole) {
		bad("default_role %q: want viewer, operator or auditor", f.DefaultRole)
	}
	for g, r := range f.GroupRoleMapping {
		if !slices.Contains([]string{store.RoleViewer, store.RoleOperator, store.RoleAuditor}, r) {
			bad("group_role_mapping[%q] = %q: groups grant viewer, operator or auditor only (never admin roles)", g, r)
		}
	}
	for _, a := range f.IDTokenAlgs {
		if !slices.Contains([]string{"RS256", "PS256", "ES256", "EdDSA"}, a) {
			bad("id_token_algs: %q is not allowed", a)
		}
	}
	mapping := f.AuthnMapping
	if f.EntraTenantID != "" {
		if mapping == nil {
			mapping = map[string]any{}
		}
		mapping["entra_tenant_id"] = f.EntraTenantID
	}
	enc := func(v any, def string) json.RawMessage {
		if v == nil || (fmt.Sprint(v) == "map[]") {
			return json.RawMessage(def)
		}
		b, err := json.Marshal(v)
		if err != nil {
			bad("%v", err)
		}
		return b
	}
	authnMapping := enc(mapping, "{}")
	if _, err := authnorm.ParseMapping(authnMapping); err != nil {
		bad("authn_mapping: %v", err)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	jit := false
	if f.JITProvisioning != nil {
		jit = *f.JITProvisioning
	}
	c := &store.IdPConnection{ID: uuid.New(), Name: strings.TrimSpace(f.Name), Protocol: f.Protocol, Profile: f.Profile,
		Status: "active", IsDefault: f.Default, VerifiedDomains: enc(f.VerifiedDomains, "[]"), StepUpRequest: enc(f.StepUpRequest, "{}"),
		AuthnMapping: authnMapping, GroupRoleMapping: enc(f.GroupRoleMapping, "{}"), JITProvisioning: jit,
		DefaultRole: f.DefaultRole, PinCerts: true, CreatedAt: now, UpdatedAt: now}
	switch f.Protocol {
	case "saml":
		entity, sso := f.IdPEntityID, f.IdPSSOURL
		c.IdPEntityID, c.IdPSSOURL, c.IdPSigningCerts = &entity, &sso, enc(f.IdPSigningCerts, "[]")
		c.SubjectSource, c.AttributeMap = f.SubjectSource, enc(f.AttributeMap, "{}")
	case "oauth2":
		oc := oauth2rp.Connection{Profile: f.Profile, AuthorizationURL: f.AuthorizationEndpoint, TokenURL: f.TokenEndpoint,
			UserinfoURL: f.UserinfoEndpoint, SubjectField: f.SubjectField, Scopes: f.Scopes}.Defaults()
		clientID := f.ClientID
		c.ClientID, c.SubjectSource = &clientID, "field:"+oc.SubjectField
		c.AuthorizationEndpoint, c.TokenEndpoint, c.UserinfoEndpoint = &oc.AuthorizationURL, &oc.TokenURL, &oc.UserinfoURL
		if len(f.Scopes) == 0 && f.Profile == store.ProfileGitHub {
			f.Scopes = []string{"read:user", "user:email"}
		}
		if len(f.Scopes) == 0 {
			c.Scopes = json.RawMessage("[]")
		}
	default:
		issuer, clientID, method := f.Issuer, f.ClientID, f.ClientAuthMethod
		c.Issuer, c.ClientID, c.ClientAuthMethod = &issuer, &clientID, &method
	}
	if len(f.Scopes) > 0 {
		c.Scopes = enc(f.Scopes, "[]")
	}
	if len(f.IDTokenAlgs) > 0 {
		c.IDTokenAlgs = enc(f.IDTokenAlgs, "[]")
	}
	if f.GroupsClaim != "" {
		g := f.GroupsClaim
		c.GroupsClaim = &g
	}
	return c, nil
}

// checkOIDC validates the OIDC fields.
func (f *idpFile) checkOIDC(prod bool, bad func(string, ...any)) {
	iss, err := url.Parse(f.Issuer)
	switch {
	case f.Issuer == "" || err != nil || iss.Host == "":
		bad("issuer must be an absolute URL")
	case prod && iss.Scheme != "https":
		bad("issuer must be https with TESSERA_ENV=prod")
	case strings.HasSuffix(f.Issuer, "/") || iss.RawQuery != "" || iss.Fragment != "":
		bad("issuer %q must be exact: no trailing slash, query or fragment", f.Issuer)
	case f.Profile == store.ProfileEntra && strings.Contains(f.Issuer, "{tenantid}"):
		bad("issuer: Entra multi-tenant templates are not supported; configure the tenant-specific issuer")
	}
	if f.ClientID == "" {
		bad("client_id is required")
	}
	switch f.ClientAuthMethod {
	case "", "client_secret_basic":
		f.ClientAuthMethod = "client_secret_basic"
	case "private_key_jwt":
		bad("client_auth_method private_key_jwt is not supported yet; use client_secret_basic")
	default:
		bad("client_auth_method %q: want client_secret_basic", f.ClientAuthMethod)
	}
	if f.Profile == store.ProfileEntra && f.EntraTenantID == "" {
		bad("entra_tenant_id is required for the entra profile")
	}
}

// checkOAuth2 validates an OAuth 2.0-only connection: the github profile
// defaults its endpoints and subject field; generic_oauth2 needs all three
// endpoints (https in prod) and the immutable id field.
func (f *idpFile) checkOAuth2(prod bool, bad func(string, ...any)) {
	if f.ClientID == "" {
		bad("client_id is required")
	}
	if f.Issuer != "" || f.IdPEntityID != "" || f.SubjectSource != "" {
		bad("issuer, idp_entity_id and subject_source are not OAuth 2.0 settings (use subject_field)")
	}
	switch f.ClientAuthMethod {
	case "", "client_secret_basic":
	default:
		bad("client_auth_method %q: OAuth 2.0 connections use a client secret", f.ClientAuthMethod)
	}
	eps := map[string]string{"authorization_endpoint": f.AuthorizationEndpoint, "token_endpoint": f.TokenEndpoint,
		"userinfo_endpoint": f.UserinfoEndpoint}
	for name, v := range eps {
		if v == "" {
			if f.Profile != store.ProfileGitHub {
				bad("%s is required for generic_oauth2", name)
			}
			continue
		}
		u, err := url.Parse(v)
		switch {
		case err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http"):
			bad("%s must be an absolute URL", name)
		case prod && u.Scheme != "https":
			bad("%s must be https with TESSERA_ENV=prod", name)
		}
	}
	switch strings.ToLower(f.SubjectField) {
	case "":
		if f.Profile != store.ProfileGitHub {
			bad("subject_field is required for generic_oauth2: the user object's immutable id field")
		}
	case "email", "login", "username", "preferred_username", "name", "upn":
		bad("subject_field %q: users are keyed on an immutable id, never a name or email", f.SubjectField)
	}
}

// checkSAML validates the SAML fields: an exact entity ID, an SSO URL
// (https in prod) and at least one pinned signing certificate.
func (f *idpFile) checkSAML(prod bool, bad func(string, ...any)) {
	if f.IdPEntityID == "" {
		bad("idp_entity_id is required")
	}
	sso, err := url.Parse(f.IdPSSOURL)
	switch {
	case f.IdPSSOURL == "" || err != nil || sso.Host == "":
		bad("idp_sso_url must be an absolute URL")
	case prod && sso.Scheme != "https":
		bad("idp_sso_url must be https with TESSERA_ENV=prod")
	}
	if len(f.IdPSigningCerts) == 0 {
		bad("idp_signing_certs: pin at least one signing certificate")
	} else if _, err := samlsp.ParseCerts(f.IdPSigningCerts); err != nil {
		bad("idp_signing_certs: %v", err)
	}
	if f.SubjectSource != "" && f.SubjectSource != "nameid_persistent" &&
		(!strings.HasPrefix(f.SubjectSource, "attribute:") || len(f.SubjectSource) == len("attribute:")) {
		bad("subject_source %q: want nameid_persistent or attribute:<name> (never email)", f.SubjectSource)
	}
	for k := range f.AttributeMap {
		if !slices.Contains([]string{"email", "name", "groups"}, k) {
			bad("attribute_map: unknown key %q (want email, name, groups)", k)
		}
	}
	if f.ClientID != "" || f.Issuer != "" {
		bad("issuer and client_id are OIDC settings; a SAML connection uses idp_entity_id and idp_sso_url")
	}
}

func lookupTenant(e *adminEnv, slug string) (store.Tenant, error) {
	var t store.Tenant
	err := e.db.ReadSystem(e.ctx, "admin tenant", func(s *store.SystemTx) error {
		var err error
		t, err = s.TenantBySlug(slug)
		return err
	})
	if errors.Is(err, store.ErrNotFound) || (err == nil && t.ID == tenancy.Platform) {
		return t, fmt.Errorf("no tenant %q", slug)
	}
	return t, err
}

func addIdP(e *adminEnv, slug, file, secretFile string) error {
	if file == "" {
		return errors.New("add-idp: -file is required")
	}
	t, err := lookupTenant(e, slug)
	if err != nil {
		return err
	}
	f, err := readIdPFile(file)
	if err != nil {
		return err
	}
	c, err := f.connection(e.cfg.IsProd(), e.now)
	if err != nil {
		return fmt.Errorf("add-idp: %w", err)
	}
	if err := sealConnectionSecrets(e, t.ID, c, secretFile); err != nil {
		return err
	}
	if err := e.db.InTenant(e.ctx, t.ID, func(tx *store.TenantTx) error {
		if err := tx.InsertIdPConnection(c); err != nil {
			return err
		}
		_, err := audit.Record(e.ctx, tx, "idp.connection.created", ojson.Object{{Key: "connection_id", Value: c.ID.String()},
			{Key: "name", Value: c.Name}, {Key: "protocol", Value: c.Protocol}, {Key: "profile", Value: c.Profile},
			{Key: "issuer", Value: firstOf(c.Issuer, c.IdPEntityID, c.UserinfoEndpoint)},
			{Key: "jit_provisioning", Value: c.JITProvisioning}, {Key: "default_role", Value: c.DefaultRole}},
			audit.At(e.now), audit.Target("idp_connection", c.ID.String()))
		return err
	}); err != nil {
		return fmt.Errorf("add-idp: %w", err)
	}
	fmt.Fprintf(e.stdout, "added connection %s (%s) to %s\n", c.ID, c.Name, t.Slug)
	if c.Protocol == "saml" {
		fmt.Fprintf(e.stdout, "register at the IdP: SP entity ID (audience) and metadata %s\nACS URL (HTTP-POST) %s\n",
			api.SPEntityID(e.cfg.PublicURL, c.ID), api.ACSURL(e.cfg.PublicURL, c.ID))
		return nil
	}
	path := "oidc"
	if c.Protocol == "oauth2" {
		path = "oauth2"
	}
	fmt.Fprintf(e.stdout, "redirect URI to register at the IdP: %s/api/auth/%s/%s/callback\n",
		strings.TrimRight(e.cfg.PublicURL, "/"), path, c.ID)
	return nil
}

// sealConnectionSecrets seals an OIDC client secret (from secretFile), or
// generates and seals a SAML connection's SP signing key.
func sealConnectionSecrets(e *adminEnv, t tenancy.ID, c *store.IdPConnection, secretFile string) error {
	if c.Protocol == "saml" {
		keyPEM, certPEM, err := samlsp.GenerateSPKey("Tessera SP "+c.ID.String(), e.now)
		if err != nil {
			return err
		}
		if c.SPKeyEnc, err = e.sealer.Seal(keyPEM, auth.SPKeyAAD(t, c.ID)); err != nil {
			return err
		}
		c.SPCertPEM = &certPEM
		return nil
	}
	if secretFile == "" {
		return errors.New("add-idp: -client-secret-file is required for client_secret_basic")
	}
	secret, err := os.ReadFile(secretFile) // #nosec G304 G703 -- a path the operator passes to their own CLI
	if err != nil {
		return err
	}
	secret = bytes.TrimSpace(secret)
	if len(secret) == 0 {
		return errors.New("add-idp: the client secret file is empty")
	}
	c.ClientSecretEnc, err = e.sealer.Seal(secret, auth.ClientSecretAAD(t, c.ID))
	return err
}

// firstOf is the first non-nil value.
func firstOf(vs ...*string) string {
	for _, v := range vs {
		if v != nil {
			return *v
		}
	}
	return ""
}

func inviteAdmin(e *adminEnv, slug, connID, email string, ttl time.Duration) error {
	t, err := lookupTenant(e, slug)
	if err != nil {
		return err
	}
	id, err := uuid.Parse(connID)
	if err != nil {
		return fmt.Errorf("invite-admin: -connection %q is not a connection id", connID)
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email {
		return fmt.Errorf("invite-admin: -email %q is not an address", email)
	}
	if ttl <= 0 || ttl > maxInviteTTL {
		return fmt.Errorf("invite-admin: -ttl must be between 0 and %s", maxInviteTTL)
	}
	code := "tbi_" + seal.RandomSecret(32)
	inv := &store.BootstrapInvitation{CodeHash: seal.SHA256Hex([]byte(code)), IdPConnectionID: id, Email: email,
		CreatedBy: operatorName(), CreatedAt: e.now, ExpiresAt: e.now.Add(ttl)}
	if err := e.db.InTenant(e.ctx, t.ID, func(tx *store.TenantTx) error {
		c, err := tx.IdPConnection(id)
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("no connection %s in %s", id, slug)
		} else if err != nil {
			return err
		}
		if c.Status != "active" || (c.Protocol != "oidc" && c.Protocol != "saml") {
			return fmt.Errorf("connection %s is not an active OIDC or SAML connection", id)
		}
		if err := tx.InsertBootstrapInvitation(inv); err != nil {
			return err
		}
		_, err = audit.Record(e.ctx, tx, "recovery.invitation.created", ojson.Object{{Key: "invitation_id", Value: inv.ID.String()},
			{Key: "connection_id", Value: id.String()}, {Key: "email", Value: email},
			{Key: "expires_at", Value: inv.ExpiresAt.Format(time.RFC3339)}},
			audit.At(e.now), audit.Target("bootstrap_invitation", inv.ID.String()))
		return err
	}); err != nil {
		return fmt.Errorf("invite-admin: %w", err)
	}
	fmt.Fprintf(e.stdout, "one-time bootstrap URL for %s (valid until %s; send it out of band):\n%s/t/%s/bootstrap?code=%s\n",
		email, inv.ExpiresAt.Format(time.RFC3339), strings.TrimRight(e.cfg.PublicURL, "/"), t.Slug, url.QueryEscape(code))
	return nil
}
