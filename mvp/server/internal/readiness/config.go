package readiness

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/ldap"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/restgen"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/sqldb"
	scimpreset "github.com/nischalravi/tessera/mvp/server/internal/provision/scim"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
)

// ConnConfig is the typed, secret-free configuration of a connection
// revision. Decoding is strict: an unknown field (for example "password") is
// rejected, so a credential can never be smuggled into config text.
type ConnConfig struct {
	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitempty"`
	// TLSMode is ldaps, starttls or none (dev only). Unset: ldaps for port
	// 636, starttls otherwise (TLSModeOf). The Required TLS check fails on none.
	TLSMode string `json:"tls_mode,omitempty"`
	// PageSize is the paged-search page of a sync, 1 to 10000 (unset: 500).
	PageSize int `json:"page_size,omitempty"`
	// AttrMap are extra LDAP attributes ingest stores on the account: each
	// maps an LDAP attribute to an account or identity attribute name.
	AttrMap []AttrMapping `json:"attr_map,omitempty"`
	// BindDN is the LDAP bind identity (not a secret; the password is the
	// sealed credential). CABundle is the PEM of the CA that signed the
	// directory's certificate (public); empty means the system roots.
	BindDN            string   `json:"bind_dn,omitempty"`
	CABundle          string   `json:"ca_bundle,omitempty"`
	BaseDNs           []string `json:"base_dns,omitempty"`
	UserFilter        string   `json:"user_filter,omitempty"`
	GroupFilter       string   `json:"group_filter,omitempty"`
	ServiceAccountOUs []string `json:"service_account_ous,omitempty"`
	OrgURL            string   `json:"org_url,omitempty"`
	TenantID          string   `json:"tenant_id,omitempty"`
	Cloud             string   `json:"cloud,omitempty"`
	Customer          string   `json:"customer,omitempty"`
	Domain            string   `json:"domain,omitempty"`
	BaseURL           string   `json:"base_url,omitempty"`
	// Rest is a generic REST connection's spec (internal/connectors/restgen). It holds no secret.
	Rest *restgen.Spec `json:"rest,omitempty"`
	// Preset is the id of the SCIM vendor preset (provision/scim) a scim_app
	// connection was created from; it selects the base URL check and quirks.
	Preset             string              `json:"preset,omitempty"`
	TenantHost         string              `json:"tenant_host,omitempty"`
	APIVersion         string              `json:"api_version,omitempty"`
	Interface          string              `json:"interface,omitempty"`
	TimeZone           string              `json:"time_zone,omitempty"`
	CorrelationKey     string              `json:"correlation_key,omitempty"`
	HRIDAttribute      string              `json:"hr_id_attribute,omitempty"`
	TechnicalOwner     string              `json:"technical_owner,omitempty"`
	BusinessOwner      string              `json:"business_owner,omitempty"`
	ExpectedCounts     *ExpectedCounts     `json:"expected_counts,omitempty"`
	StaleDays          int                 `json:"stale_days,omitempty"`
	SyncSchedule       string              `json:"sync_schedule,omitempty"`
	WriteMode          string              `json:"write_mode,omitempty"`
	WriteScope         []string            `json:"write_scope,omitempty"`
	Hybrid             bool                `json:"hybrid,omitempty"`
	UseDirSync         bool                `json:"use_dirsync,omitempty"`
	PrivilegedExpected map[string][]string `json:"privileged_expected,omitempty"`
	// SQL is the database connector's settings (template sql, issue #553). It holds no
	// secret: the password is the sealed credential.
	SQL *sqldb.Config `json:"sql,omitempty"`
	// DemoFixedChecks is the demo scenario toggle: simulated checks listed
	// here pass (for example after "fixing" ranged retrieval). Demo types only.
	DemoFixedChecks []string `json:"demo_fixed_checks,omitempty"`
	// Settings are the non-secret options of a governed connector type
	// (internal/connectors/governed: a vault user, an organization, paths).
	// The keys each type takes are closed; the secret is the sealed credential.
	Settings map[string]string `json:"settings,omitempty"`
}

// AttrMapping maps one LDAP attribute to a Tessera attribute. Scope is
// "account" or "identity": which of the two the value describes.
type AttrMapping struct {
	LDAP   string `json:"ldap"`
	Target string `json:"target"`
	Scope  string `json:"scope"`
}

// Bounds of the LDAP sync settings.
const (
	MaxPageSize = 10000
	MaxAttrMap  = 32
)

// TLSModeOf is the connection's TLS mode: the stored one, or ldaps for port 636
// and starttls for any other port, so a connection saved before tls_mode
// existed behaves as before.
func TLSModeOf(cfg ConnConfig) string { return safedial.InferMode(cfg.TLSMode, cfg.Port) }

// ExpectedCounts are the object counts the owner reads from the directory's own console.
type ExpectedCounts struct {
	Users  int `json:"users"`
	Groups int `json:"groups"`
}

// DecodeConfig strictly decodes a JSON config object.
func DecodeConfig(raw []byte) (ConnConfig, error) {
	var cfg ConnConfig
	if len(bytes.TrimSpace(raw)) == 0 {
		return cfg, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("config: %w", err)
	}
	if dec.More() {
		return cfg, fmt.Errorf("config: trailing data")
	}
	return cfg, nil
}

// MergeConfig applies a partial JSON object on top of cfg (JSON merge
// semantics: present keys replace, null clears). Unknown keys are rejected.
func MergeConfig(cfg ConnConfig, patch []byte) (ConnConfig, error) {
	cur, err := json.Marshal(cfg)
	if err != nil {
		return cfg, err
	}
	var base, p map[string]json.RawMessage
	if err := json.Unmarshal(cur, &base); err != nil {
		return cfg, err
	}
	dec := json.NewDecoder(bytes.NewReader(patch))
	if err := dec.Decode(&p); err != nil || p == nil {
		return cfg, fmt.Errorf("config: want a JSON object")
	}
	for k, v := range p {
		if string(v) == "null" {
			delete(base, k)
		} else {
			base[k] = v
		}
	}
	merged, err := json.Marshal(base)
	if err != nil {
		return cfg, err
	}
	return DecodeConfig(merged)
}

// FieldError is one invalid config field.
type FieldError struct {
	Field string `json:"field"`
	Msg   string `json:"msg"`
}

var (
	hostRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	guidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	// ibmiProfileRE is an IBM i user profile name (A-Z, 0-9, # $ @ _, at most 10, not starting with a digit or _; no period)
	ibmiProfileRE = regexp.MustCompile(`^[A-Za-z#$@][A-Za-z0-9#$@_]{0,9}$`)
	dnRE          = regexp.MustCompile(`(?i)^([a-z][a-z0-9-]*=[^,]+)(,\s*[a-z][a-z0-9-]*=[^,]+)*$`)
	attrRE        = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{0,63}$`)
	apiVersionRE  = regexp.MustCompile(`^v[0-9]{1,3}(\.[0-9]{1,2})?$`)
	printable     = regexp.MustCompile(`^[^\x00-\x1f\x7f]*$`)
	cloudNames    = []string{"global", "usgov", "china"}
	interfaces    = []string{"get_workers", "raas"}
	// governedTemplates are the templates of the connector types in internal/connectors/governed.
	governedTemplates = []string{"awsorg", "githubscan", "erp", "pam", "vms", "agentcore", "successfactors", "azurerbac", "gcpiam", "unixssh", "sftpdrop", "servicenow", "atlassian", "kubernetes", "vault", "mcp", "bedrock", "vertex", "foundry", "copilot", "agentforce"}
)

// Validate checks a config for a template. It returns every problem rather
// than the first, so the UI can mark each field.
func Validate(cfg ConnConfig, t *template.Resolved) []FieldError { return ValidateConn(cfg, t, "") }

// ValidateConn is ValidateConnEnv for production: tls_mode none is refused.
func ValidateConn(cfg ConnConfig, t *template.Resolved, connectorType string) []FieldError {
	return ValidateConnEnv(cfg, t, connectorType, config.Prod)
}

// ldapHost checks the host of a directory and says what is wrong with it.
func ldapHost(v string) string {
	switch {
	case v == "":
		return "required"
	case strings.Contains(v, "://"):
		return "a host name like ldap.example.com, without a scheme such as ldaps://"
	case strings.ContainsAny(v, " \t"):
		return "a host name like ldap.example.com, not the connection's name (no spaces)"
	case strings.Contains(v, "/"):
		return "a host name like ldap.example.com, without a path"
	}
	if _, err := netip.ParseAddr(v); err == nil || hostRE.MatchString(v) {
		return ""
	}
	if strings.Contains(v, ":") {
		return "a host name or IP address without a port; the port is its own field"
	}
	return "a host name like ldap.example.com or an IP address"
}

// ValidateConnEnv is Validate for a connector type: templates that cover several
// types (erp, pam, vms) check the settings of the type the connection has. env
// is the server environment; tls_mode none is accepted only in dev.
func ValidateConnEnv(cfg ConnConfig, t *template.Resolved, connectorType, env string) []FieldError {
	var errs []FieldError
	bad := func(field, format string, args ...any) {
		errs = append(errs, FieldError{field, fmt.Sprintf(format, args...)})
	}
	text := func(field, v string, max int) {
		if len(v) > max {
			bad(field, "longer than %d characters", max)
		}
		if !printable.MatchString(v) {
			bad(field, "contains control characters")
		}
	}
	host := func(field, v string) {
		if v == "" {
			bad(field, "required")
		} else if !hostRE.MatchString(v) {
			bad(field, "must be a host name without scheme, port or path")
		}
	}
	httpsURL := func(field, v string, allow []string) {
		if v == "" {
			bad(field, "required")
			return
		}
		u, err := url.Parse(v)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Port() != "" || (u.Path != "" && u.Path != "/" && field != "base_url") {
			bad(field, "must be an https URL with no credentials or port")
			return
		}
		if len(allow) > 0 && !HostAllowed(u.Hostname(), allow) {
			bad(field, "host %s is not on the template allowlist (%s)", u.Hostname(), strings.Join(allow, ", "))
		}
	}
	switch t.ID {
	case "ad", "ldap", "racf", "ibmi":
		if m := ldapHost(cfg.Host); m != "" {
			bad("host", "%s", m)
		}
		if !safedial.PortAllowed(cfg.Port) {
			bad("port", "must be 389, 636, or a port from 1024 up (for example 3890 or 6360), and not a database or admin port such as 3306 or 6379")
		}
		switch cfg.TLSMode {
		case "", safedial.ModeLDAPS, safedial.ModeStartTLS:
		case safedial.ModeNone:
			if env != config.Dev {
				bad("tls_mode", "none (plain LDAP) is not allowed in production; use ldaps or starttls")
			}
		default:
			bad("tls_mode", "must be ldaps, starttls or none")
		}
		if cfg.PageSize < 0 || cfg.PageSize > MaxPageSize {
			bad("page_size", "must be from 1 to %d", MaxPageSize)
		}
		if len(cfg.AttrMap) > MaxAttrMap {
			bad("attr_map", "at most %d attributes", MaxAttrMap)
		}
		seen := map[[2]string]bool{}
		for i, m := range cfg.AttrMap {
			switch {
			case !ldap.ValidAttrName(m.LDAP):
				bad("attr_map", "attr_map[%d]: not an LDAP attribute name (letters, digits and hyphens, starting with a letter)", i)
			case !ldap.ValidAttrName(m.Target):
				bad("attr_map", "attr_map[%d]: not a valid Tessera attribute name", i)
			case m.Scope != "account" && m.Scope != "identity":
				bad("attr_map", "attr_map[%d]: scope must be account or identity", i)
			case seen[[2]string{m.Scope, strings.ToLower(m.Target)}]:
				bad("attr_map", "attr_map[%d]: target is mapped twice", i)
			}
			seen[[2]string{m.Scope, strings.ToLower(m.Target)}] = true
		}
		if t.ID == "ibmi" {
			// IBM i has no directory tree: the bind field is the user profile name
			if !ibmiProfileRE.MatchString(cfg.BindDN) {
				bad("bind_dn", "must be an IBM i user profile name (1 to 10 characters)")
			}
			if len(cfg.BaseDNs) > 0 {
				bad("base_dns", "IBM i has no base DN")
			}
		} else {
			if len(cfg.BaseDNs) == 0 {
				bad("base_dns", "at least one base DN is required")
			}
			for _, dn := range append(slices.Clone(cfg.BaseDNs), cfg.ServiceAccountOUs...) {
				if len(dn) > 512 || !dnRE.MatchString(dn) {
					bad("base_dns", "%q is not a distinguished name", dn)
				}
			}
			text("user_filter", cfg.UserFilter, 1024)
			text("group_filter", cfg.GroupFilter, 1024)
			if cfg.BindDN != "" && (len(cfg.BindDN) > 512 || !dnRE.MatchString(cfg.BindDN)) {
				bad("bind_dn", "must be a distinguished name")
			}
		}
		if cfg.CABundle != "" {
			if len(cfg.CABundle) > 64<<10 {
				bad("ca_bundle", "longer than 64 KiB")
			} else if strings.Contains(cfg.CABundle, "PRIVATE KEY") {
				bad("ca_bundle", "must hold certificates only, never a private key")
			} else if _, err := caPool(cfg.CABundle); err != nil {
				bad("ca_bundle", "%v", err)
			}
		}
	case "entra":
		if !guidRE.MatchString(cfg.TenantID) {
			bad("tenant_id", "must be the tenant GUID, not a domain")
		}
		if cfg.Cloud != "" && !slices.Contains(cloudNames, cfg.Cloud) {
			bad("cloud", "must be one of %s", strings.Join(cloudNames, ", "))
		}
	case "okta":
		httpsURL("org_url", cfg.OrgURL, t.HostAllowlist)
	case "google":
		if cfg.Customer == "" {
			bad("customer", "required (my_customer or the customer id)")
		}
		text("customer", cfg.Customer, 64)
		if cfg.Domain != "" {
			host("domain", cfg.Domain)
		}
		// base_dns holds the org unit paths whose users are read (empty: all)
		if len(cfg.BaseDNs) > connsync.MaxOrgUnits {
			bad("base_dns", "at most %d org units", connsync.MaxOrgUnits)
		}
		for i, ou := range cfg.BaseDNs {
			switch {
			case !connsync.ValidOrgUnitPath(ou):
				bad("base_dns", "org unit %d is not a well-formed path: start with /, no trailing /, no quote or backslash, at most %d characters", i+1, connsync.MaxOrgUnitPath)
			case slices.Index(cfg.BaseDNs, ou) != i:
				bad("base_dns", "org unit %d is listed twice", i+1)
			}
		}
	case "workday":
		host("tenant_host", cfg.TenantHost)
		if cfg.TenantHost != "" && !HostAllowed(cfg.TenantHost, t.HostAllowlist) {
			bad("tenant_host", "must be a Workday host (%s)", strings.Join(t.HostAllowlist, ", "))
		}
		if !slices.Contains(interfaces, cfg.Interface) {
			bad("interface", "must be one of %s", strings.Join(interfaces, ", "))
		}
		text("time_zone", cfg.TimeZone, 64)
		if cfg.APIVersion != "" && !apiVersionRE.MatchString(cfg.APIVersion) {
			bad("api_version", "must look like v44.0")
		}
	case "scim_app", "salesforce":
		httpsURL("base_url", cfg.BaseURL, nil)
		if p, ok := scimpreset.PresetByID(cfg.Preset); ok {
			// Vendor-specific shape on top of the generic https check.
			if err := p.ValidateBaseURL(cfg.BaseURL); err != nil && cfg.BaseURL != "" {
				bad("base_url", "%s", err)
			}
		} else if cfg.Preset != "" {
			bad("preset", "unknown SCIM preset %q", cfg.Preset)
		}
	case "awsorg", "githubscan", "erp", "pam", "vms", "agentcore", "successfactors", "azurerbac", "gcpiam", "unixssh", "sftpdrop", "servicenow", "atlassian", "kubernetes", "vault", "mcp", "bedrock", "vertex", "foundry", "copilot", "agentforce":
		typ := connectorType
		if typ == "" && len(t.ConnectorTypes) > 0 {
			typ = t.ConnectorTypes[0]
		}
		required, takes := governed.BaseURLUse(typ)
		switch {
		case takes && (required || cfg.BaseURL != ""):
			var allow []string
			if typ == governed.SuccessFactors {
				allow = t.HostAllowlist // the documented data-center domains; a look-alike host is refused
			}
			if ports := governed.BasePorts(typ); len(ports) > 0 && cfg.BaseURL != "" {
				// a named port is allowed for these types, from a short list; the rest of the URL is checked as usual
				if u, err := url.Parse(cfg.BaseURL); err == nil && u.Port() != "" {
					if !slices.Contains(ports, u.Port()) {
						bad("base_url", "the port must be one of %s", strings.Join(ports, ", "))
					}
					u.Host = u.Hostname()
					httpsURL("base_url", u.String(), allow)
				} else {
					httpsURL("base_url", cfg.BaseURL, allow)
				}
			} else {
				httpsURL("base_url", cfg.BaseURL, allow)
			}
			// The vault, ERP and feed readers take a host (paths are settings); GitHub
			// Enterprise Server's API URL ends in /api/v3.
			if u, err := url.Parse(cfg.BaseURL); err == nil && typ != governed.GitHubScan && typ != governed.MCP && typ != governed.Foundry && u.Path != "" && u.Path != "/" {
				bad("base_url", "must be a host without a path (the paths are settings)")
			}
		case !takes && cfg.BaseURL != "":
			bad("base_url", "this connector type takes no base URL")
		}
		for _, se := range governed.ValidateSettings(typ, cfg.Settings) {
			bad("settings."+se.Key, "%s", se.Msg)
		}
		if typ == governed.SuccessFactors && cfg.WriteMode != "" && cfg.WriteMode != "off" {
			bad("write_mode", "SuccessFactors is a read-only HR source: write-back is not available")
		}
	case "rest_generic":
		if cfg.Rest == nil {
			bad("rest", "required: the connector spec (base URL, auth, resources and mapping)")
			break
		}
		for _, e := range cfg.Rest.ValidateShape() {
			bad("rest."+e.Field, "%s", e.Msg)
		}
	case "sql":
		if cfg.SQL == nil {
			bad("sql", "required: the database settings")
		} else if err := cfg.SQL.Validate(connsync.Runtime{Env: config.Prod}); err != nil {
			// a stored connection follows the production rules (no tls disable)
			bad("sql", "%v", err)
		}
	}
	if t.ID != "scim_app" && cfg.Preset != "" {
		bad("preset", "only a SCIM application has a preset")
	}
	if len(cfg.Settings) > 0 && !slices.Contains(governedTemplates, t.ID) {
		bad("settings", "this connector type takes no settings")
	}
	if cfg.CorrelationKey == "" || !attrRE.MatchString(cfg.CorrelationKey) {
		bad("correlation_key", "required: an attribute name")
	}
	if cfg.HRIDAttribute != "" && !attrRE.MatchString(cfg.HRIDAttribute) {
		bad("hr_id_attribute", "must be an attribute name")
	}
	text("technical_owner", cfg.TechnicalOwner, 200)
	text("business_owner", cfg.BusinessOwner, 200)
	text("sync_schedule", cfg.SyncSchedule, 100)
	if cfg.StaleDays < 0 || cfg.StaleDays > 3650 {
		bad("stale_days", "must be between 1 and 3650")
	}
	if cfg.ExpectedCounts != nil && (cfg.ExpectedCounts.Users < 0 || cfg.ExpectedCounts.Groups < 0) {
		bad("expected_counts", "counts cannot be negative")
	}
	if cfg.WriteMode != "" && !slices.Contains(template.WriteModes, cfg.WriteMode) {
		bad("write_mode", "must be one of %s", strings.Join(template.WriteModes, ", "))
	}
	if len(cfg.WriteScope) > 100 {
		bad("write_scope", "at most 100 entries")
	}
	if len(cfg.PrivilegedExpected) > 100 {
		bad("privileged_expected", "at most 100 groups")
	}
	for g, members := range cfg.PrivilegedExpected {
		text("privileged_expected", g, 256)
		if len(members) > 1000 {
			bad("privileged_expected", "%s: at most 1000 members", g)
		}
		for _, m := range members {
			text("privileged_expected", m, 256)
		}
	}
	if len(cfg.DemoFixedChecks) > 0 && !slices.ContainsFunc(t.ConnectorTypes, IsDemoType) {
		bad("demo_fixed_checks", "only demo connections have simulated checks")
	}
	for _, id := range cfg.DemoFixedChecks {
		if _, ok := template.Checks[id]; !ok {
			bad("demo_fixed_checks", "unknown check %q", id)
		}
	}
	return errs
}

// caPool parses a PEM CA bundle.
func caPool(pemData string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pemData)) {
		return nil, errors.New("holds no PEM certificate")
	}
	return pool, nil
}

// HostAllowed matches a host against allowlist patterns ("*.okta.com" matches
// any subdomain, not the apex).
func HostAllowed(host string, allow []string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, p := range allow {
		p = strings.ToLower(p)
		if strings.HasPrefix(p, "*.") {
			if strings.HasSuffix(host, p[1:]) && len(host) > len(p)-1 {
				return true
			}
		} else if host == p {
			return true
		}
	}
	return false
}

// IsDemoType reports whether a connector type is a simulated demo connector.
func IsDemoType(ct string) bool { return strings.HasPrefix(ct, "demo-") }

// DefaultConfig returns the starting config for a connector type: the
// template's correlation defaults plus, for demo types, the demo system.
func DefaultConfig(connectorType string, t *template.Resolved) ConnConfig {
	cfg := ConnConfig{CorrelationKey: t.DefaultCorrelationKey, HRIDAttribute: t.DefaultHRIDAttribute,
		StaleDays: 90, WriteMode: "off"}
	switch t.ID {
	case "ad", "ldap", "racf":
		cfg.Port = 636
	case "ibmi":
		cfg.Port = 9471 // the TLS-protected IBM i host server (database)
	case "entra":
		cfg.Cloud = "global"
	case "google":
		cfg.Customer = "my_customer"
	case "workday":
		cfg.Interface = "get_workers"
	}
	switch connectorType {
	case "demo-ad":
		cfg.Host = "dc01.corp.larkspur.example"
		cfg.BaseDNs = []string{"OU=People,DC=corp,DC=larkspur,DC=example", "OU=Groups,DC=corp,DC=larkspur,DC=example"}
		cfg.ServiceAccountOUs = []string{"OU=Service Accounts,DC=corp,DC=larkspur,DC=example"}
		cfg.UserFilter = "(&(objectCategory=person)(objectClass=user))"
		cfg.GroupFilter = "(objectClass=group)"
		cfg.PrivilegedExpected = map[string][]string{
			"Domain Admins":     {"thandiwe.mokoena", "ingrid.lindqvist"},
			"Enterprise Admins": {"ingrid.lindqvist"},
		}
	case "demo-okta":
		cfg.OrgURL = "https://larkspur.okta.com"
	case "demo-workday":
		cfg.TenantHost = "wd5.myworkday.com"
		cfg.APIVersion = "v44.0"
		cfg.TimeZone = "America/New_York"
	}
	return cfg
}
