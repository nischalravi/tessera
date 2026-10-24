package readiness

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/restgen"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
)

// ConnConfig is the typed, secret-free configuration of a connection
// revision. Decoding is strict: an unknown field (for example "password") is
// rejected, so a credential can never be smuggled into config text.
type ConnConfig struct {
	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitempty"`
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
	Rest               *restgen.Spec       `json:"rest,omitempty"`
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
	// DemoFixedChecks is the demo scenario toggle: simulated checks listed
	// here pass (for example after "fixing" ranged retrieval). Demo types only.
	DemoFixedChecks []string `json:"demo_fixed_checks,omitempty"`
}

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
	hostRE     = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	guidRE     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	dnRE       = regexp.MustCompile(`(?i)^([a-z][a-z0-9-]*=[^,]+)(,\s*[a-z][a-z0-9-]*=[^,]+)*$`)
	attrRE     = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{0,63}$`)
	printable  = regexp.MustCompile(`^[^\x00-\x1f\x7f]*$`)
	cloudNames = []string{"global", "usgov", "china"}
	interfaces = []string{"get_workers", "raas"}
)

// Validate checks a config for a template. It returns every problem rather
// than the first, so the UI can mark each field.
func Validate(cfg ConnConfig, t *template.Resolved) []FieldError {
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
	case "ad", "ldap":
		host("host", cfg.Host)
		if cfg.Port != 389 && cfg.Port != 636 {
			bad("port", "must be 389 (StartTLS) or 636 (LDAPS)")
		}
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
	case "workday":
		host("tenant_host", cfg.TenantHost)
		if cfg.TenantHost != "" && !HostAllowed(cfg.TenantHost, t.HostAllowlist) {
			bad("tenant_host", "must be a Workday host (%s)", strings.Join(t.HostAllowlist, ", "))
		}
		if !slices.Contains(interfaces, cfg.Interface) {
			bad("interface", "must be one of %s", strings.Join(interfaces, ", "))
		}
		text("time_zone", cfg.TimeZone, 64)
	case "scim_app":
		httpsURL("base_url", cfg.BaseURL, nil)
	case "rest_generic":
		if cfg.Rest == nil {
			bad("rest", "required: the connector spec (base URL, auth, resources and mapping)")
			break
		}
		for _, e := range cfg.Rest.ValidateShape() {
			bad("rest."+e.Field, "%s", e.Msg)
		}
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
	case "ad", "ldap":
		cfg.Port = 636
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
