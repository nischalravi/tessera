package template

import "slices"

// TemplateIDs are the connector templates that ship (base is extended, not used directly).
var TemplateIDs = []string{"ad", "ldap", "entra", "okta", "google", "workday", "scim_app", "rest_generic",
	"awsorg", "githubscan", "erp", "pam", "vms", "agentcore", "sql", "azurerbac", "gcpiam", "successfactors"}

// Categories group checklist items in the UI (§10.2).
var Categories = []string{"access", "ownership", "transport", "scope", "identity_keys", "account_status",
	"groups", "change_tracking", "data_quality", "topology", "write_back"}

// ConfigFields are the typed connection-config fields an item may declare in
// config_fields. "credential" stands for the secret reference and version.
var ConfigFields = []string{"host", "port", "bind_dn", "ca_bundle", "base_dns", "user_filter", "group_filter", "service_account_ous",
	"org_url", "tenant_id", "cloud", "customer", "domain", "base_url", "tenant_host", "api_version", "interface",
	"time_zone", "role", "correlation_key", "hr_id_attribute", "technical_owner", "business_owner",
	"expected_counts", "stale_days", "sync_schedule", "write_mode", "write_scope", "hybrid", "use_dirsync",
	"privileged_expected", "demo_fixed_checks", "settings", "rest", "credential", "sql"}

// CheckSpec describes a check id the templates may reference (§5.4). The
// check implementations live in internal/readiness/checks, whose registry
// test proves every id here has one.
type CheckSpec struct {
	Kind VerifyKind
	// Templates that may reference the check; nil means every template.
	Templates []string
	// Op is the single read-only Prober operation a live check uses
	// ("tessera" for checks that inspect only Tessera's own records).
	Op string
}

// Allowed reports whether a template may reference the check.
func (s CheckSpec) Allowed(templateID string) bool {
	return s.Templates == nil || templateID == "base" || slices.Contains(s.Templates, templateID)
}

func live(op string, templates ...string) CheckSpec {
	return CheckSpec{Kind: Live, Templates: templates, Op: op}
}

func data(templates ...string) CheckSpec { return CheckSpec{Kind: Data, Templates: templates} }

// Prober operation names (connectors.Prober methods).
const (
	OpTessera        = "tessera"
	OpConnect        = "connect"
	OpAuthenticate   = "authenticate"
	OpRootInfo       = "root_info"
	OpObjectExists   = "object_exists"
	OpSample         = "sample"
	OpEffectiveRight = "effective_rights"
	OpChangeFeed     = "change_feed"
	OpRateLimits     = "rate_limits"
	OpTime           = "time"
)

// Checks is the closed catalogue of check ids. A template that names any
// other check fails the linter.
var Checks = map[string]CheckSpec{
	// live checks
	"cred_storage":              live(OpTessera),
	"cred_expiry":               live(OpAuthenticate),
	"clock_skew":                live(OpTime),
	"write_scope":               live(OpEffectiveRight),
	"tls_handshake":             live(OpConnect, "ad", "ldap"),
	"tls_chain":                 live(OpConnect, "ad", "ldap"),
	"bind":                      live(OpAuthenticate, "ad", "ldap"),
	"token_acquire":             live(OpAuthenticate, "entra", "okta", "google"),
	"auth_ok":                   live(OpAuthenticate, "scim_app", "workday", "rest_generic", "awsorg", "githubscan", "erp", "pam", "vms", "azurerbac", "gcpiam", "successfactors"),
	"bind_identity":             live(OpAuthenticate, "ldap"),
	"ad_svc_groups":             live(OpEffectiveRight, "ad"),
	"ad_effective_rights":       live(OpEffectiveRight, "ad"),
	"effective_rights":          live(OpEffectiveRight, "ldap", "pam"),
	"ad_replication_rights":     live(OpEffectiveRight, "ad"),
	"dn_exists":                 live(OpObjectExists, "ad", "ldap"),
	"filter_parse":              live(OpTessera, "ad", "ldap"),
	"sample_search":             live(OpSample, "ad", "ldap"),
	"read_per_class":            live(OpSample, "ad", "ldap"),
	"attr_returned":             live(OpSample, "ad", "ldap"),
	"paging":                    live(OpSample, "ad", "ldap", "scim_app"),
	"range_retrieval":           live(OpSample, "ad"),
	"dc_count":                  live(OpRootInfo, "ad"),
	"incremental_capable":       live(OpChangeFeed, "ad", "ldap", "workday"),
	"dirsync_allowed":           live(OpChangeFeed, "ad"),
	"delta_capable":             live(OpChangeFeed, "entra"),
	"syslog_readable":           live(OpChangeFeed, "okta"),
	"reports_readable":          live(OpChangeFeed, "google"),
	"deleted_objects_readable":  live(OpObjectExists, "ad"),
	"forest_domains":            live(OpRootInfo, "ad"),
	"trusts":                    live(OpRootInfo, "ad"),
	"recycle_bin_state":         live(OpRootInfo, "ad"),
	"schema_read":               live(OpRootInfo, "ldap"),
	"token_roles":               live(OpAuthenticate, "entra"),
	"credential_type":           live(OpAuthenticate, "entra", "google"),
	"token_scopes":              live(OpAuthenticate, "okta"),
	"app_admin_roles":           live(OpEffectiveRight, "okta"),
	"auth_mode":                 live(OpAuthenticate, "okta"),
	"dwd_scopes":                live(OpAuthenticate, "google"),
	"subject_roles":             live(OpEffectiveRight, "google"),
	"domains_list":              live(OpRootInfo, "google"),
	"ou_list":                   live(OpRootInfo, "google"),
	"roles_readable":            live(OpSample, "entra", "okta", "google"),
	"group_rules_readable":      live(OpSample, "okta"),
	"signin_activity_available": live(OpSample, "entra"),
	"deprovisioned_visible":     live(OpSample, "okta"),
	"rate_headroom":             live(OpRateLimits, "entra", "okta", "google", "scim_app", "rest_generic"),
	"scim_discovery":            live(OpRootInfo, "scim_app"),
	"members_complete":          live(OpSample, "scim_app"),
	"mapping_applied":           live(OpSample, "rest_generic"),
	"field_inventory":           live(OpSample, "workday", "successfactors"),
	"endpoint_reachable":        live(OpConnect, "workday", "scim_app", "rest_generic", "githubscan", "erp", "pam", "vms", "successfactors"),
	"read_probe":                live(OpSample, "awsorg", "githubscan", "erp", "pam", "vms", "agentcore", "azurerbac", "gcpiam", "successfactors"),

	// data checks over the staged snapshot
	"key_unique":            data(),
	"correlation_rate":      data(),
	"fill_rate":             data(),
	"count_match":           data(),
	"findings_acknowledged": data(),
	"attr_present":          data(),
	"status_mapped":         data(),
	"nesting_resolved":      data(),
	"group_types":           data(),
	"member_resolution":     data(),
	"privileged_unexpected": data(),
	"cross_link_rate":       data(),
	"expiry_parsed":         data(),
	"class_present":         data("ad", "ldap"),
	"uac_mapped":            data("ad"),
	"primary_group":         data("ad"),
	"fsp_resolved":          data("ad"),
	"disabled_expression":   data("ldap"),
	"memberof_consistency":  data("ldap"),
	"delete_detection_mode": data("ldap"),
	"guest_classification":  data("entra"),
	"profile_source":        data("okta"),
	"population_mix":        data("workday"),
	"future_dated_present":  data("workday"),
	"multi_position":        data("workday"),
	"local_accounts":        data("scim_app"),
}

// Threshold keys and their direction: +1 when a higher value is stricter
// (fill rates), -1 when a lower value is stricter (tolerances, day counts).
var Thresholds = map[string]int{
	"fill_rate.required":    +1,
	"fill_rate.recommended": +1,
	"count_tolerance":       -1,
	"stale_days":            -1,
	"stale_lag_days":        -1,
}

// AppliesWhen vocabularies.
var (
	WriteModes = []string{"off", "dry_run", "scoped"}
	Roles      = []string{"authoritative", "account_source"}
	ConfigFlag = []string{"hybrid", "use_dirsync"}
)
