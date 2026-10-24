// Package governed maps a governed connection (a readiness connection created
// from Settings, Connections, New connection) of an existing connector type
// onto that connector's own code: the connector is built through the same
// environment mapping its FromEnv uses (so the settings mean what the
// TESSERA_* variables mean), and a read-only prober over the connector's own
// client answers the readiness live checks.
//
// Nothing here changes what a connector reads or writes. The package owns three
// things: the registry of types (Types), the validation of a connection's
// non-secret settings (ValidateSettings), and the adapters (Connector, Prober).
package governed

import (
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Connector types a connection may have, with the readiness template that
// governs each and the graph system its connector reports.
const (
	AWSOrg      = "awsorg"
	GitHubScan  = "githubscan"
	SAP         = "sap"
	Oracle      = "oracle"
	CyberArk    = "cyberark"
	BeyondTrust = "beyondtrust"
	Delinea     = "delinea"
	Fieldglass  = "fieldglass"
	Beeline     = "beeline"
	CSVFeed     = "csvfeed"
	AgentCore   = "agentcore"
	// SuccessFactors is SAP SuccessFactors Employee Central, a read-only HR source.
	SuccessFactors = "successfactors"
	AzureRBAC      = "azurerbac"
	GCPIAM         = "gcpiam"
	UnixSSH        = "unixssh"
)

// Type describes one governed connector type.
type Type struct {
	ID       string
	Template string // readiness template id
	System   string // the system name the connector writes into the graph
	// Vendor is the name the connector package knows the type by.
	Vendor string
	// Feature types hand over to a feature that keeps its own sources (the
	// AWS connectors, the contractor feeds) when activated; the others are
	// read by the sync directly (Connector).
	Feature bool
}

// Types lists every governed type.
var Types = []Type{
	{ID: AWSOrg, Template: "awsorg", System: "aws", Vendor: AWSOrg, Feature: true},
	{ID: GitHubScan, Template: "githubscan", System: "github-scan", Vendor: GitHubScan},
	{ID: SAP, Template: "erp", System: "sap", Vendor: "sap"},
	{ID: Oracle, Template: "erp", System: "oracle", Vendor: "oracle"},
	{ID: CyberArk, Template: "pam", System: "cyberark", Vendor: "cyberark"},
	{ID: BeyondTrust, Template: "pam", System: "beyondtrust", Vendor: "beyondtrust"},
	{ID: Delinea, Template: "pam", System: "delinea", Vendor: "delinea"},
	{ID: Fieldglass, Template: "vms", System: "fieldglass", Vendor: "fieldglass", Feature: true},
	{ID: Beeline, Template: "vms", System: "beeline", Vendor: "beeline", Feature: true},
	{ID: CSVFeed, Template: "vms", System: "csv", Vendor: "csv", Feature: true},
	{ID: AgentCore, Template: "agentcore", System: "aws-agentcore", Vendor: AgentCore},
	{ID: SuccessFactors, Template: "successfactors", System: "successfactors", Vendor: SuccessFactors},
	{ID: AzureRBAC, Template: "azurerbac", System: "azure", Vendor: AzureRBAC},
	{ID: GCPIAM, Template: "gcpiam", System: "gcp", Vendor: GCPIAM},
	{ID: UnixSSH, Template: "unixssh", System: "unix", Vendor: UnixSSH},
}

// Lookup returns the type with the id.
func Lookup(id string) (Type, bool) {
	for _, t := range Types {
		if t.ID == id {
			return t, true
		}
	}
	return Type{}, false
}

// Setting is one non-secret option of a connection (Config.Settings).
type Setting struct {
	Key      string
	Label    string
	Hint     string
	Required bool
}

// SettingSpecs returns the settings a type takes, in display order.
func SettingSpecs(typ string) []Setting {
	switch typ {
	case CyberArk, Delinea, BeyondTrust:
		user := "Service user"
		if typ == BeyondTrust {
			user = "Run-as user"
		}
		return []Setting{
			{"username", user, "A dedicated account with read access to safes, members and accounts. Its password (BeyondTrust: the API key) is the credential.", true},
			{"api_root", "API root path", "Only when the vendor's default path is changed.", false}}
	case SAP, Oracle:
		return []Setting{
			{"client_id", "OAuth client id", "The integration's client. Its secret is the credential.", true},
			{"api_root", "Authorization service path", "Optional.", false},
			{"token_path", "OAuth token path", "Optional.", false}}
	case GitHubScan:
		return []Setting{{"org", "Organization", "The GitHub organization to scan. The credential is a read-only token (Contents and Metadata: read).", true}}
	case SuccessFactors:
		return []Setting{
			{"auth", "Authentication", "basic (the credential is the API user's password) or saml_bearer (the credential is the PEM private key and certificate registered on the OAuth client). Default basic.", false},
			{"company_id", "Company id", "The SuccessFactors company id.", true},
			{"username", "API user", "A dedicated API user with read-only permissions. The login name for basic authentication.", true},
			{"user_id", "SAML user id", "With saml_bearer: the user id the assertion is issued for (its NameID), when it differs from the login name. Default: the API user.", false},
			{"client_id", "OAuth client id (API key)", "Required with saml_bearer.", false},
			{"legal_entity", "Legal entity", "Optional: read only the jobs of this legal entity (company).", false}}
	case AgentCore:
		return []Setting{{"snapshot", "Snapshot file", "A recorded AgentCore snapshot (JSON) in this tenant's directory under TESSERA_LOADER_DATA_DIR. There is no live AgentCore client; refused in prod.", true}}
	case Fieldglass, Beeline:
		return []Setting{
			{"workers_path", "Worker listing path", "Default: Fieldglass /api/v1/workers, Beeline /api/v2/assignments.", false},
			{"token_path", "OAuth token path", "Default /api/oauth2/v2.0/token.", false},
			{"page_size", "Page size", "1 to 1000, default 100.", false}}
	case CSVFeed:
		return []Setting{{"csv_path", "CSV path under the base URL", "The feed is fetched over HTTPS. The credential is an optional bearer token.", true}}
	case AzureRBAC:
		return []Setting{
			{"tenant_id", "Directory (tenant) id", "The Entra tenant GUID. The credential is the application's client secret, or a PEM with its certificate and RSA private key.", true},
			{"client_id", "Application (client) id", "A service principal with Reader at the scopes to read (and Microsoft.Authorization/roleEligibilityScheduleInstances/read for PIM).", true},
			{"subscription_ids", "Subscription ids", "Comma separated GUIDs. Empty with no management groups: every subscription the application can list.", false},
			{"management_group_ids", "Management group ids", "Comma separated. Empty with no subscriptions: every management group the application can list.", false},
			{"include_eligible", "Read PIM eligible assignments", "true or false (default false). Needs Entra ID P2 and the read permission above.", false}}
	case GCPIAM:
		return []Setting{
			{"organization_id", "Organization id", "The numeric organization id. Its folders and projects are walked. The credential is a service account key (JSON).", false},
			{"folder_ids", "Folder ids", "Comma separated numeric ids; each is walked. Optional.", false},
			{"project_ids", "Project ids", "Comma separated. Optional. Set at least one of organization, folders or projects.", false}}
	case UnixSSH:
		return []Setting{
			{"host", "Host", "The host name or IP address of the Unix or Linux host. Private, loopback and link-local addresses are refused from the server.", true},
			{"port", "SSH port", "1 to 65535, default 22.", false},
			{"username", "SSH user", "A dedicated account. Its private key is the credential. It runs only getent, lastlog and the sudoers read.", true},
			{"host_key", "Host key", "The pinned host key: a SHA256 fingerprint (ssh-keygen -lf) or the public key line. A host whose key differs is refused.", true},
			{"use_sudo", "Read sudoers through sudo", "true or false (default false). Needs NOPASSWD sudo entries for exactly the two read commands (see the README).", false}}
	case AWSOrg:
		return []Setting{
			{"role_name", "Reader role name", "The role assumed in each account. Default TesseraReader.", false},
			{"regions", "Regions", "Comma separated; the first is where STS is called.", true},
			{"account_ids", "Account ids", "Comma separated. Empty with a management account: every active account.", false},
			{"management_account_id", "Management account id", "Set for an organization-wide read.", false},
			{"identity_center_region", "Identity Center region", "Empty skips IAM Identity Center.", false},
			{"external_id", "External id", "The sts:ExternalId in the reader role's trust policy.", true}}
	}
	return nil
}

// BaseURLUse says whether a type takes the connection's base_url (an https
// URL of the service) and whether it must be set. GitHub scans GitHub.com when
// it is empty; AWS and AgentCore take none.
func BaseURLUse(typ string) (required, takes bool) {
	switch typ {
	case CyberArk, Delinea, BeyondTrust, SAP, Oracle, Fieldglass, Beeline, CSVFeed, SuccessFactors:
		return true, true
	case GitHubScan:
		return false, true
	}
	return false, false
}

var (
	pathRE    = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{0,200}$`)
	orgRE     = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`)
	userRE    = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,256}$`)
	clientRE  = regexp.MustCompile(`^[^\x00-\x1f\x7f\s]{1,256}$`)
	fileRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,100}$`)
	roleRE    = regexp.MustCompile(`^[\w+=,.@-]{1,64}$`)
	regionRE  = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d{1,2}$`)
	accountRE = regexp.MustCompile(`^\d{12}$`)
	extIDRE   = regexp.MustCompile(`^[\w+=,.@:/-]{2,1000}$`)
	companyRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	sfUserRE  = regexp.MustCompile(`^[^\x00-\x1f\x7f:]{1,128}$`)
	entityRE  = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,64}$`)
	guidRE    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	mgRE      = regexp.MustCompile(`^[A-Za-z0-9._()-]{1,90}$`)
	numRE     = regexp.MustCompile(`^[0-9]{1,20}$`)
	projectRE = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	sshUserRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,31}$`)
	sshHostRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	// hostKeyRE is the shape only (the connector parses the key itself): a fingerprint, or a public key line.
	hostKeyRE = regexp.MustCompile(`^(SHA256:[A-Za-z0-9+/]{43}|[^\s\x00-\x1f\x7f]{1,255} [^\x00-\x1f\x7f]{16,1000})$`)
)

// SettingError is one invalid setting.
type SettingError struct{ Key, Msg string }

// ValidateSettings checks the settings of a type: only its own keys, each
// against its grammar, and every required one present.
func ValidateSettings(typ string, set map[string]string) []SettingError {
	var errs []SettingError
	specs := SettingSpecs(typ)
	known := map[string]bool{}
	for _, s := range specs {
		known[s.Key] = true
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !known[k] {
			errs = append(errs, SettingError{k, "is not a setting of " + typ})
		}
	}
	bad := func(k, format string, a ...any) { errs = append(errs, SettingError{k, fmt.Sprintf(format, a...)}) }
	for _, s := range specs {
		v := strings.TrimSpace(set[s.Key])
		if v == "" {
			if s.Required {
				bad(s.Key, "required")
			}
			continue
		}
		switch s.Key {
		case "username":
			if typ == UnixSSH {
				if !sshUserRE.MatchString(v) {
					bad(s.Key, "must be an account name (letters, digits, _ . -, at most 32)")
				}
			} else if typ == SuccessFactors {
				if !sfUserRE.MatchString(v) {
					bad(s.Key, "must be 1 to 128 printable characters without a colon")
				}
			} else if !userRE.MatchString(v) {
				bad(s.Key, "must be 1 to 256 printable characters")
			}
		case "user_id":
			if !entityRE.MatchString(v) {
				bad(s.Key, "must be 1 to 64 printable characters")
			}
		case "auth":
			if v != "basic" && v != "saml_bearer" {
				bad(s.Key, "must be basic or saml_bearer")
			}
		case "company_id":
			if !companyRE.MatchString(v) {
				bad(s.Key, "must be a plain company id (letters, digits, . _ -)")
			}
		case "legal_entity":
			if !entityRE.MatchString(v) {
				bad(s.Key, "must be 1 to 64 printable characters")
			}
		case "client_id":
			if typ == AzureRBAC {
				if !guidRE.MatchString(v) {
					bad(s.Key, "must be the application (client) GUID")
				}
			} else if !clientRE.MatchString(v) {
				bad(s.Key, "must be 1 to 256 characters without spaces")
			}
		case "org":
			if !orgRE.MatchString(v) {
				bad(s.Key, "is not a GitHub organization name")
			}
		case "api_root", "token_path", "workers_path", "csv_path":
			if !pathRE.MatchString(v) || strings.Contains(v, "..") || strings.Contains(v, "//") {
				bad(s.Key, "must be an absolute path of plain characters")
			}
		case "page_size":
			if n, err := strconv.Atoi(v); err != nil || n < 1 || n > 1000 {
				bad(s.Key, "must be between 1 and 1000")
			}
		case "snapshot":
			if !fileRE.MatchString(v) || strings.Contains(v, "..") {
				bad(s.Key, "must be a file name (no directory)")
			}
		case "role_name":
			if !roleRE.MatchString(v) {
				bad(s.Key, "is not an IAM role name")
			}
		case "regions":
			list := List(v)
			if len(list) == 0 || len(list) > 20 {
				bad(s.Key, "between 1 and 20 regions")
			}
			for _, r := range list {
				if !regionRE.MatchString(r) {
					bad(s.Key, "%q is not a region name", clip(r))
				}
			}
		case "account_ids":
			for _, a := range List(v) {
				if !accountRE.MatchString(a) {
					bad(s.Key, "%q is not a 12-digit account id", clip(a))
				}
			}
		case "management_account_id":
			if !accountRE.MatchString(v) {
				bad(s.Key, "is not a 12-digit account id")
			}
		case "identity_center_region":
			if !regionRE.MatchString(v) {
				bad(s.Key, "is not a region name")
			}
		case "external_id":
			if !extIDRE.MatchString(v) {
				bad(s.Key, "is not a valid external id")
			}
		case "tenant_id":
			if !guidRE.MatchString(v) {
				bad(s.Key, "must be the directory (tenant) GUID")
			}
		case "subscription_ids":
			checkList(v, 200, guidRE, "a subscription GUID", s.Key, bad)
		case "management_group_ids":
			checkList(v, 200, mgRE, "a management group id", s.Key, bad)
		case "host":
			if _, err := netip.ParseAddr(v); err != nil && !sshHostRE.MatchString(v) {
				bad(s.Key, "must be a host name or an IP address (no scheme, port or path)")
			}
		case "port":
			if n, err := strconv.Atoi(v); err != nil || n < 1 || n > 65535 {
				bad(s.Key, "must be between 1 and 65535")
			}
		case "host_key":
			if !hostKeyRE.MatchString(v) {
				bad(s.Key, "must be a SHA256:<fingerprint> or a public key line (ssh-ed25519 AAAA...)")
			}
		case "include_eligible", "use_sudo":
			if v != "true" && v != "false" {
				bad(s.Key, "must be true or false")
			}
		case "organization_id":
			if !numRE.MatchString(v) {
				bad(s.Key, "must be the numeric organization id")
			}
		case "folder_ids":
			checkList(v, 200, numRE, "a numeric folder id", s.Key, bad)
		case "project_ids":
			checkList(v, 200, projectRE, "a project id", s.Key, bad)
		}
	}
	if typ == SuccessFactors && strings.TrimSpace(set["auth"]) == "saml_bearer" && strings.TrimSpace(set["client_id"]) == "" {
		bad("client_id", "required with saml_bearer")
	}
	if typ == GCPIAM && strings.TrimSpace(set["organization_id"])+strings.TrimSpace(set["folder_ids"])+strings.TrimSpace(set["project_ids"]) == "" {
		bad("organization_id", "set an organization, folders or projects to read")
	}
	return errs
}

// checkList validates a comma separated setting: at most max entries, each matching re.
func checkList(v string, max int, re *regexp.Regexp, what, key string, bad func(k, format string, a ...any)) {
	list := List(v)
	if len(list) > max {
		bad(key, "at most %d entries", max)
	}
	for _, e := range list {
		if !re.MatchString(e) {
			bad(key, "an entry is not %s", what)
			return
		}
	}
}

func clip(s string) string {
	if len(s) > 40 {
		return s[:40]
	}
	return s
}

// List splits a comma separated setting, trimming blanks.
func List(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Params is everything needed to open a governed connection. Secret is the
// opened credential; Params prints without it.
type Params struct {
	Type     string
	BaseURL  string
	Settings map[string]string
	Secret   string
	// Tenant is the tenant id text: a snapshot is read from the tenant's directory.
	Tenant string
	// DataDir is TESSERA_LOADER_DATA_DIR, where a snapshot is read from.
	DataDir string
	// Prod is true in a production deployment.
	Prod bool
}

// String omits the secret.
func (p Params) String() string { return "governed.Params{" + p.Type + "}" }

// GoString omits the secret (fmt %#v).
func (p Params) GoString() string { return p.String() }

// Format omits the secret (every verb).
func (p Params) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, p.String()) }
