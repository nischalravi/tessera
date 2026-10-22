package loaders

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	ldapdir "github.com/nischalravi/tessera/mvp/server/internal/connectors/ldap"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/naming"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func invalid(code, format string, args ...any) error {
	return model.NewError(model.Invalid, code, format, args...)
}

func conflict(code, format string, args ...any) error {
	return model.NewError(model.Conflict, code, format, args...)
}

func notFound(format string, args ...any) error {
	return model.NewError(model.NotFound, "not_found", format, args...)
}

// Limits on what a loader's definition may hold.
const (
	MaxQueryBytes  = store.MaxExtQueryBytes
	MaxNameBytes   = 128
	MaxConfigBytes = 64 << 10
)

// SQLConfig is the config of sql_simple and sql_group_list. Database is a file
// name under the loader data directory (never a path outside it).
//
// sql_simple: Query returns the subject_id column (and optionally
// subject_source) and every row is a member of the one group named Group.
// sql_group_list: Query returns group_name and subject_id (and optionally
// subject_source); GroupsQuery optionally returns group_name, display_name and
// description. IncrementalQuery, if set, returns group_name, subject_id,
// optionally subject_source, op ("add" or "remove") and seq (an integer that
// grows) for the rows after @cursor.
//
// Engine is "" or "sqlite" for a database file (Database), or "postgres" for a
// Postgres server: the loader's secret is then the DSN (a postgres:// URL, kept
// sealed and never returned) and Database stays empty. CAPEM is a PEM bundle
// that verifies a private CA's server certificate.
type SQLConfig struct {
	Engine           string `json:"engine,omitempty"`
	Database         string `json:"database,omitempty"`
	CAPEM            string `json:"ca_pem,omitempty"`
	Query            string `json:"query"`
	Group            string `json:"group,omitempty"`
	GroupsQuery      string `json:"groups_query,omitempty"`
	IncrementalQuery string `json:"incremental_query,omitempty"`
}

// CSVConfig is the config of csv: a file under the loader data directory (Path)
// or an https URL (URL; the loader's secret, if it has one, is sent as a bearer
// token). The columns are named by the header row. With Group every row is a
// member of that one group; otherwise GroupColumn names each row's group.
type CSVConfig struct {
	Path          string `json:"path,omitempty"`
	URL           string `json:"url,omitempty"`
	Group         string `json:"group,omitempty"`
	GroupColumn   string `json:"group_column,omitempty"`
	DisplayColumn string `json:"display_column,omitempty"`
	SubjectColumn string `json:"subject_column"`
	SourceColumn  string `json:"source_column,omitempty"`
	// SubjectSource is the source of every subject when SourceColumn is empty
	// (default "identity").
	SubjectSource string `json:"subject_source,omitempty"`
	Delimiter     string `json:"delimiter,omitempty"`
}

// ConnectorGroupsConfig is the config of connector_groups: every group the
// loader's connection has (the connection is the loader's connection_id)
// becomes a native group named after it, with the prefix.
type ConnectorGroupsConfig struct {
	NamePrefix string `json:"name_prefix,omitempty"`
}

// AttributeConfig is the config of attribute: one group per distinct value of
// an identity attribute, named Prefix plus the value.
type AttributeConfig struct {
	Attribute  string `json:"attribute"`
	Prefix     string `json:"prefix,omitempty"`
	OnlyActive *bool  `json:"only_active,omitempty"`
}

// RecentConfig is the config of recent_memberships: Group holds the people who
// were effective members of SourceGroup (a group name) at some time in the last
// Days days and are not now, and with IncludeCurrent also the current members.
type RecentConfig struct {
	SourceGroup    string `json:"source_group"`
	Days           int    `json:"days"`
	IncludeCurrent bool   `json:"include_current,omitempty"`
	Group          string `json:"group"`
}

// SCIMConfig is the config of scim: the groups of an external SCIM 2.0 service
// provider (RFC 7644), with their members. BaseURL is the service root
// (".../scim/v2"). The loader's secret is a bearer token (Auth "bearer", the
// default) or the client secret of an OAuth 2.0 client-credentials grant (Auth
// "client_credentials", with TokenURL and ClientID). Users are read to turn a
// member's SCIM id into the attribute named by SubjectAttr (userName, email,
// externalId or id), which is matched like any other subject (SubjectSource;
// default email for email, identity otherwise). GroupFilter and UserFilter are
// SCIM filters the provider evaluates. Members who are groups are not followed.
type SCIMConfig struct {
	BaseURL       string `json:"base_url"`
	Auth          string `json:"auth,omitempty"`
	TokenURL      string `json:"token_url,omitempty"`
	ClientID      string `json:"client_id,omitempty"`
	Scope         string `json:"scope,omitempty"`
	GroupFilter   string `json:"group_filter,omitempty"`
	UserFilter    string `json:"user_filter,omitempty"`
	PageSize      int    `json:"page_size,omitempty"`
	GroupName     string `json:"group_name,omitempty"`
	NamePrefix    string `json:"name_prefix,omitempty"`
	SubjectAttr   string `json:"subject_attr"`
	SubjectSource string `json:"subject_source,omitempty"`
	OnlyActive    *bool  `json:"only_active,omitempty"`
}

// LDAPConfig is the config of ldap_simple and ldap_group_list. URL is
// ldaps://host[:636] or ldap://host[:389] (StartTLS is required: there is no
// plain LDAP), BindDN a read-only account; the loader's secret is its password.
// CAPEM verifies a private CA. Filter and BaseDN are validated; Scope is sub
// (default) or one; entries are read a page at a time (RFC 2696).
//
// ldap_simple: Filter selects people; SubjectAttr is the attribute of each
// that names the person (uid, mail, employeeNumber); every one is a member of
// the one group named Group.
//
// ldap_group_list: Filter selects group entries; the group's name is
// GroupNameAttr (default cn) and its members are the values of MemberAttr
// (default member). A member that is a DN gives its subject through MemberRDN
// (the RDN attribute whose value names the person, such as uid); with MemberRDN
// empty the value itself is the subject (memberUid). Active Directory's ranged
// member lists (1,500 at a time) are followed.
type LDAPConfig struct {
	URL           string `json:"url"`
	BindDN        string `json:"bind_dn"`
	CAPEM         string `json:"ca_pem,omitempty"`
	BaseDN        string `json:"base_dn"`
	Scope         string `json:"scope,omitempty"`
	Filter        string `json:"filter"`
	PageSize      int    `json:"page_size,omitempty"`
	Group         string `json:"group,omitempty"`
	SubjectAttr   string `json:"subject_attr,omitempty"`
	GroupNameAttr string `json:"group_name_attr,omitempty"`
	DisplayAttr   string `json:"display_attr,omitempty"`
	MemberAttr    string `json:"member_attr,omitempty"`
	MemberRDN     string `json:"member_rdn,omitempty"`
	SubjectSource string `json:"subject_source,omitempty"`
	NamePrefix    string `json:"name_prefix,omitempty"`
}

// attributes an attribute loader may group by.
var groupableAttributes = map[string]bool{"department": true, "title": true, "type": true, "status": true, "source": true}

var (
	dbFileRE     = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*(/[A-Za-z0-9_][A-Za-z0-9_.-]*)*$`)
	columnRE     = regexp.MustCompile(`^[A-Za-z0-9_ .-]{1,64}$`)
	sourceNameRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
	ldapAttrRE   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,62}$`)
)

// strictDecode decodes JSON into v refusing unknown fields and trailing data.
func strictDecode(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

// ValidateConfig checks a loader's config for its type and returns it in
// canonical form (the fields in declaration order, defaults not filled). A
// connector_groups loader needs a connection: hasConnection says it has one.
func ValidateConfig(typ string, raw json.RawMessage, hasConnection bool) (json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > MaxConfigBytes {
		return nil, invalid("invalid_config", "config is required and at most %d bytes", MaxConfigBytes)
	}
	var v any
	var err error
	switch typ {
	case TypeSQLSimple, TypeSQLGroupList:
		c := &SQLConfig{}
		if err = strictDecode(raw, c); err == nil {
			err = c.validate(typ)
		}
		v = c
	case TypeCSV:
		c := &CSVConfig{}
		if err = strictDecode(raw, c); err == nil {
			err = c.validate()
		}
		v = c
	case TypeConnectorGroups:
		c := &ConnectorGroupsConfig{}
		if err = strictDecode(raw, c); err == nil {
			if c.NamePrefix != "" {
				err = checkPrefix(c.NamePrefix)
			}
			if err == nil && !hasConnection {
				err = errors.New("a connector_groups loader needs a connection_id")
			}
		}
		v = c
	case TypeAttribute:
		c := &AttributeConfig{}
		if err = strictDecode(raw, c); err == nil {
			switch {
			case !groupableAttributes[c.Attribute]:
				err = errors.New("attribute is one of department, title, type, status, source")
			case c.Prefix != "":
				err = checkPrefix(c.Prefix)
			}
		}
		v = c
	case TypeSCIM:
		c := &SCIMConfig{}
		if err = strictDecode(raw, c); err == nil {
			err = c.validate()
		}
		v = c
	case TypeLDAPSimple, TypeLDAPGroupList:
		c := &LDAPConfig{}
		if err = strictDecode(raw, c); err == nil {
			err = c.validate(typ)
		}
		v = c
	case TypeRecent:
		c := &RecentConfig{}
		if err = strictDecode(raw, c); err == nil {
			switch {
			case strings.TrimSpace(c.SourceGroup) == "" || len(c.SourceGroup) > 512:
				err = errors.New("source_group is the name of a group")
			case c.Days < 1 || c.Days > 366:
				err = errors.New("days is 1 to 366 (the longest history window)")
			default:
				err = naming.ValidateExtension(c.Group)
			}
		}
		v = c
	default:
		if unavailableTypes[typ] {
			return nil, invalid("loader_type_unavailable", "loader type %q is designed but not available yet (types: %s)", typ, strings.Join(Types(), ", "))
		}
		return nil, invalid("invalid_type", "type is one of %s", strings.Join(Types(), ", "))
	}
	if err != nil {
		return nil, invalid("invalid_config", "%s config: %v", typ, err)
	}
	out, err := json.Marshal(v)
	if err != nil {
		return nil, invalid("invalid_config", "%s config: %v", typ, err)
	}
	return out, nil
}

// checkPrefix: a name prefix is part of an extension.
func checkPrefix(p string) error {
	if err := naming.ValidateExtension(p + "x"); err != nil {
		return fmt.Errorf("prefix %q cannot start a group name: %v", p, err)
	}
	return nil
}

// IsPostgres reports whether the SQL loader runs on a Postgres server.
func (c *SQLConfig) IsPostgres() bool { return c.Engine == "postgres" }

func (c *SQLConfig) validate(typ string) error {
	switch c.Engine {
	case "", "sqlite":
		if len(c.Database) > 255 || !dbFileRE.MatchString(c.Database) || strings.Contains(c.Database, "..") {
			return errors.New("database is a file name under the loader data directory (letters, digits, _ . - and /; no ..)")
		}
		if c.CAPEM != "" {
			return errors.New("ca_pem is for a postgres source")
		}
	case "postgres":
		if c.Database != "" {
			return errors.New("a postgres source names no database file: the connection string is the loader's secret")
		}
		if c.CAPEM != "" {
			if len(c.CAPEM) > 64<<10 || !x509.NewCertPool().AppendCertsFromPEM([]byte(c.CAPEM)) {
				return errors.New("ca_pem holds no PEM certificate")
			}
		}
	default:
		return errors.New("engine is sqlite (a database file) or postgres")
	}
	if err := CheckReadOnlySQL(c.Query); err != nil {
		return fmt.Errorf("query: %v", err)
	}
	switch typ {
	case TypeSQLSimple:
		if err := naming.ValidateExtension(c.Group); err != nil {
			return fmt.Errorf("group: %v", err)
		}
		if c.GroupsQuery != "" {
			return errors.New("groups_query is only for sql_group_list")
		}
	case TypeSQLGroupList:
		if c.Group != "" {
			return errors.New("group is only for sql_simple")
		}
	}
	if c.GroupsQuery != "" {
		if err := CheckReadOnlySQL(c.GroupsQuery); err != nil {
			return fmt.Errorf("groups_query: %v", err)
		}
	}
	if c.IncrementalQuery != "" {
		if err := CheckReadOnlySQL(c.IncrementalQuery); err != nil {
			return fmt.Errorf("incremental_query: %v", err)
		}
		if !strings.Contains(c.IncrementalQuery, "@cursor") {
			return errors.New("incremental_query must use the @cursor parameter")
		}
	}
	return nil
}

var scimAttrs = map[string]bool{"userName": true, "email": true, "externalId": true, "id": true}

// checkSCIMFilter: a SCIM filter is evaluated by the provider; here only its
// size and characters are bounded.
func checkSCIMFilter(name, f string) error {
	if len(f) > 512 || strings.ContainsFunc(f, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return fmt.Errorf("%s is at most 512 characters without control characters", name)
	}
	return nil
}

func checkHTTPURL(name, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(raw) > 2048 {
		return fmt.Errorf("%s is an https URL without credentials, query or fragment", name)
	}
	return nil
}

func (c *SCIMConfig) validate() error {
	if err := checkHTTPURL("base_url", c.BaseURL); err != nil {
		return err
	}
	switch c.Auth {
	case "", "bearer":
		if c.TokenURL != "" || c.ClientID != "" || c.Scope != "" {
			return errors.New("token_url, client_id and scope are for auth client_credentials")
		}
	case "client_credentials":
		if err := checkHTTPURL("token_url", c.TokenURL); err != nil {
			return err
		}
		if c.ClientID == "" || len(c.ClientID) > 256 || len(c.Scope) > 256 {
			return errors.New("client_id is required (at most 256 characters)")
		}
	default:
		return errors.New("auth is bearer or client_credentials")
	}
	if !scimAttrs[c.SubjectAttr] {
		return errors.New("subject_attr is one of userName, email, externalId, id")
	}
	if c.SubjectSource != "" && !sourceNameRE.MatchString(c.SubjectSource) {
		return errors.New("subject_source is a source name")
	}
	switch c.GroupName {
	case "", "displayName", "externalId":
	default:
		return errors.New("group_name is displayName or externalId")
	}
	if c.PageSize < 0 || c.PageSize > 1000 {
		return errors.New("page_size is 1 to 1000")
	}
	if c.NamePrefix != "" {
		if err := checkPrefix(c.NamePrefix); err != nil {
			return err
		}
	}
	if err := checkSCIMFilter("group_filter", c.GroupFilter); err != nil {
		return err
	}
	return checkSCIMFilter("user_filter", c.UserFilter)
}

// LDAPEndpoint is a parsed directory URL: the port is 636 for ldaps and 389
// (with StartTLS) for ldap unless named, and only those two are reachable.
type LDAPEndpoint struct {
	Host string
	Port int
}

// ParseLDAPURL checks an ldap:// or ldaps:// URL (scheme, host and port only).
func ParseLDAPURL(raw string) (LDAPEndpoint, error) {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 512 || u.Hostname() == "" || (u.Scheme != "ldaps" && u.Scheme != "ldap") ||
		u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return LDAPEndpoint{}, errors.New("url is ldaps://host[:636] or ldap://host[:389] (StartTLS), with nothing after the port")
	}
	port := 636
	if u.Scheme == "ldap" {
		port = 389
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || (n != 389 && n != 636) {
			return LDAPEndpoint{}, errors.New("the port is 389 (StartTLS) or 636 (LDAPS)")
		}
		port = n
	}
	if (u.Scheme == "ldaps") != (port == 636) {
		return LDAPEndpoint{}, errors.New("ldaps:// uses port 636 and ldap:// uses 389 with StartTLS")
	}
	return LDAPEndpoint{Host: u.Hostname(), Port: port}, nil
}

func (c *LDAPConfig) validate(typ string) error {
	if _, err := ParseLDAPURL(c.URL); err != nil {
		return err
	}
	if err := ldapdir.ValidDN(c.BindDN); err != nil {
		return fmt.Errorf("bind_dn: %v", err)
	}
	if err := ldapdir.ValidDN(c.BaseDN); err != nil {
		return fmt.Errorf("base_dn: %v", err)
	}
	if err := ldapdir.ValidFilter(c.Filter); err != nil {
		return fmt.Errorf("filter: %v", err)
	}
	if c.CAPEM != "" && (len(c.CAPEM) > 64<<10 || !x509.NewCertPool().AppendCertsFromPEM([]byte(c.CAPEM))) {
		return errors.New("ca_pem holds no PEM certificate")
	}
	switch c.Scope {
	case "", "sub", "one":
	default:
		return errors.New("scope is sub or one")
	}
	if c.PageSize < 0 || c.PageSize > 5000 {
		return errors.New("page_size is 1 to 5000")
	}
	if c.SubjectSource != "" && !sourceNameRE.MatchString(c.SubjectSource) {
		return errors.New("subject_source is a source name")
	}
	if c.NamePrefix != "" {
		if err := checkPrefix(c.NamePrefix); err != nil {
			return err
		}
	}
	for name, v := range map[string]string{"subject_attr": c.SubjectAttr, "group_name_attr": c.GroupNameAttr, "display_attr": c.DisplayAttr,
		"member_attr": c.MemberAttr, "member_rdn": c.MemberRDN} {
		if v != "" && !ldapAttrRE.MatchString(v) {
			return fmt.Errorf("%s is an attribute name", name)
		}
	}
	if typ == TypeLDAPSimple {
		if c.SubjectAttr == "" {
			return errors.New("subject_attr names the attribute of each entry that identifies the person")
		}
		if err := naming.ValidateExtension(c.Group); err != nil {
			return fmt.Errorf("group: %v", err)
		}
		if c.GroupNameAttr != "" || c.DisplayAttr != "" || c.MemberAttr != "" || c.MemberRDN != "" {
			return errors.New("group_name_attr, display_attr, member_attr and member_rdn are for ldap_group_list")
		}
		return nil
	}
	if c.Group != "" || c.SubjectAttr != "" {
		return errors.New("group and subject_attr are for ldap_simple")
	}
	return nil
}

// SecretUse says whether a loader holds a credential and whether it must.
type SecretUse int

// The credential of a loader: none, optional (a CSV URL's bearer token), or
// required (a SCIM token or client secret, an LDAP bind password, a Postgres
// connection string).
const (
	SecretNone SecretUse = iota
	SecretOptional
	SecretRequired
)

// SecretPolicy says what credential a loader of the type and config takes.
// It is only meaningful for a config that has been validated.
func SecretPolicy(typ string, config json.RawMessage) SecretUse {
	switch typ {
	case TypeSCIM, TypeLDAPSimple, TypeLDAPGroupList:
		return SecretRequired
	case TypeCSV:
		var c CSVConfig
		if strictDecode(config, &c) == nil && c.URL != "" {
			return SecretOptional
		}
	case TypeSQLSimple, TypeSQLGroupList:
		var c SQLConfig
		if strictDecode(config, &c) == nil && c.IsPostgres() {
			return SecretRequired
		}
	}
	return SecretNone
}

// CheckSecret checks a credential before it is sealed: its size, and for a
// Postgres source its connection string (in production only sslmode=verify-full).
func CheckSecret(typ string, config json.RawMessage, secret string, prod bool) error {
	switch {
	case len(secret) > SecretMaxBytes:
		return invalid("invalid_secret", "secret is at most %d bytes", SecretMaxBytes)
	case strings.ContainsRune(secret, 0):
		return invalid("invalid_secret", "secret contains a NUL byte")
	}
	var c SQLConfig
	if (typ == TypeSQLSimple || typ == TypeSQLGroupList) && strictDecode(config, &c) == nil && c.IsPostgres() {
		if err := store.CheckPGDSN(secret, prod); err != nil {
			return invalid("invalid_secret", "the connection string: %v", err)
		}
	}
	return nil
}

func (c *CSVConfig) validate() error {
	switch {
	case (c.Path == "") == (c.URL == ""):
		return errors.New("name exactly one of path and url")
	case c.Path != "" && (len(c.Path) > 255 || !dbFileRE.MatchString(c.Path) || strings.Contains(c.Path, "..")):
		return errors.New("path is a file name under the loader data directory (letters, digits, _ . - and /; no ..)")
	case c.SubjectColumn == "" || !columnRE.MatchString(c.SubjectColumn):
		return errors.New("subject_column names the column of the subjects")
	case c.Group != "" && c.GroupColumn != "":
		return errors.New("name group or group_column, not both")
	case c.Group == "" && c.GroupColumn == "":
		return errors.New("name group (one group for every row) or group_column")
	case c.GroupColumn != "" && !columnRE.MatchString(c.GroupColumn):
		return errors.New("group_column names the column of the groups")
	case c.DisplayColumn != "" && !columnRE.MatchString(c.DisplayColumn):
		return errors.New("display_column names a column")
	case c.SourceColumn != "" && !columnRE.MatchString(c.SourceColumn):
		return errors.New("source_column names a column")
	case c.SourceColumn != "" && c.SubjectSource != "":
		return errors.New("name source_column or subject_source, not both")
	case c.SubjectSource != "" && !sourceNameRE.MatchString(c.SubjectSource):
		return errors.New("subject_source is a source name")
	case c.Delimiter != "" && (len([]rune(c.Delimiter)) != 1 || c.Delimiter == "\"" || c.Delimiter == "\n" || c.Delimiter == "\r"):
		return errors.New("delimiter is one character")
	}
	if c.Group != "" {
		if err := naming.ValidateExtension(c.Group); err != nil {
			return fmt.Errorf("group: %v", err)
		}
	}
	if c.URL != "" {
		u, err := url.Parse(c.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || len(c.URL) > 2048 {
			return errors.New("url is an https URL without credentials")
		}
	}
	return nil
}

// CheckReadOnlySQL is the first line of defence of a SQL loader: the statement
// must be one SELECT or WITH statement (design §9.1), checked by parsing its
// first keyword. The check lives in the store, which runs the query and repeats
// it; the second line is the connection itself, which is read-only.
func CheckReadOnlySQL(q string) error { return store.CheckReadOnlySQL(q) }

// ApplyTemplate turns a source's group name into the extension of the native
// group. The template has exactly one {{.Name}} and otherwise plain text: no
// code runs (K6).
func ApplyTemplate(tmpl, name string) string { return strings.Replace(tmpl, "{{.Name}}", name, 1) }

// ValidateTemplate checks a name template.
func ValidateTemplate(tmpl string) error {
	if strings.Count(tmpl, "{{.Name}}") != 1 {
		return invalid("invalid_name_template", "name_template has exactly one {{.Name}}")
	}
	if err := naming.ValidateExtension(ApplyTemplate(tmpl, "x")); err != nil {
		return invalid("invalid_name_template", "name_template does not make a group name: %v", err)
	}
	return nil
}
