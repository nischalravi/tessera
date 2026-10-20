package loaders

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

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
type SQLConfig struct {
	Database         string `json:"database"`
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

// attributes an attribute loader may group by.
var groupableAttributes = map[string]bool{"department": true, "title": true, "type": true, "status": true, "source": true}

var (
	dbFileRE     = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*(/[A-Za-z0-9_][A-Za-z0-9_.-]*)*$`)
	columnRE     = regexp.MustCompile(`^[A-Za-z0-9_ .-]{1,64}$`)
	sourceNameRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
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

func (c *SQLConfig) validate(typ string) error {
	if len(c.Database) > 255 || !dbFileRE.MatchString(c.Database) || strings.Contains(c.Database, "..") {
		return errors.New("database is a file name under the loader data directory (letters, digits, _ . - and /; no ..)")
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
