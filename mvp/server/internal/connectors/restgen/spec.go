// Package restgen is the generic REST connector (issue #552): any HTTP/JSON
// system becomes an identity source and a provisioning target from a
// declarative Spec, with no code.
//
// A Spec (JSON or YAML) holds the base URL, how to authenticate, the resources
// to read (users, groups, entitlements) with their pagination and a JSONPath
// field mapping, how group membership is expanded, and the write operations as
// request templates. It holds no secret: the credential is a separate sealed
// value (Secrets), so a Spec can be shown, logged and diffed.
//
// Safety properties:
//   - Every request goes through the *http.Client given to NewClient, which
//     must come from internal/safehttp (SSRF guard, address checks after DNS).
//   - The base URL is https (plain http only to loopback in dev). A pagination
//     link taken from a response must stay on the base URL's origin, so the
//     credential never follows a response to another host.
//   - Values that come from Tessera's records or from responses are never
//     concatenated into a URL: path parameters are escaped one segment at a
//     time, query values are encoded, and bodies are built as JSON values.
//   - Rate limited by a token bucket; 429 and Retry-After are honoured within
//     a bound; retries, pages, records, response size and time are all capped.
package restgen

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// DefaultSystem is the graph system name when the Spec names none.
const DefaultSystem = "rest"

// Auth types.
const (
	AuthOAuth2 = "oauth2_client_credentials"
	AuthAPIKey = "api_key"
	AuthBasic  = "basic"
	AuthBearer = "bearer"
)

// Pagination styles.
const (
	PageNone       = "none"
	PagePage       = "page"
	PageOffset     = "offset"
	PageCursor     = "cursor"
	PageLinkHeader = "link_header"
	PageNextURL    = "next_url"
)

// Spec configures one REST system.
type Spec struct {
	// System is the system name records carry ("rest" by default); lower-case letters, digits, "-" and "_".
	System  string            `json:"system,omitempty"`
	BaseURL string            `json:"base_url,omitempty"`
	Auth    Auth              `json:"auth"`
	Headers map[string]string `json:"headers,omitempty"`
	Limits  Limits            `json:"limits,omitempty"`
	// NoIdentities turns off the identity emitted per user, for when an HR system is the authority.
	NoIdentities bool `json:"no_identities,omitempty"`

	Users        *Resource `json:"users,omitempty"`
	Groups       *Resource `json:"groups,omitempty"`
	Entitlements *Resource `json:"entitlements,omitempty"`
	Writes       *Writes   `json:"writes,omitempty"`
}

// Auth says how requests authenticate. The secret half is in Secrets.
type Auth struct {
	Type string `json:"type"`
	// oauth2_client_credentials
	TokenURL   string   `json:"token_url,omitempty"`
	ClientID   string   `json:"client_id,omitempty"`
	Scopes     []string `json:"scopes,omitempty"`
	ClientAuth string   `json:"client_auth,omitempty"` // "basic" (default) or "body"
	// api_key: sent as header or query parameter Name; Prefix is put before the key in a header.
	In     string `json:"in,omitempty"`
	Name   string `json:"name,omitempty"`
	Prefix string `json:"prefix,omitempty"`
	// basic
	Username string `json:"username,omitempty"`
}

// Limits bound what the connector may do. Zero values take the default.
type Limits struct {
	RequestsPerSecond   float64 `json:"requests_per_second,omitempty"`    // token bucket refill (5)
	Burst               int     `json:"burst,omitempty"`                  // token bucket size (5)
	MaxAttempts         int     `json:"max_attempts,omitempty"`           // tries per request (4, at most 8)
	TimeoutSeconds      int     `json:"timeout_seconds,omitempty"`        // one request (15, at most 60)
	MaxResponseBytes    int64   `json:"max_response_bytes,omitempty"`     // one response (2 MiB, at most 8 MiB)
	MaxPages            int     `json:"max_pages,omitempty"`              // pages per listing (200, at most 1000)
	MaxRecords          int     `json:"max_records,omitempty"`            // records per listing (50000, at most 200000)
	MaxRetryWaitSeconds int     `json:"max_retry_wait_seconds,omitempty"` // longest Retry-After waited for (30, at most 120)
}

// Hard ceilings and defaults of Limits.
const (
	defRPS, maxRPS         = 5.0, 100.0
	defBurst, maxBurst     = 5, 100
	defAttempts, maxAtt    = 4, 8
	defTimeout, maxTimeout = 15, 60
	defBytes, maxBytes     = int64(2 << 20), int64(8 << 20)
	defPages, maxPages     = 200, 1000
	defRecords, maxRecords = 50000, 200000
	defWait, maxWait       = 30, 120
)

// norm returns l with defaults filled in.
func (l Limits) norm() Limits {
	if l.RequestsPerSecond <= 0 {
		l.RequestsPerSecond = defRPS
	}
	if l.Burst <= 0 {
		l.Burst = defBurst
	}
	if l.MaxAttempts <= 0 {
		l.MaxAttempts = defAttempts
	}
	if l.TimeoutSeconds <= 0 {
		l.TimeoutSeconds = defTimeout
	}
	if l.MaxResponseBytes <= 0 {
		l.MaxResponseBytes = defBytes
	}
	if l.MaxPages <= 0 {
		l.MaxPages = defPages
	}
	if l.MaxRecords <= 0 {
		l.MaxRecords = defRecords
	}
	if l.MaxRetryWaitSeconds <= 0 {
		l.MaxRetryWaitSeconds = defWait
	}
	return l
}

// Resource is one readable collection.
type Resource struct {
	// Path is the list endpoint, relative to the base URL ("/v1/users").
	Path  string            `json:"path"`
	Query map[string]string `json:"query,omitempty"`
	// ItemsPath is where the array of records is in the response ("$.data", "$.items[*]"); empty or "$" is the root.
	ItemsPath  string     `json:"items_path,omitempty"`
	Pagination Pagination `json:"pagination,omitempty"`
	// Fields maps a Tessera field to a JSONPath in one record (see userFields, groupFields).
	// A user field "attr.<name>" is kept as an account attribute.
	Fields map[string]string `json:"fields"`
	// ActiveValues are the status values that mean an enabled user (default: active, enabled, true, 1, yes).
	ActiveValues []string `json:"active_values,omitempty"`
	// PrivilegedValues are the values of the "privileged" field that mean true (default: true, yes, 1).
	PrivilegedValues []string `json:"privileged_values,omitempty"`
	// Members expands membership of a group or entitlement.
	Members *Members `json:"members,omitempty"`
}

// Members says how the users of a group or entitlement are found: either ids
// inside the group's own record (IDsPath), or a list endpoint per group (Path,
// with {id}). The ids are the users' "id" field.
type Members struct {
	IDsPath    string            `json:"ids_path,omitempty"`
	Path       string            `json:"path,omitempty"`
	Query      map[string]string `json:"query,omitempty"`
	ItemsPath  string            `json:"items_path,omitempty"`
	IDPath     string            `json:"id_path,omitempty"` // in each member record (default "$.id"; "$" when members are bare ids)
	Pagination Pagination        `json:"pagination,omitempty"`
}

// Pagination says how a listing is walked.
type Pagination struct {
	Style string `json:"style,omitempty"` // none (default), page, offset, cursor, link_header, next_url
	// PageSize is sent as SizeParam (page, offset, cursor styles).
	PageSize  int    `json:"page_size,omitempty"`
	SizeParam string `json:"size_param,omitempty"`
	// page: PageParam carries the page number, from StartPage (default 1).
	PageParam string `json:"page_param,omitempty"`
	StartPage int    `json:"start_page,omitempty"`
	// offset: OffsetParam carries the number of records already read.
	OffsetParam string `json:"offset_param,omitempty"`
	// cursor: CursorParam carries the token found at NextPath in the previous response; no token ends the walk.
	CursorParam string `json:"cursor_param,omitempty"`
	NextPath    string `json:"next_path,omitempty"`
	// next_url: NextPath is a JSONPath to the URL of the next page. link_header: the rel="next" Link.
}

// Writes are the operations that change the target, as request templates.
type Writes struct {
	// Lookup reads one user (GET): 2xx with the record, 404 when absent. The target reads it before
	// every write (so a repeated request converges) and again to verify.
	Lookup       *Operation `json:"lookup,omitempty"`
	Create       *Operation `json:"create,omitempty"`
	Update       *Operation `json:"update,omitempty"`
	Disable      *Operation `json:"disable,omitempty"`
	Delete       *Operation `json:"delete,omitempty"`
	AddMember    *Operation `json:"add_member,omitempty"`
	RemoveMember *Operation `json:"remove_member,omitempty"`
	// IsMember reads one membership (GET): 2xx when the user is in the group, 404 when not. Verification
	// of add_member and remove_member re-reads it.
	IsMember *Operation `json:"is_member,omitempty"`
}

// Operation is one request template.
type Operation struct {
	Method string `json:"method"`
	// Path is relative to the base URL. "{name}" is replaced by the escaped value of a variable.
	Path  string            `json:"path"`
	Query map[string]string `json:"query,omitempty"`
	// Body is a JSON value. A string "${name}" is replaced by the variable (an object member or array
	// element whose whole value is an unset variable is left out); "${a} ${b}" interpolates text.
	Body json.RawMessage `json:"body,omitempty"`
	// Expect lists the accepted statuses (default: any 2xx).
	Expect []int `json:"expect,omitempty"`
	// RecordPath, on lookup, is where the user record is in the response (default: the whole body).
	// The record is read with users.fields.
	RecordPath string `json:"record_path,omitempty"`
}

// Variables an operation template may use. attr.<name> is an update attribute.
const (
	varUsername    = "username"
	varExternalID  = "external_id"
	varEmail       = "email"
	varDisplayName = "display_name"
	varGroupID     = "group_id"
	varGroupName   = "group_name"
)

var (
	userVars  = []string{varUsername, varExternalID, varEmail, varDisplayName}
	groupVars = []string{varUsername, varExternalID, varEmail, varGroupID, varGroupName}

	userFields  = []string{"id", "username", "email", "display_name", "status", "department", "title", "created_at", "last_login_at"}
	groupFields = []string{"id", "name", "description", "privileged"}

	systemRE  = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	attrRE    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,63}$`)
	varRE     = regexp.MustCompile(`\$\{([A-Za-z0-9_.-]*)\}`)
	phRE      = regexp.MustCompile(`\{([^{}]*)\}`)
	hdrNameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,63}$`)
	// header names a static header may not use: they carry credentials or change routing
	forbiddenHdr = regexp.MustCompile(`(?i)auth|cookie|token|secret|key|password|^host$|^content-length$|^transfer-encoding$|^connection$|^x-tessera-`)
)

// FieldError is one problem in a Spec; Field is a dotted path ("users.fields.id").
type FieldError struct {
	Field string `json:"field"`
	Msg   string `json:"msg"`
}

func (e FieldError) Error() string { return e.Field + ": " + e.Msg }

// ErrorList is every problem found in a Spec.
type ErrorList []FieldError

func (l ErrorList) Error() string {
	parts := make([]string, len(l))
	for i, e := range l {
		parts[i] = e.Error()
	}
	return strings.Join(parts, "; ")
}

// ParseSpec decodes a Spec from JSON or YAML. Decoding is strict: an unknown
// field (a misspelt "pagination", or "password") is an error, so a secret can
// never ride in the Spec. It does not validate; call Validate.
func ParseSpec(raw []byte) (*Spec, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) > 0 && raw[0] == '"' { // a JSON string holding the YAML or JSON text
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			return nil, errors.New("rest config: not a valid string")
		}
		raw = bytes.TrimSpace([]byte(text))
	}
	if len(raw) == 0 {
		return nil, errors.New("rest config is empty")
	}
	if len(raw) > 256<<10 {
		return nil, errors.New("rest config is longer than 256 KiB")
	}
	if raw[0] != '{' {
		var doc any
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("rest config is neither JSON nor YAML: %v", err)
		}
		j, err := json.Marshal(doc)
		if err != nil {
			return nil, fmt.Errorf("rest config: %v", err)
		}
		raw = j
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var a specFields
	if err := dec.Decode(&a); err != nil {
		return nil, fmt.Errorf("rest config: %v", err)
	}
	if dec.More() {
		return nil, errors.New("rest config: trailing data")
	}
	s := Spec(a)
	return &s, nil
}

// specFields is Spec without its UnmarshalJSON, so ParseSpec can decode into it.
type specFields Spec

// UnmarshalJSON reads a Spec from a JSON object or from a string holding JSON or YAML, strictly,
// so a Spec can be a field of a larger JSON document (a connection's config).
func (s *Spec) UnmarshalJSON(b []byte) error {
	p, err := ParseSpec(b)
	if err != nil {
		return err
	}
	*s = *p
	return nil
}

// Validate checks a Spec and returns every problem, not just the first. rt
// decides what the base URL may be (https only in prod).
func (s *Spec) Validate(rt connsync.Runtime) ErrorList { return s.validate(rt, false) }

// ValidateShape is Validate without the environment's URL policy: the base and
// token URLs need only be well-formed http(s) URLs. It is for callers that do
// not know the environment (the readiness config check); whoever saves or
// runs the spec applies Validate.
func (s *Spec) ValidateShape() ErrorList { return s.validate(connsync.Runtime{}, true) }

// checkURL validates a configured URL: by the environment's policy, or for its shape only.
func checkURL(raw string, rt connsync.Runtime, shapeOnly bool) error {
	if !shapeOnly {
		_, err := connsync.ParseBaseURL(raw, rt)
		return err
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	switch {
	case err != nil || u.Host == "" || len(raw) > 512:
		return errors.New("base URL is not a valid URL")
	case u.Scheme != "https" && u.Scheme != "http":
		return errors.New("base URL must be https")
	case u.User != nil || u.RawQuery != "" || u.Fragment != "":
		return errors.New("base URL must not contain user info, a query or a fragment")
	}
	return nil
}

func (s *Spec) validate(rt connsync.Runtime, shapeOnly bool) ErrorList {
	var errs ErrorList
	bad := func(field, format string, a ...any) {
		errs = append(errs, FieldError{field, fmt.Sprintf(format, a...)})
	}

	if s.System != "" && !systemRE.MatchString(s.System) {
		bad("system", "must be lower-case letters, digits, - or _, up to 32 characters")
	}
	if err := checkURL(s.BaseURL, rt, shapeOnly); err != nil {
		bad("base_url", "%v", err)
	}
	s.validateAuth(rt, shapeOnly, bad)
	for k, v := range s.Headers {
		switch {
		case !hdrNameRE.MatchString(k):
			bad("headers."+k, "is not a header name")
		case forbiddenHdr.MatchString(k):
			bad("headers."+k, "carries a credential or routing; credentials belong in the sealed secrets, not in the config")
		case len(v) > 256 || strings.ContainsAny(v, "\r\n\x00"):
			bad("headers."+k, "value is too long or has control characters")
		}
	}
	l := s.Limits
	switch {
	case l.RequestsPerSecond < 0 || l.RequestsPerSecond > maxRPS:
		bad("limits.requests_per_second", "must be between 0 and %v", maxRPS)
	case l.Burst < 0 || l.Burst > maxBurst:
		bad("limits.burst", "must be between 0 and %d", maxBurst)
	case l.MaxAttempts < 0 || l.MaxAttempts > maxAtt:
		bad("limits.max_attempts", "must be between 1 and %d", maxAtt)
	case l.TimeoutSeconds < 0 || l.TimeoutSeconds > maxTimeout:
		bad("limits.timeout_seconds", "must be between 1 and %d", maxTimeout)
	case l.MaxResponseBytes < 0 || l.MaxResponseBytes > maxBytes:
		bad("limits.max_response_bytes", "must be between 1 and %d", maxBytes)
	case l.MaxPages < 0 || l.MaxPages > maxPages:
		bad("limits.max_pages", "must be between 1 and %d", maxPages)
	case l.MaxRecords < 0 || l.MaxRecords > maxRecords:
		bad("limits.max_records", "must be between 1 and %d", maxRecords)
	case l.MaxRetryWaitSeconds < 0 || l.MaxRetryWaitSeconds > maxWait:
		bad("limits.max_retry_wait_seconds", "must be between 1 and %d", maxWait)
	}
	if s.Users == nil && s.Groups == nil && s.Entitlements == nil && s.Writes == nil {
		bad("users", "configure at least one of users, groups, entitlements or writes")
	}
	if s.Users != nil {
		s.Users.validate("users", userFields, true, bad)
		if s.Users.Members != nil {
			bad("users.members", "users have no members")
		}
	}
	if s.Groups != nil {
		s.Groups.validate("groups", groupFields, false, bad)
	}
	if s.Entitlements != nil {
		s.Entitlements.validate("entitlements", groupFields, false, bad)
	}
	if (s.Groups != nil || s.Entitlements != nil) && s.Users == nil {
		bad("users", "groups and entitlements are expanded into membership of users: configure users too")
	}
	if s.Writes != nil {
		s.Writes.validate(s, bad)
	}
	sort.SliceStable(errs, func(i, j int) bool { return errs[i].Field < errs[j].Field })
	return errs
}

func (s *Spec) validateAuth(rt connsync.Runtime, shapeOnly bool, bad func(string, string, ...any)) {
	a := s.Auth
	switch a.Type {
	case AuthOAuth2:
		if err := checkURL(a.TokenURL, rt, shapeOnly); err != nil {
			bad("auth.token_url", "%v", strings.Replace(err.Error(), "base URL", "token URL", 1))
		} else if u, _ := url.Parse(a.TokenURL); u.Path == "" || u.Path == "/" {
			bad("auth.token_url", "must include the token endpoint path")
		}
		if a.ClientID == "" || len(a.ClientID) > 256 {
			bad("auth.client_id", "required (the client secret is a sealed secret)")
		}
		if a.ClientAuth != "" && a.ClientAuth != "basic" && a.ClientAuth != "body" {
			bad("auth.client_auth", "must be basic or body")
		}
		if len(a.Scopes) > 20 {
			bad("auth.scopes", "at most 20 scopes")
		}
		for _, sc := range a.Scopes {
			if sc == "" || strings.ContainsAny(sc, " \r\n") {
				bad("auth.scopes", "%q is not a scope", sc)
			}
		}
	case AuthAPIKey:
		if a.In != "header" && a.In != "query" {
			bad("auth.in", "must be header or query")
		}
		if !hdrNameRE.MatchString(a.Name) && !(a.In == "query" && attrRE.MatchString(a.Name)) {
			bad("auth.name", "must be the header or query parameter name")
		}
		if a.In == "query" && a.Prefix != "" {
			bad("auth.prefix", "applies to a header only")
		}
		if len(a.Prefix) > 32 || strings.ContainsAny(a.Prefix, "\r\n") {
			bad("auth.prefix", "is too long or has control characters")
		}
	case AuthBasic:
		if a.Username == "" || len(a.Username) > 256 || strings.Contains(a.Username, ":") {
			bad("auth.username", "required, without a colon (the password is a sealed secret)")
		}
	case AuthBearer:
	default:
		bad("auth.type", "must be one of %s, %s, %s, %s", AuthOAuth2, AuthAPIKey, AuthBasic, AuthBearer)
	}
}

func (r *Resource) validate(name string, fields []string, isUsers bool, bad func(string, string, ...any)) {
	if !safePath(r.Path) {
		bad(name+".path", "must start with / and have no ?, #, .. or //")
	} else if strings.ContainsAny(r.Path, "{}") {
		bad(name+".path", "a list endpoint takes no {placeholders}")
	}
	checkQuery(name+".query", r.Query, bad)
	checkPath(name+".items_path", r.ItemsPath, true, bad)
	r.Pagination.validate(name+".pagination", bad)
	if r.Fields["id"] == "" {
		bad(name+".fields.id", "required: a JSONPath to the record's stable id")
	}
	if isUsers && r.Fields["username"] == "" && r.Fields["email"] == "" {
		bad(name+".fields.username", "required (or map email): a JSONPath to the sign-in name")
	}
	if !isUsers && r.Fields["name"] == "" {
		bad(name+".fields.name", "required: a JSONPath to the display name")
	}
	for k, p := range r.Fields {
		if !slices.Contains(fields, k) && !(isUsers && strings.HasPrefix(k, "attr.") && attrRE.MatchString(k[5:])) {
			bad(name+".fields."+k, "is not a Tessera field (%s%s)", strings.Join(fields, ", "), map[bool]string{true: ", attr.<name>", false: ""}[isUsers])
			continue
		}
		checkPath(name+".fields."+k, p, false, bad)
	}
	if len(r.ActiveValues) > 20 || len(r.PrivilegedValues) > 20 {
		bad(name+".active_values", "at most 20 values")
	}
	if !isUsers && r.Fields["privileged"] == "" && len(r.PrivilegedValues) > 0 {
		bad(name+".privileged_values", "needs fields.privileged")
	}
	if m := r.Members; m != nil {
		mn := name + ".members"
		switch {
		case m.IDsPath == "" && m.Path == "":
			bad(mn, "set ids_path (ids inside the record) or path (a list endpoint per record, with {id})")
		case m.IDsPath != "" && m.Path != "":
			bad(mn, "set ids_path or path, not both")
		}
		checkPath(mn+".ids_path", m.IDsPath, true, bad)
		if m.Path != "" {
			if !safePath(m.Path) {
				bad(mn+".path", "must start with / and have no ?, #, .. or //")
			}
			for _, ph := range phRE.FindAllStringSubmatch(m.Path, -1) {
				if ph[1] != "id" {
					bad(mn+".path", "only {id} is a placeholder here, not {%s}", ph[1])
				}
			}
			if !strings.Contains(m.Path, "{id}") {
				bad(mn+".path", "must contain {id}, the id of the group")
			}
		}
		checkQuery(mn+".query", m.Query, bad)
		checkPath(mn+".items_path", m.ItemsPath, true, bad)
		checkPath(mn+".id_path", m.IDPath, true, bad)
		m.Pagination.validate(mn+".pagination", bad)
	}
}

func (p *Pagination) validate(name string, bad func(string, string, ...any)) {
	need := func(field, v string) {
		if v == "" {
			bad(name+"."+field, "required for style %s", p.Style)
		} else if !attrRE.MatchString(v) {
			bad(name+"."+field, "is not a query parameter name")
		}
	}
	if p.PageSize < 0 || p.PageSize > 1000 {
		bad(name+".page_size", "must be between 1 and 1000")
	}
	if p.StartPage < 0 || p.StartPage > 1000000 {
		bad(name+".start_page", "is out of range")
	}
	switch p.Style {
	case "", PageNone:
	case PagePage:
		need("page_param", p.PageParam)
		need("size_param", p.SizeParam)
		if p.PageSize == 0 {
			bad(name+".page_size", "required for style page: a short page is how the last page is recognised")
		}
	case PageOffset:
		need("offset_param", p.OffsetParam)
		need("size_param", p.SizeParam)
		if p.PageSize == 0 {
			bad(name+".page_size", "required for style offset: a short page is how the last page is recognised")
		}
	case PageCursor:
		need("cursor_param", p.CursorParam)
		if p.NextPath == "" {
			bad(name+".next_path", "required for style cursor: a JSONPath to the next cursor")
		}
		if p.SizeParam != "" && !attrRE.MatchString(p.SizeParam) {
			bad(name+".size_param", "is not a query parameter name")
		}
	case PageLinkHeader:
	case PageNextURL:
		if p.NextPath == "" {
			bad(name+".next_path", "required for style next_url: a JSONPath to the next page's URL")
		}
	default:
		bad(name+".style", "must be one of none, page, offset, cursor, link_header, next_url")
	}
	checkPath(name+".next_path", p.NextPath, true, bad)
}

func (w *Writes) ops() map[string]*Operation {
	return map[string]*Operation{"lookup": w.Lookup, "create": w.Create, "update": w.Update, "disable": w.Disable,
		"delete": w.Delete, "add_member": w.AddMember, "remove_member": w.RemoveMember, "is_member": w.IsMember}
}

func (w *Writes) validate(s *Spec, bad func(string, string, ...any)) {
	for name, op := range w.ops() {
		if op == nil {
			continue
		}
		vars := userVars
		if strings.HasSuffix(name, "member") {
			vars = groupVars
		}
		op.validate("writes."+name, name, vars, bad)
	}
	userOp := w.Create != nil || w.Update != nil || w.Disable != nil || w.Delete != nil
	if userOp && w.Lookup == nil {
		bad("writes.lookup", "required with create, update, disable or delete: the target is read before a write and again to verify")
	}
	if (w.AddMember != nil || w.RemoveMember != nil) && w.IsMember == nil {
		bad("writes.is_member", "required with add_member or remove_member, to verify the change")
	}
	if w.Lookup != nil && s.Users == nil {
		bad("users", "required with writes.lookup: its fields map the record that is read back")
	}
}

func (o *Operation) validate(name, kind string, vars []string, bad func(string, string, ...any)) {
	allowed := func(v string) bool {
		return slices.Contains(vars, v) || (strings.HasPrefix(v, "attr.") && attrRE.MatchString(v[5:]) && kind == "update") ||
			(kind == "create" && strings.HasPrefix(v, "attr.") && attrRE.MatchString(v[5:]))
	}
	switch o.Method {
	case "GET":
		if len(o.Body) > 0 {
			bad(name+".body", "a GET has no body")
		}
	case "POST", "PUT", "PATCH", "DELETE":
	default:
		bad(name+".method", "must be GET, POST, PUT, PATCH or DELETE")
	}
	if (kind == "lookup" || kind == "is_member") && o.Method != "GET" {
		bad(name+".method", "a read must be a GET")
	}
	if kind != "lookup" && kind != "is_member" && o.Method == "GET" {
		bad(name+".method", "a write cannot be a GET")
	}
	if !safePath(o.Path) {
		bad(name+".path", "must start with / and have no ?, #, .. or //")
	}
	for _, ph := range phRE.FindAllStringSubmatch(o.Path, -1) {
		if !allowed(ph[1]) {
			bad(name+".path", "{%s} is not a variable here (%s)", ph[1], strings.Join(vars, ", "))
		}
	}
	if strings.ContainsAny(phRE.ReplaceAllString(o.Path, ""), "{}") {
		bad(name+".path", "has an unbalanced { or }")
	}
	checkQuery(name+".query", o.Query, bad)
	for k, v := range o.Query {
		for _, m := range varRE.FindAllStringSubmatch(v, -1) {
			if !allowed(m[1]) {
				bad(name+".query."+k, "${%s} is not a variable here", m[1])
			}
		}
	}
	if len(o.Body) > 0 {
		var tree any
		if err := json.Unmarshal(o.Body, &tree); err != nil {
			bad(name+".body", "is not valid JSON: %v", err)
		} else {
			walkStrings(tree, func(str string) {
				for _, m := range varRE.FindAllStringSubmatch(str, -1) {
					if !allowed(m[1]) {
						bad(name+".body", "${%s} is not a variable here (%s)", m[1], strings.Join(vars, ", "))
					}
				}
			})
		}
		if len(o.Body) > 16<<10 {
			bad(name+".body", "is longer than 16 KiB")
		}
	}
	for _, c := range o.Expect {
		if c < 200 || c > 299 {
			bad(name+".expect", "%d is not a 2xx status", c)
		}
	}
	checkPath(name+".record_path", o.RecordPath, true, bad)
	if o.RecordPath != "" && kind != "lookup" {
		bad(name+".record_path", "applies to lookup only")
	}
}

func walkStrings(v any, fn func(string)) {
	switch t := v.(type) {
	case string:
		fn(t)
	case []any:
		for _, e := range t {
			walkStrings(e, fn)
		}
	case map[string]any:
		for _, e := range t {
			walkStrings(e, fn)
		}
	}
}

func checkPath(field, p string, optional bool, bad func(string, string, ...any)) {
	if p == "" {
		if !optional {
			bad(field, "required")
		}
		return
	}
	if _, err := CompilePath(p); err != nil {
		bad(field, "%v", err)
	}
}

func checkQuery(field string, q map[string]string, bad func(string, string, ...any)) {
	if len(q) > 20 {
		bad(field, "at most 20 parameters")
	}
	for k, v := range q {
		if !attrRE.MatchString(k) {
			bad(field+"."+k, "is not a query parameter name")
		}
		if len(v) > 256 {
			bad(field+"."+k, "value is longer than 256 characters")
		}
	}
}

// safePath reports whether p is an absolute path fit for a template: no
// query, fragment, dot segments or empty segments, no control characters.
func safePath(p string) bool {
	if !strings.HasPrefix(p, "/") || len(p) > 256 || strings.ContainsAny(p, "?#\\ \x00\r\n\t%") {
		return false
	}
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == ".." || seg == "." {
			return false
		}
	}
	return !strings.Contains(p, "//")
}

// SecretDestination names everything that decides where the credential is sent and how: the origins of the base
// URL and the token URL, the auth type, the header or query parameter (with its prefix), and the client id or
// user name. Two specs with the same destination send a stored secret to the same place the same way; when it
// differs, the secret must be entered again, or whoever edits the config could point a stored credential at a
// host or field of their choosing.
func (s *Spec) SecretDestination() string {
	origin := func(raw string) string {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Host == "" {
			return ""
		}
		port := u.Port()
		if port == "" {
			port = map[string]string{"https": "443", "http": "80"}[strings.ToLower(u.Scheme)]
		}
		return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Hostname()) + ":" + port
	}
	a := s.Auth
	return strings.Join([]string{origin(s.BaseURL), a.Type, origin(a.TokenURL), a.In, strings.ToLower(a.Name), a.Prefix, a.ClientID, a.Username}, "|")
}

// DestinationOf is SecretDestination of a stored spec (JSON); "" when it cannot be read.
func DestinationOf(raw []byte) string {
	if len(bytes.TrimSpace(raw)) == 0 {
		return ""
	}
	s, err := ParseSpec(raw)
	if err != nil {
		return ""
	}
	return s.SecretDestination()
}
