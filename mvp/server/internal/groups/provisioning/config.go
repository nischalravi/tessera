package provisioning

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"text/template"

	"github.com/go-ldap/ldap/v3"
)

// Common is the configuration every target type shares (a provisioner's
// config JSON). The target-specific part is Target.
type Common struct {
	// AccountSystem is the accounts.system whose accounts the members are
	// translated through (an identity's account in the target).
	AccountSystem string `json:"account_system"`
	// GroupName is the template of the target group's name (default "{{.Name}}").
	GroupName string `json:"group_name"`
	// Attrs maps a target attribute to its template (LDAP attribute names, SCIM
	// "externalId"). Empty output omits the attribute.
	Attrs map[string]string `json:"attrs"`
	// MemberRef is the template of a member reference (default "{{.Username}}").
	MemberRef string          `json:"member_ref"`
	Target    json.RawMessage `json:"target"`
}

// Failsafe bounds what one run may delete (design §9.2). The zero value of a
// field is its default.
type Failsafe struct {
	// MaxDeletes is the most member removals one run may do (default 1000).
	MaxDeletes *int `json:"max_deletes,omitempty"`
	// MaxDeletePercent is the most removals as a percentage of the target's
	// memberships (default 2). It applies only to a target with at least
	// PercentFloor memberships, so a tiny target is not blocked by a single removal.
	MaxDeletePercent *float64 `json:"max_delete_percent,omitempty"`
	// MaxGroupDeletes is the most groups one run may delete (default 0: group
	// deletion needs approval).
	MaxGroupDeletes *int `json:"max_group_deletes,omitempty"`
}

// Failsafe defaults.
const (
	DefaultMaxDeletes       = 1000
	DefaultMaxDeletePercent = 2.0
	DefaultMaxGroupDeletes  = 0
	// PercentFloor is the smallest number of target memberships to which the
	// percentage limit applies.
	PercentFloor = 50
)

// Limits is a Failsafe with its defaults filled in.
type Limits struct {
	MaxDeletes       int
	MaxDeletePercent float64
	MaxGroupDeletes  int
}

// Resolve fills in the defaults.
func (f Failsafe) Resolve() Limits {
	l := Limits{MaxDeletes: DefaultMaxDeletes, MaxDeletePercent: DefaultMaxDeletePercent, MaxGroupDeletes: DefaultMaxGroupDeletes}
	if f.MaxDeletes != nil {
		l.MaxDeletes = *f.MaxDeletes
	}
	if f.MaxDeletePercent != nil {
		l.MaxDeletePercent = *f.MaxDeletePercent
	}
	if f.MaxGroupDeletes != nil {
		l.MaxGroupDeletes = *f.MaxGroupDeletes
	}
	return l
}

// Validate checks the limits' ranges.
func (f Failsafe) Validate() error {
	l := f.Resolve()
	switch {
	case l.MaxDeletes < 0 || l.MaxDeletes > 10_000_000:
		return cfgErr("failsafe.max_deletes must be from 0 to 10,000,000")
	case l.MaxDeletePercent < 0 || l.MaxDeletePercent > 100:
		return cfgErr("failsafe.max_delete_percent must be from 0 to 100")
	case l.MaxGroupDeletes < 0 || l.MaxGroupDeletes > 100_000:
		return cfgErr("failsafe.max_group_deletes must be from 0 to 100,000")
	}
	return nil
}

// ParseFailsafe decodes a failsafe JSON object (empty means all defaults).
func ParseFailsafe(raw []byte) (Failsafe, error) {
	var f Failsafe
	if len(bytes.TrimSpace(raw)) == 0 {
		return f, nil
	}
	if err := strictJSON(raw, &f); err != nil {
		return f, cfgErr("failsafe: %v", err)
	}
	return f, f.Validate()
}

// strictJSON decodes one JSON value, refusing unknown fields and trailing data.
func strictJSON(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("trailing data")
	}
	return nil
}

var (
	systemRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)
	attrKeyRE  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,62}$`)
	scheduleRE = regexp.MustCompile(`^(\d{1,2}) (\d{1,2}) \* \* \*$`)
)

// Compiled is a Common with its templates parsed.
type Compiled struct {
	Common
	name   *Tpl
	member *Tpl
	attrs  map[string]*Tpl
	// dnMember: the member reference is a DN (member and uniqueMember of an
	// ldap or ad target). Member then escapes the fields the template reads
	// (RFC 4514) and checks the DN keeps the shape the template gives it.
	dnMember bool
	// dnShape is the attribute types of the member_ref DN rendered with
	// placeholder values, one slice per RDN; nil when that is not a DN.
	dnShape [][]string
}

// MaxAttrs bounds the attributes of a group.
const MaxAttrs = 50

// ParseCommon decodes a provisioner's config JSON and compiles its templates.
func ParseCommon(raw []byte) (*Compiled, error) {
	var c Common
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, cfgErr("config is required")
	}
	if err := strictJSON(raw, &c); err != nil {
		return nil, cfgErr("config: %v", err)
	}
	if c.GroupName == "" {
		c.GroupName = "{{.Name}}"
	}
	if c.MemberRef == "" {
		c.MemberRef = "{{.Username}}"
	}
	if !systemRE.MatchString(c.AccountSystem) {
		return nil, cfgErr("account_system is required (the accounts.system the members are translated through)")
	}
	if len(c.Attrs) > MaxAttrs {
		return nil, cfgErr("attrs: at most %d attributes", MaxAttrs)
	}
	out := &Compiled{Common: c, attrs: map[string]*Tpl{}}
	var err error
	if out.name, err = ParseTemplate("group_name", c.GroupName); err != nil {
		return nil, err
	}
	if out.member, err = ParseTemplate("member_ref", c.MemberRef); err != nil {
		return nil, err
	}
	for k, src := range c.Attrs {
		if !attrKeyRE.MatchString(k) {
			return nil, cfgErr("attrs: %q is not an attribute name", k)
		}
		if out.attrs[k], err = ParseTemplate("attrs."+k, src); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// ParseCommonFor is ParseCommon for a provisioner of the target type: for an
// ldap or ad target whose member attribute holds DNs, the member_ref
// substitutions are DN-escaped (an unreadable target config counts as DN-valued,
// failing closed). ldapEscape in member_ref is then the identity, as the
// fields are already escaped.
func ParseCommonFor(typ string, raw []byte) (*Compiled, error) {
	c, err := ParseCommon(raw)
	if err != nil || (typ != TypeLDAP && typ != TypeAD) {
		return c, err
	}
	c.dnMember = true
	if cfg, perr := parseLDAPConfig(typ, c, Deps{AllowPlainLDAP: true}); perr == nil {
		c.dnMember = strings.EqualFold(cfg.MemberAttr, "member") || strings.EqualFold(cfg.MemberAttr, "uniqueMember")
	}
	if !c.dnMember {
		return c, nil
	}
	fm := template.FuncMap{}
	for k, v := range funcs {
		fm[k] = v
	}
	fm["ldapEscape"] = func(s string) string { return s }
	if c.member, err = parseTemplate("member_ref", c.MemberRef, fm); err != nil {
		return nil, err
	}
	if probe, err := c.member.Render(escapeMember(MemberData{Name: "x", Email: "x", Username: "x", ExternalID: "x"})); err == nil {
		c.dnShape = dnShapeOf(probe)
	}
	return c, nil
}

// escapeMember DN-escapes every string the member_ref template can read.
func escapeMember(m MemberData) MemberData {
	m.Name, m.Email, m.Username, m.ExternalID = EscapeDN(m.Name), EscapeDN(m.Email), EscapeDN(m.Username), EscapeDN(m.ExternalID)
	return m
}

// dnShapeOf is the attribute types of each RDN of dn, nil if dn is not a DN.
func dnShapeOf(dn string) [][]string {
	p, err := ldap.ParseDN(dn)
	if err != nil || len(p.RDNs) == 0 {
		return nil
	}
	out := make([][]string, len(p.RDNs))
	for i, r := range p.RDNs {
		for _, a := range r.Attributes {
			out[i] = append(out[i], strings.ToLower(a.Type))
		}
	}
	return out
}

// AttrKeys lists the managed attribute names, sorted.
func (c *Compiled) AttrKeys() []string {
	keys := make([]string, 0, len(c.attrs))
	for k := range c.attrs {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// Group translates a native group to its target name and attributes.
func (c *Compiled) Group(g GroupData) (string, map[string][]string, error) {
	name, err := c.name.Render(g)
	if err != nil {
		return "", nil, err
	}
	if name == "" {
		return "", nil, fmt.Errorf("group_name is empty for %s", g.Name)
	}
	attrs := map[string][]string{}
	for k, t := range c.attrs {
		v, err := t.Render(g)
		if err != nil {
			return "", nil, err
		}
		if v != "" {
			attrs[k] = []string{v}
		}
	}
	return name, attrs, nil
}

// Member translates an identity's account to a member reference.
func (c *Compiled) Member(m MemberData) (string, error) {
	if c.dnMember {
		m = escapeMember(m)
	}
	ref, err := c.member.Render(m)
	if err != nil {
		return "", err
	}
	if ref == "" {
		return "", fmt.Errorf("member_ref is empty for identity %d", m.IdentityID)
	}
	if c.dnMember && c.dnShape != nil && !slices.EqualFunc(dnShapeOf(ref), c.dnShape, slices.Equal[[]string]) {
		return "", fmt.Errorf("member_ref for identity %d does not keep the DN the template defines", m.IdentityID)
	}
	return ref, nil
}

// ValidSchedule reports whether s is "M H * * *" with a valid time of day.
func ValidSchedule(s string) bool {
	_, _, ok := ParseSchedule(s)
	return ok
}

// ParseSchedule reads the UTC minute and hour of a daily "M H * * *" schedule.
func ParseSchedule(s string) (minute, hour int, ok bool) {
	m := scheduleRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, 0, false
	}
	if _, err := fmt.Sscanf(m[1]+" "+m[2], "%d %d", &minute, &hour); err != nil {
		return 0, 0, false
	}
	return minute, hour, minute < 60 && hour < 24
}
