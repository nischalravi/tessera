package provisioning

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
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
	ref, err := c.member.Render(m)
	if err != nil {
		return "", err
	}
	if ref == "" {
		return "", fmt.Errorf("member_ref is empty for identity %d", m.IdentityID)
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
