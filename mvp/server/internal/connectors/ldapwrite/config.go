package ldapwrite

import (
	"crypto/x509"
	"errors"
	"slices"
	"sort"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
)

// Flavors of directory.
const (
	FlavorLDAP = "ldap"
	FlavorAD   = "ad"
)

// Ways an account is disabled.
const (
	DisableUAC          = "uac"           // AD: userAccountControl bit 2
	DisableNSAccountLck = "nsaccountlock" // 389-DS and other Netscape-lineage servers
	DisablePPolicy      = "ppolicy"       // OpenLDAP ppolicy: pwdAccountLockedTime
	DisableAttribute    = "attribute"     // a configured attribute and value
)

// ppolicyPermanentLock is the value that locks an account until it is cleared (draft-behera-ldap-password-policy).
const ppolicyPermanentLock = "000001010000Z"

// Config describes one LDAP or AD provisioning target. It holds no secret: the bind password is the
// target's sealed credential. Every name and template in it is validated by Validate.
type Config struct {
	Flavor string `json:"flavor"`
	Host   string `json:"host"`
	Port   int    `json:"port,omitempty"` // 636 (LDAPS, the default) or 389 (StartTLS)
	BindDN string `json:"bind_dn"`
	// CACertPEM is the directory's private CA, when its certificate is not publicly trusted.
	CACertPEM string `json:"ca_cert_pem,omitempty"`

	// WriteScope names the OUs the target may change entries under (each DN written must be
	// strictly below one). It is required: there is no default scope.
	WriteScope []string `json:"write_scope"`
	// UserBase is where accounts are searched for.
	UserBase string `json:"user_base"`
	// UserDNTemplate is the DN of a new account, e.g. uid=${account},ou=People,dc=acme,dc=com.
	UserDNTemplate string `json:"user_dn_template"`
	// UserObjectClasses default by flavor.
	UserObjectClasses []string `json:"user_object_classes,omitempty"`
	// UserAttrs maps an attribute to its template, e.g. {"mail": "${user.email}", "uid": "${account}"}.
	UserAttrs map[string]string `json:"user_attrs"`
	// MatchAttr is the key of UserAttrs that ties a directory entry to the request (employeeNumber
	// or mail). Its template may not use ${account}.
	MatchAttr string `json:"match_attr"`
	// AccountNames are candidate names for ${account} in the style of Saviynt's ACCOUNTNAMERULE:
	// each is tried in order until one is unique. Default: ${user.username}.
	AccountNames []string `json:"account_names,omitempty"`
	// UniqueAttrs are checked for uniqueness across UserBase before a create (CHECKFORUNIQUE).
	UniqueAttrs []string `json:"unique_attrs,omitempty"`
	// UpdateAttrs is the allow-list of attributes update_account may set.
	UpdateAttrs []string `json:"update_attrs,omitempty"`
	// CreateDisabled creates the account disabled.
	CreateDisabled bool `json:"create_disabled,omitempty"`
	// InitialPassword gives a new account a random password from Password (never shown or stored;
	// the account must change it at next sign-in where the directory supports that).
	InitialPassword bool           `json:"initial_password,omitempty"`
	Password        PasswordPolicy `json:"password,omitempty"`
	// AllowPasswordReset lets update_account set a new random password (attrs {"tessera.password": "reset"}).
	AllowPasswordReset bool `json:"allow_password_reset,omitempty"`

	DisableMode  string `json:"disable_mode,omitempty"`
	DisableAttr  string `json:"disable_attr,omitempty"`  // DisableAttribute only
	DisableValue string `json:"disable_value,omitempty"` // DisableAttribute only (default TRUE)
	// DisabledOU, when set, is where a disabled account is moved; EnabledOU is where an enabled one is
	// moved back to. Both must be below a write-scope OU and inside UserBase.
	DisabledOU string `json:"disabled_ou,omitempty"`
	EnabledOU  string `json:"enabled_ou,omitempty"`

	// Groups. GroupBase is searched for a group by cn; GroupDNTemplate (with ${group.name}) names one directly.
	GroupBase       string `json:"group_base,omitempty"`
	GroupDNTemplate string `json:"group_dn_template,omitempty"`
	// GroupMemberAttr is member (default), uniqueMember or memberUid.
	GroupMemberAttr string `json:"group_member_attr,omitempty"`
	// MemberUIDAttr is the account attribute memberUid holds (default uid; sAMAccountName for AD).
	MemberUIDAttr string `json:"member_uid_attr,omitempty"`
}

// Validate normalizes the config (defaults) and reports why it cannot be used. Messages are fixed
// text: they never carry what was submitted.
func (c *Config) Validate() error {
	bad := func(msg string) error { return errors.New(msg) }
	switch c.Flavor {
	case FlavorLDAP, FlavorAD:
	default:
		return bad("flavor must be ldap or ad")
	}
	if c.Port == 0 {
		c.Port = 636
	}
	if c.Port != 636 && c.Port != 389 {
		return bad("port must be 636 (LDAPS) or 389 (StartTLS); a directory connection is always encrypted")
	}
	if c.Host == "" || len(c.Host) > 253 || strings.ContainsAny(c.Host, "/@ \t\r\n:") {
		return bad("host must be a host name")
	}
	if !validDN(c.BindDN) {
		return bad("bind_dn is not a distinguished name")
	}
	if len(c.WriteScope) == 0 || len(c.WriteScope) > 20 {
		return bad("write_scope must name one to twenty OUs")
	}
	for _, ou := range c.WriteScope {
		if !validDN(ou) {
			return bad("write_scope holds a name that is not a distinguished name")
		}
	}
	if !validDN(c.UserBase) {
		return bad("user_base is not a distinguished name")
	}
	ut, err := ParseTemplate(c.UserDNTemplate)
	if err != nil {
		return bad("user_dn_template is not a valid template")
	}
	probe, err := ut.RenderDN(probeVars(ut))
	if err != nil || !c.InScope(probe) {
		return bad("user_dn_template must produce a name below a write_scope OU")
	}
	if len(c.UserObjectClasses) == 0 {
		c.UserObjectClasses = []string{"top", "person", "organizationalPerson", "inetOrgPerson"}
		if c.Flavor == FlavorAD {
			c.UserObjectClasses = []string{"top", "person", "organizationalPerson", "user"}
		}
	}
	for _, oc := range c.UserObjectClasses {
		if !attrNameRE.MatchString(oc) {
			return bad("user_object_classes holds a name that is not an object class")
		}
	}
	if len(c.UserAttrs) == 0 || len(c.UserAttrs) > 40 {
		return bad("user_attrs must hold one to forty attributes")
	}
	for a, tpl := range c.UserAttrs {
		t, err := ParseTemplate(tpl)
		if !attrNameRE.MatchString(a) || protectedAttrs[strings.ToLower(a)] || err != nil {
			return bad("user_attrs holds an attribute that is protected or has an invalid template")
		}
		if strings.EqualFold(a, c.MatchAttr) && slices.Contains(t.Refs(), "account") {
			return bad("the match_attr template cannot use the account name")
		}
		if slices.ContainsFunc(t.Refs(), func(r string) bool { return strings.HasPrefix(r, "group.") }) {
			return bad("user_attrs templates cannot use group values")
		}
	}
	if c.attrKey(c.MatchAttr) == "" {
		return bad("match_attr must be one of user_attrs")
	}
	if len(c.AccountNames) == 0 {
		c.AccountNames = []string{"${user.username}"}
	}
	if len(c.AccountNames) > 10 {
		return bad("account_names holds at most ten candidates")
	}
	for _, n := range c.AccountNames {
		t, err := ParseTemplate(n)
		if err != nil || slices.Contains(t.Refs(), "account") || slices.ContainsFunc(t.Refs(), func(r string) bool { return strings.HasPrefix(r, "group.") }) {
			return bad("account_names holds an invalid candidate template")
		}
	}
	for _, a := range c.UniqueAttrs {
		if c.attrKey(a) == "" {
			return bad("unique_attrs must be among user_attrs")
		}
	}
	for _, a := range c.UpdateAttrs {
		if !attrNameRE.MatchString(a) || protectedAttrs[strings.ToLower(a)] {
			return bad("update_attrs holds an attribute that is protected or not a name")
		}
	}
	if msg := c.Password.Validate(); msg != "" {
		return errors.New(msg)
	}
	if err := c.validateDisable(); err != nil {
		return err
	}
	return c.validateGroups()
}

func (c *Config) validateDisable() error {
	if c.DisableMode == "" {
		c.DisableMode = DisableNSAccountLck
		if c.Flavor == FlavorAD {
			c.DisableMode = DisableUAC
		}
	}
	switch c.DisableMode {
	case DisableUAC:
		if c.Flavor != FlavorAD {
			return errors.New("disable_mode uac is for Active Directory")
		}
	case DisableNSAccountLck, DisablePPolicy:
	case DisableAttribute:
		if !attrNameRE.MatchString(c.DisableAttr) || protectedAttrs[strings.ToLower(c.DisableAttr)] {
			return errors.New("disable_attr must be an attribute name that is not protected")
		}
		if c.DisableValue == "" {
			c.DisableValue = "TRUE"
		}
		if !cleanValue(c.DisableValue) {
			return errors.New("disable_value is not a valid value")
		}
	default:
		return errors.New("disable_mode must be uac, nsaccountlock, ppolicy or attribute")
	}
	for _, ou := range []string{c.DisabledOU, c.EnabledOU} {
		if ou != "" && (!validDN(ou) || !(c.InScope(ou) || c.writeRoot(ou)) || !(dnBelow(ou, c.UserBase) || sameDN(ou, c.UserBase))) {
			return errors.New("disabled_ou and enabled_ou must be below a write_scope OU and inside user_base")
		}
	}
	return nil
}

func (c *Config) validateGroups() error {
	if c.GroupMemberAttr == "" {
		c.GroupMemberAttr = "member"
	}
	if !slices.Contains([]string{"member", "uniqueMember", "memberUid"}, c.GroupMemberAttr) {
		return errors.New("group_member_attr must be member, uniqueMember or memberUid")
	}
	if c.MemberUIDAttr == "" {
		c.MemberUIDAttr = "uid"
		if c.Flavor == FlavorAD {
			c.MemberUIDAttr = "sAMAccountName"
		}
	}
	if !attrNameRE.MatchString(c.MemberUIDAttr) {
		return errors.New("member_uid_attr is not an attribute name")
	}
	if c.GroupBase != "" && (!validDN(c.GroupBase) || !(c.InScope(c.GroupBase) || c.writeRoot(c.GroupBase))) {
		return errors.New("group_base must be a distinguished name inside a write_scope OU")
	}
	if c.GroupDNTemplate != "" {
		t, err := ParseTemplate(c.GroupDNTemplate)
		if err != nil || slices.ContainsFunc(t.Refs(), func(r string) bool { return !strings.HasPrefix(r, "group.") }) {
			return errors.New("group_dn_template may use only group values")
		}
		probe, err := t.RenderDN(probeVars(t))
		if err != nil || !c.InScope(probe) {
			return errors.New("group_dn_template must produce a name below a write_scope OU")
		}
	}
	return nil
}

func validDN(dn string) bool {
	if dn == "" || len(dn) > maxTemplate || strings.ContainsAny(dn, "\x00\r\n") {
		return false
	}
	d, err := goldap.ParseDN(dn)
	return err == nil && len(d.RDNs) > 0
}

// probeVars gives every placeholder of t a plain value, to check the shape of a template.
func probeVars(t *Template) Vars {
	v := Vars{User: map[string]string{}, Group: map[string]string{}, Account: "x"}
	for _, r := range t.Refs() {
		switch {
		case strings.HasPrefix(r, "user."):
			v.User[r[len("user."):]] = "x"
		case strings.HasPrefix(r, "group."):
			v.Group[r[len("group."):]] = "x"
		}
	}
	return v
}

// attrKey is the configured spelling of a UserAttrs key matching name ("" if none).
func (c *Config) attrKey(name string) string {
	for k := range c.UserAttrs {
		if strings.EqualFold(k, name) {
			return k
		}
	}
	return ""
}

func (c *Config) sortedAttrs() []string {
	keys := make([]string, 0, len(c.UserAttrs))
	for k := range c.UserAttrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// writeRoot reports whether dn is itself one of the write-scope OUs.
func (c *Config) writeRoot(dn string) bool {
	return slices.ContainsFunc(c.WriteScope, func(ou string) bool { return sameDN(dn, ou) })
}

// CAPool parses a PEM bundle for a target's private CA.
func CAPool(pem string) (*x509.CertPool, error) {
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM([]byte(pem)) {
		return nil, errors.New("the CA bundle holds no PEM certificate")
	}
	return p, nil
}
