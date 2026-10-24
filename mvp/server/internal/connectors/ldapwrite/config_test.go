package ldapwrite

import (
	"bytes"
	"crypto/rand"
	"io"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
)

func validConfig() Config {
	return Config{Flavor: "ldap", Host: "ldap.acme.example", BindDN: "cn=svc,dc=acme,dc=example",
		WriteScope: []string{"ou=People,dc=acme,dc=example"}, UserBase: "ou=People,dc=acme,dc=example",
		UserDNTemplate: "uid=${account},ou=People,dc=acme,dc=example",
		UserAttrs:      map[string]string{"uid": "${account}", "employeeNumber": "${user.external_id}"}, MatchAttr: "employeeNumber"}
}

func TestConfigValidate(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*Config)
		want string // fragment of the error, "" for valid
	}{
		{"valid", func(*Config) {}, ""},
		{"plain ldap port", func(c *Config) { c.Port = 3389 }, "encrypted"},
		{"no scope", func(c *Config) { c.WriteScope = nil }, "write_scope"},
		{"template outside scope", func(c *Config) { c.UserDNTemplate = "uid=${account},ou=Admins,dc=acme,dc=example" }, "below a write_scope"},
		{"scope root itself", func(c *Config) { c.UserDNTemplate = "ou=People,dc=acme,dc=example" }, "below a write_scope"},
		{"unknown placeholder", func(c *Config) { c.UserAttrs["mail"] = "${env.HOME}" }, "protected or has an invalid"},
		{"protected attribute", func(c *Config) { c.UserAttrs["userPassword"] = "${user.email}" }, "protected"},
		{"match attr uses account", func(c *Config) { c.UserAttrs["employeeNumber"] = "${account}" }, "match_attr"},
		{"match attr missing", func(c *Config) { c.MatchAttr = "mail" }, "match_attr"},
		{"update attr protected", func(c *Config) { c.UpdateAttrs = []string{"memberOf"} }, "update_attrs"},
		{"uac on ldap", func(c *Config) { c.DisableMode = "uac" }, "Active Directory"},
		{"bad member attr", func(c *Config) { c.GroupMemberAttr = "owner" }, "group_member_attr"},
		{"disabled ou outside scope", func(c *Config) { c.DisabledOU = "ou=Out,dc=acme,dc=example" }, "disabled_ou"},
		{"bad password policy", func(c *Config) { c.Password = PasswordPolicy{MinLength: 4} }, "password length"},
		{"bad flavor", func(c *Config) { c.Flavor = "x" }, "flavor"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			tc.mut(&c)
			err := c.Validate()
			switch {
			case tc.want == "" && err != nil:
				t.Fatal(err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRenderDN(t *testing.T) {
	tpl, err := ParseTemplate("uid=${user.username},ou=People,dc=acme,dc=example")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		value string
		ok    bool
	}{
		{"bob", true}, {"o'brien", true}, {"a,b", true}, {"a+b", true}, {`a"b`, true}, {"#lead", true}, {" pad ", true},
		{"", false}, {"a\nb", false}, {"a\x00b", false}, {strings.Repeat("a", 300), false},
	} {
		dn, err := tpl.RenderDN(Vars{User: map[string]string{"username": tc.value}})
		if (err == nil) != tc.ok {
			t.Errorf("%q: err %v, want ok=%t", tc.value, err, tc.ok)
			continue
		}
		if err == nil && !dnBelow(dn, "ou=People,dc=acme,dc=example") {
			t.Errorf("%q rendered %q, outside People", tc.value, dn)
		}
		if err == nil && parentDN(dn) != "ou=People,dc=acme,dc=example" {
			t.Errorf("%q rendered %q with another parent %q", tc.value, dn, parentDN(dn))
		}
	}
	for _, bad := range []string{"${user.}", "${x", "${user.a b}", "${group.name}x${", ""} {
		if _, err := ParseTemplate(bad); err == nil {
			t.Errorf("template %q parsed", bad)
		}
	}
}

func TestEqFilterEscapes(t *testing.T) {
	f, err := EqFilter("uid", "*)(uid=*")
	if err != nil || f != `(uid=\2a\29\28uid=\2a)` {
		t.Errorf("%q %v", f, err)
	}
	if _, err := EqFilter("u id)", "x"); err == nil {
		t.Error("a bad attribute name was accepted")
	}
}

func TestDNHelpers(t *testing.T) {
	root := "OU=People, DC=Acme,dc=example"
	for dn, want := range map[string]bool{"uid=a,ou=people,dc=acme,dc=example": true, "uid=a,ou=x,ou=people,dc=acme,dc=example": true,
		"ou=people,dc=acme,dc=example": false, "uid=a,ou=other,dc=acme,dc=example": false, "garbage": false} {
		if dnBelow(dn, root) != want {
			t.Errorf("dnBelow(%q) = %t", dn, !want)
		}
	}
}

func TestGeneratePassword(t *testing.T) {
	p := PasswordPolicy{MinLength: 20, MaxLength: 24, MinUpper: 3, MinDigits: 3, MinSpecial: 2}
	seen := map[string]bool{}
	for range 50 {
		s, err := GeneratePassword(p, randReader())
		if err != nil {
			t.Fatal(err)
		}
		pw := s.Reveal()
		var up, dg, sp int
		for _, r := range pw {
			switch {
			case r >= 'A' && r <= 'Z':
				up++
			case r >= '0' && r <= '9':
				dg++
			case strings.ContainsRune(specialSet, r):
				sp++
			}
		}
		if len(pw) < 20 || len(pw) > 24 || up < 3 || dg < 3 || sp < 2 {
			t.Fatalf("password %q does not meet the policy", pw)
		}
		seen[pw] = true
	}
	if len(seen) != 50 {
		t.Error("passwords repeat")
	}
	s, _ := GeneratePassword(p, randReader())
	if strings.Contains(strings.Join([]string{s.String()}, ""), s.Reveal()) {
		t.Error("the secret prints")
	}
	for _, bad := range []PasswordPolicy{{MinLength: 4}, {MinLength: 10, MinUpper: 6, MinDigits: 6}, {MinLength: 20, MaxLength: 10}} {
		if _, err := GeneratePassword(bad, randReader()); err == nil {
			t.Errorf("policy %+v accepted", bad)
		}
	}
}

func TestUnicodePwd(t *testing.T) {
	got := UnicodePwd("Ab")
	want := []byte{'"', 0, 'A', 0, 'b', 0, '"', 0}
	if !bytes.Equal(got, want) {
		t.Errorf("% x", got)
	}
}

var _ = target.CreateAccount

func randReader() io.Reader { return rand.Reader }

func TestProtectedAttrsPerFlavor(t *testing.T) {
	for _, tc := range []struct {
		flavor, attr string
		create       bool
		want         bool
	}{
		{"ad", "nTSecurityDescriptor", true, true}, {"ad", "MSDS-KEYCREDENTIALLINK", true, true},
		{"ad", "msDS-AllowedToActOnBehalfOfOtherIdentity", false, true}, {"ad", "msDS-AllowedToDelegateTo", true, true},
		{"ad", "servicePrincipalName", true, true}, {"ad", "altSecurityIdentities", false, true}, {"ad", "sIDHistory", true, true},
		{"ad", "adminCount", true, true}, {"ad", "scriptPath", false, true}, {"ad", "userCertificate", true, true},
		{"ad", "primaryGroupID", true, true}, {"ad", "userPrincipalName", true, false}, {"ad", "USERPRINCIPALNAME", false, true},
		{"ad", "uidNumber", true, false}, {"ad", "mail", false, false},
		{"ldap", "uidNumber", true, true}, {"ldap", "GIDNUMBER", false, true}, {"ldap", "authPassword", true, true},
		{"ldap", "sambaNTPassword", true, true}, {"ldap", "sambaLMPassword", true, true}, {"ldap", "sshPublicKey", false, true},
		{"ldap", "homeDirectory", true, true}, {"ldap", "loginShell", true, true},
		{"ldap", "servicePrincipalName", true, false}, {"ldap", "userPrincipalName", false, false}, {"ldap", "mail", true, false},
		{"ldap", "userPassword", true, true}, {"ad", "unicodePwd", true, true},
	} {
		if got := isProtected(tc.flavor, tc.attr, tc.create); got != tc.want {
			t.Errorf("isProtected(%s, %s, create=%t) = %t", tc.flavor, tc.attr, tc.create, got)
		}
	}
	// the config refuses them in templates, the update allow-list and the disable attribute
	c := validConfig()
	c.Flavor = "ad"
	c.DisableMode = "attribute"
	c.UserAttrs["userPrincipalName"] = "${user.email}"
	c.DisableAttr = "carLicense"
	if err := c.Validate(); err != nil {
		t.Fatalf("a UPN template on create: %v", err)
	}
	for name, mut := range map[string]func(*Config){
		"update upn":  func(c *Config) { c.UpdateAttrs = []string{"UserPrincipalName"} },
		"update spn":  func(c *Config) { c.UpdateAttrs = []string{"servicePrincipalName"} },
		"create sd":   func(c *Config) { c.UserAttrs["nTSecurityDescriptor"] = "x" },
		"disable sid": func(c *Config) { c.DisableAttr = "sIDHistory" },
	} {
		cc := validConfig()
		cc.Flavor, cc.DisableMode, cc.DisableAttr = "ad", "attribute", "carLicense"
		mut(&cc)
		if cc.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	l := validConfig()
	l.UserAttrs["loginShell"] = "/bin/sh"
	if l.Validate() == nil {
		t.Error("loginShell accepted on an LDAP target")
	}
}

func TestReservedWriteScope(t *testing.T) {
	for scope, reserved := range map[string]bool{
		"dc=acme,dc=example": true, "DC=acme": true,
		"cn=Users,dc=acme,dc=example": true, "CN=Builtin,DC=acme,DC=example": true, "cn=System,dc=acme,dc=example": true,
		"cn=Configuration,dc=acme,dc=example": true, "OU=Domain Controllers,DC=acme,DC=example": true,
		"ou=Sub,cn=Users,dc=acme,dc=example": true, "cn=Policies,cn=System,dc=acme,dc=example": true,
		"ou=People,dc=acme,dc=example": false, "ou=Users,dc=acme,dc=example": false, "ou=Staff,ou=Domain Controllers2,dc=acme,dc=example": false,
	} {
		if got := reservedScope(scope); got != reserved {
			t.Errorf("reservedScope(%q) = %t", scope, got)
		}
		c := validConfig()
		c.WriteScope = []string{scope}
		c.UserDNTemplate = "uid=${account}," + scope
		c.UserBase = scope
		if err := c.Validate(); reserved && (err == nil || !strings.Contains(err.Error(), "write_scope")) {
			t.Errorf("scope %q accepted: %v", scope, err)
		}
	}
}
