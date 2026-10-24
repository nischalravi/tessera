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
