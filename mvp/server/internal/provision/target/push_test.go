package target_test

import (
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
)

func goodSpec() target.PushSpec {
	return target.PushSpec{OpID: "op-1", Target: "scim", BaseURL: "https://scim.corp.example:8443/scim/v2", Dialect: "entra",
		Op: target.DisableAccount, Key: "jml:leaver:1", Account: target.Account{Username: "alice@corp.example"}}
}

func TestPushSpecValidate(t *testing.T) {
	if err := goodSpec().Validate(); err != nil {
		t.Fatal(err)
	}
	h, p, err := goodSpec().HostPort()
	if err != nil || h != "scim.corp.example" || p != 8443 {
		t.Errorf("HostPort = %q %d %v", h, p, err)
	}
	if _, p, _ := (target.PushSpec{BaseURL: "https://scim.corp.example/x"}).HostPort(); p != 443 {
		t.Errorf("default port = %d", p)
	}
	r := goodSpec().Request()
	if r.Kind != target.DisableAccount || r.Key != "jml:leaver:1" || r.Account.Username != "alice@corp.example" {
		t.Errorf("request = %+v", r)
	}
	for name, mut := range map[string]func(*target.PushSpec){
		"no op id":          func(p *target.PushSpec) { p.OpID = "" },
		"separator in op":   func(p *target.PushSpec) { p.OpID = "a|b" },
		"unknown target":    func(p *target.PushSpec) { p.Target = "ldap" },
		"http":              func(p *target.PushSpec) { p.BaseURL = "http://scim.corp.example/v2" },
		"credentials":       func(p *target.PushSpec) { p.BaseURL = "https://u:p@scim.corp.example/v2" },
		"query":             func(p *target.PushSpec) { p.BaseURL = "https://scim.corp.example/v2?x=1" },
		"fragment":          func(p *target.PushSpec) { p.BaseURL = "https://scim.corp.example/v2#x" },
		"long url":          func(p *target.PushSpec) { p.BaseURL = "https://scim.corp.example/" + strings.Repeat("a", 300) },
		"bad port":          func(p *target.PushSpec) { p.BaseURL = "https://scim.corp.example:99999/v2" },
		"no host":           func(p *target.PushSpec) { p.BaseURL = "https:///v2" },
		"dialect":           func(p *target.PushSpec) { p.Dialect = "weird" },
		"okta dialect":      func(p *target.PushSpec) { p.Target, p.Dialect = "okta", "entra" },
		"unknown op":        func(p *target.PushSpec) { p.Op = "nuke" },
		"no key":            func(p *target.PushSpec) { p.Key = "" },
		"newline in key":    func(p *target.PushSpec) { p.Key = "a\nb" },
		"no username":       func(p *target.PushSpec) { p.Account.Username = "" },
		"control in name":   func(p *target.PushSpec) { p.Account.Username = "a\x00b" },
		"long email":        func(p *target.PushSpec) { p.Account.Email = strings.Repeat("a", 600) },
		"entitlement group": func(p *target.PushSpec) { p.Op = target.AddEntitlement },
		"cred path":         func(p *target.PushSpec) { p.CredName = "../x" },
		"too many attrs": func(p *target.PushSpec) {
			p.Account.Attrs = map[string]string{}
			for i := 0; i < 51; i++ {
				p.Account.Attrs[strings.Repeat("k", i+1)] = "v"
			}
		},
	} {
		p := goodSpec()
		mut(&p)
		if err := p.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
