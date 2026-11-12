package provisioning

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func srvNameTarget(serverName string) map[string]any {
	return map[string]any{"url": "ldaps://ldap.example.com", "base_dn": "ou=g,dc=a,dc=b", "bind_dn": "cn=svc,dc=a,dc=b", "server_name": serverName}
}

func srvNameConfig(serverName string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"account_system": "dir", "member_ref": "{{.Username}}",
		"group_name": "{{.Name}}", "target": srvNameTarget(serverName)})
	return b
}

// The LDAP provisioner's TLS server_name is a bare ASCII host name; the message names the field and never echoes the value (#962).
func TestLDAPServerName(t *testing.T) {
	cases := []struct {
		name, in string
		want     string // substring of the error; empty means accepted
	}{
		{"empty", "", ""},
		{"host", "ldap.example.com", ""},
		{"punycode", "xn--exmple-cua.com", ""},
		{"ipv4", "192.0.2.10", ""},
		{"scheme", "ldaps://ldap.example.com", "host name only"},
		{"userinfo", "user:pw@ldap.example.com", "host name only"},
		{"port", "ldap.example.com:636", "host name only"},
		{"path", "ldap.example.com/x", "host name only"},
		{"space", "ldap example.com", "host name only"},
		{"ipv6", "[2001:db8::1]", "host name only"},
		{"non-ASCII", "ldäp.example.com", "must be ASCII"},
		{"look-alike", "ldap.exаmple.com", "must be ASCII"},
		{"too long", strings.Repeat("a", 254), "host name only"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Compiled{Target: mustJSON(t, srvNameTarget(tc.in))}
			_, err := parseLDAPConfig(TypeLDAP, c, Deps{})
			if tc.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "target.server_name") ||
				(tc.in != "" && strings.Contains(err.Error(), tc.in)) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

// A provisioner stored with an odd server_name stays editable while that value is unchanged; a changed value, or
// taking it out of pause, gets the full check (#962, as #953).
func TestUpdate_LegacyServerName(t *testing.T) {
	const legacy = "ldap.example.com:636"
	str := func(s string) *string { return &s }
	cases := []struct {
		name    string
		paused  bool
		in      func() UpdateInput
		refused bool
	}{
		{"pause", false, func() UpdateInput { return UpdateInput{Mode: str(store.ProvModePaused)} }, false},
		{"rename", false, func() UpdateInput { return UpdateInput{Name: str("renamed")} }, false},
		{"same config resent while pausing", false, func() UpdateInput {
			return UpdateInput{Mode: str(store.ProvModePaused), Config: srvNameConfig(legacy)}
		}, false},
		{"resume", true, func() UpdateInput { return UpdateInput{Mode: str(store.ProvModeAdopt)} }, true},
		{"changed to another bad value", false, func() UpdateInput { return UpdateInput{Config: srvNameConfig("other.example.com:1")} }, true},
		{"changed to a good value", false, func() UpdateInput { return UpdateInput{Config: srvNameConfig("ldap2.example.com")} }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			x := newHarness(t, 1)
			var p *store.Provisioner
			x.must(func(e model.Env) error {
				var err error
				p, err = x.svc.Create(e.Tx, x.now, "tester", CreateInput{Name: "legacy-ldap", TargetType: TypeLDAP, Config: srvNameConfig("ldap.example.com"),
					Secret: map[string]string{"bind_password": "s3cr3t-pw"}})
				return err
			})
			x.must(func(e model.Env) error { // the row as an earlier version stored it
				p.Config = srvNameConfig(legacy)
				if tc.paused {
					p.Mode = store.ProvModePaused
				}
				return e.Tx.UpdateProvisioner(p, x.now)
			})
			var err error
			x.must(func(e model.Env) error {
				cur, gerr := e.Tx.Provisioner(p.ID)
				if gerr != nil {
					return gerr
				}
				in := tc.in()
				in.Version = cur.Version
				_, err = x.svc.Update(e.Tx, x.now, "t", p.ID, in)
				return nil
			})
			if tc.refused != (err != nil) || (err != nil && (!strings.Contains(err.Error(), "target.server_name") || strings.Contains(err.Error(), "example.com"))) {
				t.Fatalf("refused=%v, got %v", tc.refused, err)
			}
		})
	}
}

// A new LDAP provisioner with a bad server_name is refused on create.
func TestCreate_RefusesBadServerName(t *testing.T) {
	x := newHarness(t, 1)
	x.must(func(e model.Env) error {
		_, err := x.svc.Create(e.Tx, x.now, "tester", CreateInput{Name: "bad", TargetType: TypeLDAP, Config: srvNameConfig("https://h"),
			Secret: map[string]string{"bind_password": "s3cr3t-pw"}})
		if err == nil || !strings.Contains(err.Error(), "target.server_name") {
			t.Errorf("got %v", err)
		}
		return nil
	})
}
