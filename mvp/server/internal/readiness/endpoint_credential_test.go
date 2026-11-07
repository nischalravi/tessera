package readiness

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Issue #830: a credential was entered for one destination. Changing any endpoint field of a
// connection (settings.host, org_url, domain, tenant_host, base_url, ...) drops the stored
// credential, so an edit can never repoint a sealed secret at a host the editor controls.
func TestPatchConfig_EndpointChangeClearsCredential(t *testing.T) {
	const owners = `"technical_owner":"Ingrid","business_owner":"Thandiwe","correlation_key":"username"`
	for _, tc := range []struct {
		name, typ, cfg string
		endpoint       string // patch that moves the destination
		other          string // patch that does not
	}{
		{"unixssh host", "unixssh", `{"settings":{"host":"ssh.example.com","username":"svc","host_key":"SHA256:abc"}}`,
			`{"settings":{"host":"attacker.example.net","username":"svc","host_key":"SHA256:abc"}}`, `{"settings":{"host":"ssh.example.com","username":"other","host_key":"SHA256:abc"}}`},
		{"unixssh port", "unixssh", `{"settings":{"host":"ssh.example.com","username":"svc"}}`,
			`{"settings":{"host":"ssh.example.com","username":"svc","port":"2222"}}`, `{"settings":{"host":"ssh.example.com","username":"other"}}`},
		{"unixssh host key", "unixssh", `{"settings":{"host":"ssh.example.com","username":"svc","host_key":"SHA256:abc"}}`,
			`{"settings":{"host":"ssh.example.com","username":"svc","host_key":"SHA256:def"}}`, `{"settings":{"host":"ssh.example.com","username":"other","host_key":"SHA256:abc"}}`},
		{"sftpdrop host", "sftpdrop", `{"settings":{"host":"sftp.example.com","username":"svc"}}`,
			`{"settings":{"host":"attacker.example.net","username":"svc"}}`, `{"settings":{"host":"sftp.example.com","username":"other"}}`},
		{"okta org_url", "okta", `{"org_url":"https://acme.okta.com"}`, `{"org_url":"https://attacker.okta.com"}`, `{"stale_days":60}`},
		{"google domain", "google", `{"domain":"example.com","admin_email":"a@example.com"}`, `{"domain":"attacker.example.net"}`, `{"admin_email":"b@example.com"}`},
		{"workday tenant_host", "workday", `{"tenant_host":"wd5.example.com","tenant_id":"acme"}`, `{"tenant_host":"attacker.example.net"}`, `{"stale_days":60}`},
		{"scim_app base_url", "scim_app", `{"base_url":"https://scim.example.com"}`, `{"base_url":"https://attacker.example.net"}`, `{"stale_days":60}`},
		{"entra tenant_id", "entra", `{"tenant_id":"11111111-1111-1111-1111-111111111111","cloud":"public"}`, `{"tenant_id":"22222222-2222-2222-2222-222222222222"}`, `{"stale_days":60}`},
		{"entra cloud", "entra", `{"tenant_id":"11111111-1111-1111-1111-111111111111","cloud":"public"}`, `{"cloud":"usgov"}`, `{"stale_days":60}`},
		// Issue #912: any settings key Endpoints() treats as an endpoint drops the credential, not just a fixed list.
		{"settings foo_url", "unixssh", `{"settings":{"host":"ssh.example.com","username":"svc","foo_url":"https://a.example.com","label":"x"}}`,
			`{"settings":{"host":"ssh.example.com","username":"svc","foo_url":"https://attacker.example.net","label":"x"}}`,
			`{"settings":{"host":"ssh.example.com","username":"svc","foo_url":"https://a.example.com","label":"y"}}`},
		{"settings bar_host", "unixssh", `{"settings":{"host":"ssh.example.com","username":"svc","bar_host":"b.example.com"}}`,
			`{"settings":{"host":"ssh.example.com","username":"svc","bar_host":"attacker.example.net"}}`,
			`{"settings":{"host":"ssh.example.com","username":"other","bar_host":"b.example.com"}}`},
		{"settings x_port", "unixssh", `{"settings":{"host":"ssh.example.com","username":"svc","x_port":"443"}}`,
			`{"settings":{"host":"ssh.example.com","username":"svc","x_port":"8443"}}`,
			`{"settings":{"host":"ssh.example.com","username":"other","x_port":"443"}}`},
		{"settings new endpoint added", "unixssh", `{"settings":{"host":"ssh.example.com","username":"svc"}}`,
			`{"settings":{"host":"ssh.example.com","username":"svc","api_endpoint":"https://attacker.example.net"}}`,
			`{"settings":{"host":"ssh.example.com","username":"svc","label":"x"}}`},
		{"azurerbac settings tenant_id", "azurerbac", `{"settings":{"tenant_id":"11111111-1111-1111-1111-111111111111"}}`,
			`{"settings":{"tenant_id":"22222222-2222-2222-2222-222222222222"}}`, `{"stale_days":60}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, s := newStore(t), newSvc(t)
			var id string
			cfg := strings.Replace(tc.cfg, "{", "{"+owners+",", 1)
			put := func() {
				write(t, st, func(c *store.TenantTx) error {
					_, err := s.SetCredential(c, id, CredentialInput{Reference: "vault:kv/tessera/x"}, "admin", t0)
					return err
				})
			}
			patch := func(body string) *ConfigResult {
				var res *ConfigResult
				write(t, st, func(c *store.TenantTx) error {
					var err error
					res, err = s.PatchConfig(c, id, []byte(body), "admin", t0)
					return err
				})
				return res
			}
			write(t, st, func(c *store.TenantTx) error {
				b, err := s.Create(c, CreateInput{Name: "C", ConnectorType: tc.typ, System: "sys", Config: json.RawMessage(cfg)}, "admin", t0)
				if err != nil {
					return err
				}
				id = b.Conn.ID
				return nil
			})
			put()
			if res := patch(tc.other); res.Bundle.Rev.SecretRef == nil {
				t.Fatal("a non-endpoint edit dropped the credential")
			}
			res := patch(tc.endpoint)
			if res.Bundle.Rev.SecretRef != nil || res.Bundle.Rev.SecretVersion != nil {
				t.Fatal("an endpoint change kept the credential")
			}
			if st := res.Bundle.Rev.State; st != store.StateDraft {
				t.Errorf("state = %s, want draft (needs credentials)", st)
			}
			if res.Bundle.Eval != nil {
				for _, it := range res.Bundle.Eval.Items {
					if it.ID == "credential" && it.Status == StatusPass {
						t.Error("the credential check still passes")
					}
				}
			}
			// a new credential entered after the move is kept by the next unrelated edit
			put()
			if res := patch(`{"stale_days":90}`); res.Bundle.Rev.SecretRef == nil {
				t.Error("a re-entered credential was dropped by an unrelated edit")
			}
			// the same endpoint again changes nothing
			if res := patch(tc.endpoint); res.Bundle.Rev.SecretRef == nil {
				t.Error("an unchanged endpoint dropped the credential")
			}
		})
	}
}

// The audit event of a drop names the endpoint fields that moved, never their values.
func TestPatchConfig_EndpointDropAudited(t *testing.T) {
	st, s := newStore(t), newSvc(t)
	var id string
	write(t, st, func(c *store.TenantTx) error {
		b, err := s.Create(c, CreateInput{Name: "C", ConnectorType: "sftpdrop", System: "sys",
			Config: json.RawMessage(`{"settings":{"host":"sftp.example.com","username":"svc"}}`)}, "admin", t0)
		if err != nil {
			return err
		}
		id = b.Conn.ID
		_, err = s.SetCredential(c, id, CredentialInput{Reference: "vault:kv/tessera/x"}, "admin", t0)
		return err
	})
	var detail string
	write(t, st, func(c *store.TenantTx) error {
		if _, err := s.PatchConfig(c, id, []byte(`{"settings":{"host":"attacker.example.net","username":"svc"}}`), "admin", t0); err != nil {
			return err
		}
		evs, err := c.AuditEvents(store.AuditFilter{})
		for _, e := range evs {
			if e.Action == "connection.config_changed" {
				detail = string(e.Detail)
			}
		}
		return err
	})
	if !strings.Contains(detail, "credential (cleared: the endpoint changed: settings.host)") {
		t.Errorf("audit detail does not record the drop: %s", detail)
	}
	if strings.Contains(detail, "attacker.example.net") {
		t.Errorf("audit detail carries a value: %s", detail)
	}
}

// Issue #912: the credential-drop check and Endpoints() share one definition of an endpoint setting.
func TestEndpointChanged_MatchesEndpoints(t *testing.T) {
	base := ConnConfig{Settings: map[string]string{"foo_url": "u", "bar_host": "h", "x_port": "1", "api_endpoint": "e", "label": "l", "username": "u"}}
	for k := range base.Settings {
		next := ConnConfig{Settings: map[string]string{}}
		for k2, v := range base.Settings {
			next.Settings[k2] = v
		}
		next.Settings[k] = "changed"
		inEndpoints := !slices.Equal(base.Endpoints(), next.Endpoints())
		moved := endpointChanged(base, next)
		if inEndpoints != (len(moved) > 0) {
			t.Errorf("settings.%s: Endpoints changed=%v, endpointChanged=%v", k, inEndpoints, moved)
		}
		if inEndpoints && !slices.Equal(moved, []string{"settings." + k}) {
			t.Errorf("settings.%s: endpointChanged = %v", k, moved)
		}
	}
}
