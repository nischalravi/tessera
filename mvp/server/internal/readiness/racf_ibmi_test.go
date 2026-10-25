package readiness

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func tmplOfID(t *testing.T, id string) *template.Resolved {
	t.Helper()
	r, ok := template.MustDefault().Get(id)
	if !ok {
		t.Fatalf("no %s template", id)
	}
	return r
}

// TestValidateConn_RACFAndIBMi: RACF takes the LDAP connect rules (SDBM suffix
// as the base DN); IBM i takes a host, a host-server port and a user profile
// name, and no base DN. Messages never echo the input.
func TestValidateConn_RACFAndIBMi(t *testing.T) {
	racf := ConnConfig{Host: "zos.corp.example", Port: 636, BindDN: "racfid=TESSERA,profiletype=USER,cn=RACFA", BaseDNs: []string{"cn=RACFA"}, CorrelationKey: "racfid"}
	ibmi := ConnConfig{Host: "as400.corp.example", Port: 9471, BindDN: "TESSERA", CorrelationKey: "USER_NAME"}
	for name, tc := range map[string]struct {
		typ   string
		cfg   ConnConfig
		mut   func(*ConnConfig)
		field string
	}{
		"racf ok":                          {"racf", racf, func(c *ConnConfig) {}, ""},
		"racf no suffix":                   {"racf", racf, func(c *ConnConfig) { c.BaseDNs = nil }, "base_dns"},
		"racf bad suffix":                  {"racf", racf, func(c *ConnConfig) { c.BaseDNs = []string{"not a dn"} }, "base_dns"},
		"racf bind is not a DN":            {"racf", racf, func(c *ConnConfig) { c.BindDN = "TESSERA" }, "bind_dn"},
		"racf scheme in host":              {"racf", racf, func(c *ConnConfig) { c.Host = "ldaps://zos" }, "host"},
		"racf ssh port":                    {"racf", racf, func(c *ConnConfig) { c.Port = 22 }, "port"},
		"racf plain in prod":               {"racf", racf, func(c *ConnConfig) { c.TLSMode = "none" }, "tls_mode"},
		"ibmi ok":                          {"ibmi", ibmi, func(c *ConnConfig) {}, ""},
		"ibmi no profile":                  {"ibmi", ibmi, func(c *ConnConfig) { c.BindDN = "" }, "bind_dn"},
		"ibmi profile too long":            {"ibmi", ibmi, func(c *ConnConfig) { c.BindDN = "ELEVENCHARS" }, "bind_dn"},
		"ibmi profile with a space":        {"ibmi", ibmi, func(c *ConnConfig) { c.BindDN = "A B" }, "bind_dn"},
		"ibmi profile with a period":       {"ibmi", ibmi, func(c *ConnConfig) { c.BindDN = "TESS.ERA" }, "bind_dn"},
		"ibmi profile starts with a digit": {"ibmi", ibmi, func(c *ConnConfig) { c.BindDN = "1TESSERA" }, "bind_dn"},
		"ibmi profile starts with _":       {"ibmi", ibmi, func(c *ConnConfig) { c.BindDN = "_TESSERA" }, "bind_dn"},
		"ibmi profile with # $ @ _":        {"ibmi", ibmi, func(c *ConnConfig) { c.BindDN = "#T$@_9" }, ""},
		"ibmi profile is a DN":             {"ibmi", ibmi, func(c *ConnConfig) { c.BindDN = "cn=x,dc=y" }, "bind_dn"},
		"ibmi base dn":                     {"ibmi", ibmi, func(c *ConnConfig) { c.BaseDNs = []string{"dc=x"} }, "base_dns"},
		"ibmi database port":               {"ibmi", ibmi, func(c *ConnConfig) { c.Port = 3306 }, "port"},
		"ibmi bad host":                    {"ibmi", ibmi, func(c *ConnConfig) { c.Host = "as400/x" }, "host"},
	} {
		cfg := tc.cfg
		tc.mut(&cfg)
		var got []string
		for _, fe := range ValidateConnEnv(cfg, tmplOfID(t, tc.typ), tc.typ, config.Prod) {
			got = append(got, fe.Field)
			for _, in := range []string{cfg.Host, cfg.BindDN} {
				if len(in) > 3 && strings.Contains(fe.Msg, in) {
					t.Errorf("%s: message echoes the input: %q", name, fe.Msg)
				}
			}
		}
		switch {
		case tc.field == "" && len(got) > 0:
			t.Errorf("%s: unexpected errors on %v", name, got)
		case tc.field != "" && !slices_contains(got, tc.field):
			t.Errorf("%s: no error on %s (got %v)", name, tc.field, got)
		}
	}
	if DefaultConfig("racf", tmplOfID(t, "racf")).Port != 636 || DefaultConfig("ibmi", tmplOfID(t, "ibmi")).Port != 9471 {
		t.Error("default ports")
	}
}

// TestSetCredential_ModulesNeedAnAgent: RACF and IBM i are read by an agent
// module only, so a server-held secret or a vault reference is refused and the
// agent reference is taken.
func TestSetCredential_ModulesNeedAnAgent(t *testing.T) {
	for typ, cfg := range map[string]string{
		"racf": `{"host":"zos.corp.example","port":636,"bind_dn":"racfid=T,profiletype=USER,cn=RACFA","base_dns":["cn=RACFA"],"correlation_key":"racfid"}`,
		"ibmi": `{"host":"as400.corp.example","port":9471,"bind_dn":"TESSERA","correlation_key":"USER_NAME"}`,
	} {
		st, s, _, agentID := agentSvc(t)
		var id string
		write(t, st, func(c *store.TenantTx) error {
			b, err := s.Create(c, CreateInput{Name: "MF " + typ, ConnectorType: typ, System: "mf-" + typ, Config: json.RawMessage(cfg)}, "admin", t0)
			if err == nil {
				id = b.Conn.ID
			}
			return err
		})
		set := func(in CredentialInput) error {
			return st.Write(context.Background(), func(c *store.TenantTx) error {
				_, err := s.SetCredential(c, id, in, "admin", t0)
				return err
			})
		}
		for name, in := range map[string]CredentialInput{"secret": {Secret: "hunter2"}, "vault": {Reference: "vault:kv/mf"}} {
			var re *Error
			err := set(in)
			if !errors.As(err, &re) || re.Code != "agent_required" || strings.Contains(re.Msg, "hunter2") {
				t.Errorf("%s %s: %v", typ, name, err)
			}
		}
		if err := set(CredentialInput{Reference: "agent:" + agentID + "/mf"}); err != nil {
			t.Errorf("%s agent reference: %v", typ, err)
		}
	}
}

// TestTemplates_RACFAndIBMi: the templates exist, are account sources, and
// use only the live checks that make sense for them (RACF is probed over LDAP;
// IBM i has no live check until its transport exists).
func TestTemplates_RACFAndIBMi(t *testing.T) {
	racf, ibmi := tmplOfID(t, "racf"), tmplOfID(t, "ibmi")
	if racf.Role != "account_source" || ibmi.Role != "account_source" || racf.ConnectorTypes[0] != "racf" || ibmi.ConnectorTypes[0] != "ibmi" {
		t.Errorf("racf %+v ibmi %+v", racf.ConnectorTypes, ibmi.ConnectorTypes)
	}
	live := func(r *template.Resolved) (out []string) {
		for _, it := range r.Items {
			if !strings.HasPrefix(it.ID, r.ID+".") {
				continue
			}
			for _, v := range it.Verify {
				if v.Kind == template.Live {
					out = append(out, v.Check)
				}
			}
		}
		return out
	}
	for _, c := range live(racf) {
		if c != "tls_handshake" && c != "tls_chain" && c != "bind" {
			t.Errorf("racf live check %s", c)
		}
	}
	if got := live(ibmi); len(got) != 0 {
		t.Errorf("ibmi has live checks %v before its transport exists", got)
	}
}

// TestLive_RACFNeverDialsDirectly: a RACF revision that somehow holds a
// server-side credential still gets no direct-dial prober.
func TestLive_RACFNeverDialsDirectly(t *testing.T) {
	st, s, _, _ := agentSvc(t)
	s.Runner.Live.Env = config.Dev
	var id string
	write(t, st, func(c *store.TenantTx) error {
		b, err := s.Create(c, CreateInput{Name: "MF", ConnectorType: "racf", System: "mf",
			Config: json.RawMessage(`{"host":"zos.corp.example","port":636,"bind_dn":"racfid=T,profiletype=USER,cn=RACFA","base_dns":["cn=RACFA"],"correlation_key":"racfid"}`)}, "admin", t0)
		if err == nil {
			id = b.Conn.ID
		}
		return err
	})
	read(t, st, func(c *store.TenantTx) error {
		b, _ := s.Current(c, id, t0)
		ref := "sealed:x"
		b.Rev.SecretRef, b.cred = &ref, "pw"
		if p, ok, err := s.Runner.Live.liveProber(b, t0); p != nil || !ok || err == nil {
			t.Errorf("%T %v %v", p, ok, err)
		}
		return nil
	})
}
