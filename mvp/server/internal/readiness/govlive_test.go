package readiness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// govConfig is a valid minimal config of every governed connector type.
var govConfig = map[string]string{
	"awsorg":         `{"correlation_key":"arn","settings":{"regions":"us-east-1","management_account_id":"111111111111","external_id":"tessera-abc123"}}`,
	"githubscan":     `{"settings":{"org":"acme"}}`,
	"sap":            `{"base_url":"https://s4.example.com","settings":{"client_id":"tessera"}}`,
	"oracle":         `{"base_url":"https://fa.example.com","settings":{"client_id":"tessera"}}`,
	"cyberark":       `{"base_url":"https://pvwa.example.com","settings":{"username":"svc-tessera"}}`,
	"beyondtrust":    `{"base_url":"https://bt.example.com","settings":{"username":"tessera"}}`,
	"delinea":        `{"base_url":"https://ss.example.com","settings":{"username":"tessera"}}`,
	"fieldglass":     `{"base_url":"https://fg.example.com","correlation_key":"worker_id"}`,
	"beeline":        `{"base_url":"https://bl.example.com","correlation_key":"worker_id"}`,
	"csvfeed":        `{"base_url":"https://feeds.example.com","correlation_key":"worker_id","settings":{"csv_path":"/c.csv"}}`,
	"agentcore":      `{"settings":{"snapshot":"agentcore.json"}}`,
	"azurerbac":      `{"correlation_key":"id","settings":{"tenant_id":"11111111-2222-3333-4444-555555555555","client_id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}}`,
	"gcpiam":         `{"correlation_key":"id","settings":{"organization_id":"123456789012"}}`,
	"successfactors": `{"base_url":"https://api4.successfactors.com","correlation_key":"person_id","settings":{"company_id":"acme","username":"tessera-api"}}`,
	"servicenow":     `{"base_url":"https://acme.service-now.com","settings":{"username":"tessera.integration"}}`,
	"kubernetes":     `{"base_url":"https://api.k8s.example.com:6443","correlation_key":"id","settings":{"namespaces":"payments, web","openshift":"false"}}`,
	"vault":          `{"base_url":"https://vault.example.com:8200","correlation_key":"id","settings":{"namespace":"team-a/prod"}}`,
	"atlassian":      `{"base_url":"https://acme.atlassian.net","settings":{"email":"tessera@acme.example","project_keys":"PROJ"}}`,
	"mcp":            `{"base_url":"https://tools.acme.example/mcp","settings":{"owner":"olu@acme.example"}}`,
	"bedrock":        `{"correlation_key":"id","settings":{"region":"us-east-1"}}`,
	"vertex":         `{"correlation_key":"id","settings":{"project_id":"acme-agents-prod","location":"us-central1","owner":"olu@acme.example"}}`,
	"foundry":        `{"base_url":"https://acme.services.ai.azure.com/api/projects/support","correlation_key":"id","settings":{"tenant_id":"11111111-2222-3333-4444-555555555555","client_id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}}`,
	"copilot":        `{"base_url":"https://acme.crm.dynamics.com","correlation_key":"id","settings":{"tenant_id":"11111111-2222-3333-4444-555555555555","client_id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}}`,
	"agentforce":     `{"base_url":"https://acme.my.salesforce.com","correlation_key":"id"}`,
	"unixssh":        `{"correlation_key":"id","settings":{"host":"host1.example.com","username":"tessera","host_key":"SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"}}`,
	"sftpdrop":       `{"correlation_key":"id","settings":{"host":"files.example.com","username":"tessera","host_key":"SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8","directory":"/drop/hr","accounts_file":"accounts.csv","accounts_account_id":"ID","accounts_username":"Login"}}`,
}

func createGov(t *testing.T, s *Service, st Scope, typ, name, cfg string) string {
	t.Helper()
	var id string
	write(t, st, func(c *store.TenantTx) error {
		b, err := s.Create(c, CreateInput{Name: name, ConnectorType: typ, Config: json.RawMessage(cfg)}, "admin", t0)
		if err != nil {
			return err
		}
		id = b.Conn.ID
		return nil
	})
	return id
}

// Every governed connector type is creatable from its template: the system is
// the one its connector writes, the template is pinned, and a valid config has
// no field errors while an empty one names what is missing.
func TestGoverned_CreateEveryType(t *testing.T) {
	reg := template.MustDefault()
	for _, gt := range governed.Types {
		t.Run(gt.ID, func(t *testing.T) {
			st, s := newStore(t), newSvc(t)
			tmpl, ok := reg.ForConnectorType(gt.ID)
			if !ok || tmpl.ID != gt.Template {
				t.Fatalf("template for %s = %v", gt.ID, tmpl)
			}
			id := createGov(t, s, st, gt.ID, "Test "+gt.ID, govConfig[gt.ID])
			b, err := current(st, s, id, t0)
			if err != nil {
				t.Fatal(err)
			}
			if b.Conn.System != gt.System || b.Conn.ConnectorType != gt.ID || b.Conn.Role != tmpl.Role || b.Simulated() {
				t.Errorf("connection = %+v", b.Conn)
			}
			if b.Rev.TemplateID != gt.Template || b.Rev.State != store.StateDraft {
				t.Errorf("revision = %s %s", b.Rev.TemplateID, b.Rev.State)
			}
			if errs := ValidateConn(b.Config, b.Template, gt.ID); len(errs) != 0 {
				t.Errorf("valid config: %v", errs)
			}
			empty := ConnConfig{CorrelationKey: tmpl.DefaultCorrelationKey}
			errs := ValidateConn(empty, b.Template, gt.ID)
			required := 0
			for _, sp := range governed.SettingSpecs(gt.ID) {
				if sp.Required {
					required++
				}
			}
			if req, _ := governed.BaseURLUse(gt.ID); req {
				required++
			}
			if gt.ID == governed.GCPIAM {
				required++ // none of its settings is required alone, but one scope must be named
			}
			if gt.ID == governed.ServiceNow {
				required++ // the sign-in decides which identity is needed: basic needs the user, oauth the client id
			}
			if len(errs) != required {
				t.Errorf("empty config: %d errors %v, want %d", len(errs), errs, required)
			}
		})
	}
}

// A cluster API server and a Vault listener name their port; every other governed type takes none, and these
// two take a short list.
func TestGoverned_BasePortsOnlyForKubernetesAndVault(t *testing.T) {
	for _, c := range []struct {
		typ, url string
		ok       bool
	}{
		{"kubernetes", "https://api.k8s.example.com:6443", true},
		{"kubernetes", "https://api.k8s.example.com", true},
		{"kubernetes", "https://api.k8s.example.com:8200", false},
		{"kubernetes", "https://api.k8s.example.com:9999", false},
		{"kubernetes", "https://u:p@api.k8s.example.com:6443", false},
		{"kubernetes", "http://api.k8s.example.com:6443", false},
		{"kubernetes", "https://api.k8s.example.com:6443/x", false},
		{"vault", "https://vault.example.com:8200", true},
		{"vault", "https://vault.example.com:6443", false},
		{"servicenow", "https://acme.service-now.com:8200", false},
	} {
		tmpl, _ := template.MustDefault().ForConnectorType(c.typ)
		cfg := ConnConfig{BaseURL: c.url, CorrelationKey: "id", Settings: map[string]string{}}
		if c.typ == "servicenow" {
			cfg.Settings["username"] = "svc"
		}
		if errs := ValidateConn(cfg, tmpl, c.typ); (len(errs) == 0) != c.ok {
			t.Errorf("%s %s: %v", c.typ, c.url, errs)
		}
	}
}

func TestGoverned_Validation(t *testing.T) {
	tmpl, _ := template.MustDefault().ForConnectorType("cyberark")
	ok := ConnConfig{BaseURL: "https://pvwa.example.com", Settings: map[string]string{"username": "svc"}, CorrelationKey: "id"}
	if errs := ValidateConn(ok, tmpl, "cyberark"); len(errs) != 0 {
		t.Fatalf("valid: %v", errs)
	}
	for name, mut := range map[string]func(*ConnConfig){
		"http":        func(c *ConnConfig) { c.BaseURL = "http://pvwa.example.com" },
		"path":        func(c *ConnConfig) { c.BaseURL = "https://pvwa.example.com/PasswordVault" },
		"credentials": func(c *ConnConfig) { c.BaseURL = "https://u:p@pvwa.example.com" },
		"port":        func(c *ConnConfig) { c.BaseURL = "https://pvwa.example.com:8443" },
		"unknown key": func(c *ConnConfig) { c.Settings = map[string]string{"username": "svc", "password": "x"} },
		"bad path":    func(c *ConnConfig) { c.Settings = map[string]string{"username": "svc", "api_root": "/a/../b"} },
	} {
		c := ok
		mut(&c)
		if errs := ValidateConn(c, tmpl, "cyberark"); len(errs) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
	// settings belong to the governed types only
	ldap, _ := template.MustDefault().ForConnectorType("ldap")
	c := ConnConfig{Host: "ldap.example.com", Port: 636, BaseDNs: []string{"dc=x"}, CorrelationKey: "entryUUID", Settings: map[string]string{"a": "b"}}
	if errs := ValidateConn(c, ldap, "ldap"); len(errs) != 1 || errs[0].Field != "settings" {
		t.Errorf("settings on ldap: %v", errs)
	}
	// the strict decoder rejects a credential smuggled into the config, as for every type
	if _, err := DecodeConfig([]byte(`{"base_url":"https://x.example.com","password":"p"}`)); err == nil {
		t.Error("a password field decoded")
	}
	// GitHub takes an optional API URL (Enterprise Server's ends in a path); AWS and AgentCore take none
	gh, _ := template.MustDefault().ForConnectorType("githubscan")
	if errs := ValidateConn(ConnConfig{BaseURL: "https://ghe.example.com/api/v3", Settings: map[string]string{"org": "a"}, CorrelationKey: "id"}, gh, "githubscan"); len(errs) != 0 {
		t.Errorf("enterprise API URL: %v", errs)
	}
	aws, _ := template.MustDefault().ForConnectorType("awsorg")
	if errs := ValidateConn(ConnConfig{BaseURL: "https://x.example.com", Settings: map[string]string{"regions": "us-east-1", "external_id": "e1"}, CorrelationKey: "arn"}, aws, "awsorg"); len(errs) != 1 {
		t.Errorf("base URL on awsorg: %v", errs)
	}
}

// stubProber answers every check the governed templates use.
type stubProber struct {
	auth   connectors.AuthInfo
	sample connectors.SampleStats
	rights connectors.Rights
}

func (stubProber) Connect(context.Context) (connectors.ConnInfo, error) {
	return connectors.ConnInfo{Reachable: true, TLSVersion: "1.3", ChainValid: true, HostnameMatch: true}, nil
}
func (p stubProber) Authenticate(context.Context) (connectors.AuthInfo, error) { return p.auth, nil }
func (stubProber) RootInfo(context.Context) (connectors.RootInfo, error) {
	return connectors.RootInfo{}, connectors.ErrUnsupported
}
func (stubProber) ObjectExists(context.Context, string) (bool, error) {
	return false, connectors.ErrUnsupported
}
func (p stubProber) Sample(context.Context, connectors.SampleQuery) (connectors.SampleStats, error) {
	return p.sample, nil
}
func (p stubProber) EffectiveRights(context.Context, string) (connectors.Rights, error) {
	return p.rights, nil
}
func (stubProber) ChangeFeed(context.Context) (connectors.FeedInfo, error) {
	return connectors.FeedInfo{}, connectors.ErrUnsupported
}
func (stubProber) RateLimits(context.Context) (connectors.RateInfo, error) {
	return connectors.RateInfo{}, connectors.ErrUnsupported
}
func (stubProber) Time(context.Context) (time.Time, error) {
	return time.Time{}, connectors.ErrUnsupported
}

const govSecret = "gov-secret-value-4417"

// govSvc is a service whose Gov options hand every governed connection a stub
// prober, recording what it was opened with.
func govSvc(t *testing.T, opened *[]governed.Params, p stubProber) *Service {
	t.Helper()
	s := liveSvc(t)
	s.AWSAllowStaticKeys = true // these tests seal a secret on every governed type
	s.Runner.Gov = GovOptions{Client: &http.Client{}, DataDir: "/data", Prod: true,
		Prober: func(gp governed.Params, _ governed.Net) (connectors.Prober, error) {
			*opened = append(*opened, gp)
			return p, nil
		},
		Connector: func(governed.Params, governed.Net) (connectors.Connector, error) {
			return nil, errors.New("not in this test")
		}}
	return s
}

func readyGov(t *testing.T, s *Service, st Scope, typ string, withSecret bool) string {
	t.Helper()
	id := createGov(t, s, st, typ, "Gov "+typ, govConfig[typ])
	write(t, st, func(c *store.TenantTx) error {
		if withSecret {
			if _, err := s.SetCredential(c, id, CredentialInput{Secret: govSecret}, "admin", t0); err != nil {
				return err
			}
		} else if _, err := s.SetCredential(c, id, CredentialInput{Reference: "vault:kv/x"}, "admin", t0); err != nil {
			return err
		}
		b, err := s.Current(c, id, t0)
		if err != nil {
			return err
		}
		for _, it := range b.Template.Items {
			if ie, ok := b.Eval.Item(it.ID); ok && ie.Applicable && it.HasKind(template.Attestation) && it.Level == template.Required && it.OnlyAttestation() {
				if _, err := s.Attest(c, id, it.ID, "confirmed in CHG-2210", "admin", t0); err != nil {
					return err
				}
			}
		}
		_, err = s.Transition(c, id, store.StateReadyToValidate, "admin", t0)
		return err
	})
	return id
}

// A real governed connection has no simulated results: the sealed credential is
// opened inside the run and handed to the prober, the checks that need the
// system run against it, and a run without a credential reports errors rather
// than passing.
func TestGoverned_ValidateRunsTheRealProber(t *testing.T) {
	var opened []governed.Params
	okProber := stubProber{auth: connectors.AuthInfo{OK: true, Mode: "password"}, sample: connectors.SampleStats{Objects: 12, Available: true,
		PerClass: map[string]int{"safe": 3}}}
	s := govSvc(t, &opened, okProber)
	st := newStore(t)
	id := readyGov(t, s, st, "cyberark", true)

	v, err := s.Validate(context.Background(), st, id, "admin", clockAt(t0))
	if err != nil {
		t.Fatal(err)
	}
	if v.Simulated {
		t.Error("a real connection's run is labelled simulated")
	}
	for _, c := range [][2]string{{"pam.endpoint", "endpoint_reachable"}, {"pam.auth", "auth_ok"}, {"pam.read", "read_probe"}} {
		r := resultFor(v, c[0], c[1])
		if r == nil || r.Status != "pass" || r.Simulated {
			t.Errorf("%s: %+v", c[1], r)
		}
	}
	if len(opened) == 0 {
		t.Fatal("no prober was opened")
	}
	gp := opened[0]
	if gp.Secret != govSecret || gp.Type != "cyberark" || gp.BaseURL != "https://pvwa.example.com" || gp.Settings["username"] != "svc-tessera" ||
		gp.Tenant != st.Tenant.String() || !gp.Prod || gp.DataDir != "/data" {
		t.Errorf("opened with %+v", gp)
	}
	if b, _ := json.Marshal(v); strings.Contains(string(b), govSecret) {
		t.Error("the secret is in the run view")
	}

	// a vault reference cannot be opened by Tessera: the checks that need the system error
	opened = nil
	st2 := newStore(t)
	id2 := readyGov(t, s, st2, "cyberark", false)
	v, err = s.Validate(context.Background(), st2, id2, "admin", clockAt(t0))
	if err != nil {
		t.Fatal(err)
	}
	r := resultFor(v, "pam.auth", "auth_ok")
	if r == nil || r.Status == "pass" || v.Simulated || len(opened) != 0 {
		t.Errorf("without a stored credential: %+v (opened %d)", r, len(opened))
	}
	if r := resultFor(v, "pam.endpoint", "endpoint_reachable"); r == nil || r.Status != "error" || r.Simulated {
		t.Errorf("endpoint without a credential: %+v", r)
	}
}

// A source that refuses the credential fails the authentication item, and an
// empty read fails the read item: a clean-looking nothing is never a pass.
func TestGoverned_FailingChecks(t *testing.T) {
	var opened []governed.Params
	st := newStore(t)
	s := govSvc(t, &opened, stubProber{auth: connectors.AuthInfo{OK: false}, sample: connectors.SampleStats{Available: true}})
	id := readyGov(t, s, st, "sap", true)
	v, err := s.Validate(context.Background(), st, id, "admin", clockAt(t0))
	if err != nil {
		t.Fatal(err)
	}
	if r := resultFor(v, "erp.auth", "auth_ok"); r == nil || r.Status != "fail" {
		t.Errorf("refused credential: %+v", r)
	}
	if r := resultFor(v, "erp.read", "read_probe"); r == nil || r.Status != "blocked" {
		t.Errorf("a read behind a refused credential: %+v", r)
	}
	if got := state(t, s, st, id); got != store.StateReadyToValidate {
		t.Errorf("state after failing validation: %s", got)
	}
	st2 := newStore(t)
	s2 := govSvc(t, &opened, stubProber{auth: connectors.AuthInfo{OK: true}, sample: connectors.SampleStats{Available: true}})
	id2 := readyGov(t, s2, st2, "sap", true)
	if v, err = s2.Validate(context.Background(), st2, id2, "admin", clockAt(t0)); err != nil {
		t.Fatal(err)
	}
	if r := resultFor(v, "erp.read", "read_probe"); r == nil || r.Status != "fail" {
		t.Errorf("empty read: %+v", r)
	}
}

// AgentCore has no credential: the credential gate passes without one, and the
// type still reads its snapshot only through the prober.
func TestGoverned_AgentCoreNeedsNoCredential(t *testing.T) {
	var opened []governed.Params
	s := govSvc(t, &opened, stubProber{sample: connectors.SampleStats{Objects: 3, Available: true}})
	st := newStore(t)
	id := createGov(t, s, st, "agentcore", "AgentCore", govConfig["agentcore"])
	var b *Bundle
	read(t, st, func(c *store.TenantTx) (err error) {
		b, err = s.Current(c, id, t0)
		return err
	})
	p, ok, err := s.Runner.Gov.prober(b, t0)
	if !ok || err != nil || p == nil || len(opened) != 1 {
		t.Fatalf("prober: ok %v err %v opened %d", ok, err, len(opened))
	}
	if needsSecret("agentcore") || !needsSecret("cyberark") {
		t.Error("needsSecret")
	}
}

func TestGoverned_DemoAndOtherTypesKeepTheirProbers(t *testing.T) {
	var opened []governed.Params
	s := govSvc(t, &opened, stubProber{})
	for _, typ := range []string{"demo-ad", "ldap", "scim_app", "okta"} {
		if _, ok, _ := s.Runner.Gov.prober(&Bundle{Conn: &store.Connection{ConnectorType: typ}}, t0); ok {
			t.Errorf("%s got a governed prober", typ)
		}
		if govLive(&Bundle{Conn: &store.Connection{ConnectorType: typ}}) {
			t.Errorf("%s is governed-live", typ)
		}
	}
	// no client, no prober: a real governed connection fails closed
	z := GovOptions{}
	b := &Bundle{Conn: &store.Connection{ConnectorType: "cyberark"}, cred: "x"}
	if _, ok, err := z.prober(b, t0); !ok || err == nil {
		t.Errorf("zero options: ok %v err %v", ok, err)
	}
	if _, err := z.connector(b, t0); err == nil {
		t.Error("zero options opened a connector")
	}
}

// passingEvidence stands in for validation and a dry run of a real connection:
// every live and data check passes, bound to the current item hashes, and none
// is labelled simulated (a simulated result cannot satisfy a real type's gate).
func passingEvidence(s *Service, at time.Time) {
	s.extraEvidence = func(c *store.TenantTx, rev *store.ConnectionRevision, ev *Evidence) {
		conn, err := c.Connection(rev.ConnectionID)
		if err != nil {
			panic(err)
		}
		tmpl, err := s.templateFor(c, rev.TemplateID, rev.TemplateVersion, rev.OverlayVersion)
		if err != nil {
			panic(err)
		}
		cfg, _ := DecodeConfig([]byte(rev.Config))
		in := hashInput(conn, rev, cfg)
		full, _ := in.ConfigHash()
		ev.LiveRun = &RunInfo{ID: "live-1", Kind: "validation", Status: "completed", ConfigHash: full, StartedAt: at, FinishedAt: &at}
		ev.DataRun = &RunInfo{ID: "data-1", Kind: "dry_run", Status: "completed", ConfigHash: full, StartedAt: at, FinishedAt: &at}
		for _, it := range tmpl.Items {
			h, _ := in.ItemHash(it.ConfigFields)
			for _, v := range it.Verify {
				r := &ResultInfo{ItemID: it.ID, CheckID: v.Check, Status: "pass", ItemHash: h, Message: "passed"}
				switch v.Kind {
				case template.Live:
					ev.Live[resultKey{it.ID, v.Check}] = r
				case template.Data:
					ev.Data[resultKey{it.ID, v.Check}] = r
				}
			}
		}
	}
}

// The write items come from the base template: a write-enabled governed
// connection needs a second approver, and its write scope is checked live (the
// vault's own rights; an ERP cannot answer, so an attestation stands in).
func TestGoverned_WriteEnabledNeedsSecondPerson(t *testing.T) {
	st, s := newStore(t), newSvc(t)
	passingEvidence(s, t0.Add(ActivationTTL+time.Hour))
	var id string
	write(t, st, func(c *store.TenantTx) error {
		b, err := s.Create(c, CreateInput{Name: "Vault writeback", ConnectorType: "cyberark",
			Config: json.RawMessage(`{"base_url":"https://pvwa.example.com","settings":{"username":"svc"},"write_mode":"scoped","write_scope":["7"],` +
				`"technical_owner":"Ingrid Lindqvist","business_owner":"Thandiwe Mokoena"}`)}, ingrid.Display, t0)
		if err != nil {
			return err
		}
		id = b.Conn.ID
		if _, err := s.SetCredential(c, id, CredentialInput{Reference: "vault:kv/pam"}, ingrid.Display, t0); err != nil {
			return err
		}
		for _, it := range b.Template.Items {
			if it.HasKind(template.Attestation) {
				if _, err := s.Attest(c, id, it.ID, "checked in the vault console", ingrid.Display, t0); err != nil && codeOf(err) != "not_attestable" {
					var re *Error
					if asErr(err, &re) && re.Report != nil {
						return fmt.Errorf("attest %s: %w: %+v", it.ID, err, re.Report.Blocking)
					}
					return fmt.Errorf("attest %s: %w", it.ID, err)
				}
			}
		}
		if _, err := s.Transition(c, id, store.StateReadyToValidate, ingrid.Display, t0); err != nil {
			return err
		}
		b, err = s.Current(c, id, t0)
		if err != nil {
			return err
		}
		if err := s.advanceAfterValidation(c, b, ingrid.Display, t0); err != nil {
			return err
		}
		_, err = s.Transition(c, id, store.StateDryRunReconciled, ingrid.Display, t0)
		return err
	})
	if got := state(t, s, st, id); got != store.StateDryRunReconciled {
		t.Fatalf("setup: state %s", got)
	}
	b, _ := current(st, s, id, t0)
	// the vault checks that apply to a write-enabled connection, and the one that does not
	applies := map[string]bool{}
	for _, it := range b.Eval.Items {
		applies[it.ID] = it.Applicable
	}
	if !applies["base.writeback.scope"] || !applies["base.writeback.dryrun"] || applies["pam.rights.readonly"] {
		t.Errorf("write-mode applicability: %v", applies)
	}
	err := try(st, func(c *store.TenantTx) error {
		_, _, err := s.Activate(c, id, pam.Display, t0)
		return err
	})
	var re *Error
	if codeOf(err) != "activation_blocked" || !asErr(err, &re) || len(re.Report.Blocking) != 1 || re.Report.Blocking[0].Item != ApprovalItem {
		t.Fatalf("direct activation of a write-enabled vault: %v", err)
	}
	write(t, st, func(c *store.TenantTx) error {
		_, err := s.RequestActivation(c, id, pam, t0)
		return err
	})
	write(t, st, func(c *store.TenantTx) error {
		_, ac, err := s.ApproveActivation(c, id, olu, "reviewed the write scope", t0.Add(time.Hour))
		if err == nil && (ac.ConnectorType() != "cyberark" || ac.System() != "cyberark") {
			t.Errorf("active connection = %s %s", ac.ConnectorType(), ac.System())
		}
		return err
	})
	if got := state(t, s, st, id); got != store.StateActive {
		t.Errorf("state after approval = %s", got)
	}
	// the read-only vault check is applicable only without write-back
	st2, s2 := newStore(t), newSvc(t)
	id2 := createGov(t, s2, st2, "cyberark", "Vault read-only", govConfig["cyberark"])
	b2, _ := current(st2, s2, id2, t0)
	if it, ok := b2.Eval.Item("pam.rights.readonly"); !ok || !it.Applicable {
		t.Errorf("pam.rights.readonly for a read-only connection: %+v", it)
	}
}

// An unsupported write-scope check (the ERP cannot read the integration's
// rights) can be attested by a named person instead, and only that way.
func TestGoverned_ERPWriteScopeAttestedWhenUnsupported(t *testing.T) {
	tmpl, _ := template.MustDefault().ForConnectorType("sap")
	it, ok := tmpl.Item("base.writeback.scope")
	if !ok || !it.HasLiveAlternative() {
		t.Fatalf("base.writeback.scope: %+v", it)
	}
	// a live check that fails is never replaced by an attestation (on_unsupported covers 'unsupported' only)
	for _, v := range it.Verify {
		if v.OnUnsupported != template.Attestation {
			t.Errorf("verify %+v", v)
		}
	}
}

func TestGoverned_EveryTemplateItemCheckAllowed(t *testing.T) {
	reg := template.MustDefault()
	for _, id := range []string{"awsorg", "githubscan", "erp", "pam", "vms", "agentcore", "azurerbac", "gcpiam", "unixssh", "sftpdrop", "kubernetes", "vault", "mcp", "bedrock", "vertex", "foundry", "copilot", "agentforce"} {
		r, ok := reg.Get(id)
		if !ok {
			t.Fatalf("no template %s", id)
		}
		if got := slices.Sorted(slices.Values(r.ConnectorTypes)); !slices.Equal(got, governedTypesOf(id)) {
			t.Errorf("%s covers %v", id, r.ConnectorTypes)
		}
		wantInv := id == "awsorg" || id == "githubscan" || id == "vms" || id == "azurerbac" || id == "gcpiam" || id == "unixssh" || id == "sftpdrop" || id == "kubernetes" || id == "vault"
		if r.Inventory != wantInv {
			t.Errorf("%s inventory = %v", id, r.Inventory)
		}
	}
}

func governedTypesOf(tmpl string) []string {
	var out []string
	for _, t := range governed.Types {
		if t.Template == tmpl {
			out = append(out, t.ID)
		}
	}
	// the template lists the types in its own order
	slices.Sort(out)
	return out
}

// A credential the connector cannot read fails the authentication check with the
// connector's fixed hint and blocks the checks behind it; any other construction
// failure keeps the generic "no prober" error. Neither shows the error text or
// the credential.
func TestGoverned_CredentialFormatFailure(t *testing.T) {
	const hint = "bedrockagents: the credential is JSON with access_key_id and secret_access_key"
	tests := []struct {
		name       string
		err        error
		wantAuth   string
		wantStatus string
		wantMsg    string
		wantCode   bool
	}{
		{name: "credential format", err: connsync.CredentialFormat(hint), wantAuth: "fail", wantStatus: "blocked", wantMsg: hint, wantCode: true},
		{name: "wrapped", err: fmt.Errorf("open: %w (%s)", connsync.CredentialFormat(hint), govSecret), wantAuth: "fail", wantStatus: "blocked", wantMsg: hint, wantCode: true},
		{name: "other failure", err: errors.New("base URL " + govSecret + " is refused"), wantAuth: "error", wantStatus: "error", wantMsg: "no prober is available for this connection"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var opened []governed.Params
			s := govSvc(t, &opened, stubProber{})
			s.Runner.Gov.Prober = func(governed.Params, governed.Net) (connectors.Prober, error) { return nil, tc.err }
			st := newStore(t)
			id := readyGov(t, s, st, "cyberark", true)
			v, err := s.Validate(context.Background(), st, id, "admin", clockAt(t0))
			if err != nil {
				t.Fatal(err)
			}
			auth := resultFor(v, "pam.auth", "auth_ok")
			if auth == nil || auth.Status != tc.wantAuth || auth.Message != tc.wantMsg {
				t.Fatalf("auth_ok: %+v", auth)
			}
			if code, _ := auth.Observed["code"].(string); (code == "credential_format") != tc.wantCode {
				t.Errorf("code %q, want credential_format=%v", code, tc.wantCode)
			}
			if r := resultFor(v, "pam.endpoint", "endpoint_reachable"); r == nil || r.Status != tc.wantStatus {
				t.Errorf("endpoint_reachable: %+v", r)
			}
			if b, _ := json.Marshal(v); strings.Contains(string(b), govSecret) {
				t.Error("the secret is in the run view")
			}
		})
	}
}
