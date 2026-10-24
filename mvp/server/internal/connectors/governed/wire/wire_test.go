package wire_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/erp/erpfake"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed/wire"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/pam/pamfake"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/vms/vmsfake"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/checks"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

var t0 = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)

// serve starts a TLS fake and returns the Net that reaches it.
func serve(t *testing.T, h http.Handler) (*connsynctest.Server, governed.Net) {
	t.Helper()
	srv := connsynctest.New(t, h)
	hc, err := safehttp.NewForTest(t, srv.Options(0))
	if err != nil {
		t.Fatal(err)
	}
	return srv, governed.Net{RT: connsynctest.Runtime, HC: hc, Now: func() time.Time { return t0 }}
}

// run executes one registered readiness check against a prober, as the runner does.
func run(t *testing.T, p connectors.Prober, id string, env checks.Env) checks.Result {
	t.Helper()
	c, ok := checks.Get(id)
	if !ok {
		t.Fatalf("no check %s", id)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	env.Probe, env.Now = p, t0
	return checks.Run(ctx, c, env, nil)
}

func wantPass(t *testing.T, p connectors.Prober, tmpl string, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if r := run(t, p, id, checks.Env{TemplateID: tmpl}); r.Status != checks.Pass {
			t.Errorf("%s: %s %s %v", id, r.Status, r.Message, r.Observed)
		}
	}
}

func prober(t *testing.T, p governed.Params, n governed.Net) connectors.Prober {
	t.Helper()
	pr, err := wire.Prober(p, n)
	if err != nil {
		t.Fatal(err)
	}
	return pr
}

// ---------------------------------------------------------------- PAM

const pamUser, pamSecret = "svc-tessera", "s3cret-value"

func pamSafe(vendor string, manage bool) pamfake.Safe {
	s := pamfake.Safe{ID: "7", Name: "Prod-DB",
		Accounts: []pamfake.Account{{ID: "11", Name: "oracle-sys", User: "sys", Address: "db1.example.com", Platform: "Oracle", Auto: true,
			Created: t0.Add(-100 * time.Hour), Rotated: t0.Add(-10 * time.Hour)}}}
	switch vendor {
	case "cyberark":
		perms := []string{"listAccounts", "viewSafeMembers"}
		if manage {
			perms = append(perms, "manageSafeMembers")
		}
		s.Members = []pamfake.Member{{Name: pamUser, Type: "User", Perms: perms},
			{Name: "alice", Type: "User", Perms: []string{"listAccounts", "viewSafeMembers", "useAccounts", "retrieveAccounts"}}}
	case "delinea":
		s.Members = []pamfake.Member{{Name: "alice", Type: "User", Folder: "View", Secret: "Edit"}}
	case "beyondtrust":
		s.Members = []pamfake.Member{{Name: "alice", Type: "Group", Roles: []string{"Requestor", "Approver"}}}
	}
	return s
}

func pamRig(t *testing.T, vendor string, manage bool) (governed.Params, governed.Net, *pamfake.Fake) {
	t.Helper()
	fk := pamfake.New(vendor, pamUser, pamSecret)
	fk.Users, fk.Groups = []string{"alice"}, []string{"alice"}
	fk.Set(pamSafe(vendor, manage))
	srv, n := serve(t, fk)
	return governed.Params{Type: vendor, BaseURL: srv.URL, Settings: map[string]string{"username": pamUser}, Secret: pamSecret}, n, fk
}

func TestPAMProber(t *testing.T) {
	for _, vendor := range []string{governed.CyberArk, governed.Delinea, governed.BeyondTrust} {
		t.Run(vendor, func(t *testing.T) {
			p, n, fk := pamRig(t, vendor, false)
			pr := prober(t, p, n)
			wantPass(t, pr, "pam", "endpoint_reachable", "auth_ok", "read_probe")
			if _, _, writes := fk.Counts(); writes != 0 {
				t.Errorf("the probe wrote %d times", writes)
			}
			s, err := pr.Sample(context.Background(), connectors.SampleQuery{Op: "probe"})
			if err != nil || s.PerClass["safe"] != 1 || s.PerClass["member"] < 1 || s.PerClass["vaulted_account"] != 1 {
				t.Errorf("sample = %+v, %v", s, err)
			}
		})
	}
}

func TestPAMProber_WrongPassword(t *testing.T) {
	p, n, _ := pamRig(t, governed.CyberArk, false)
	p.Secret = "not-the-password"
	r := run(t, prober(t, p, n), "auth_ok", checks.Env{TemplateID: "pam"})
	if r.Status != checks.Fail {
		t.Errorf("auth_ok with a wrong password: %s %s", r.Status, r.Message)
	}
}

// With write-back enabled the write scope must cover every safe the service
// user can manage the members of; read-only, the user must manage none.
func TestPAMProber_EffectiveRights(t *testing.T) {
	p, n, _ := pamRig(t, governed.CyberArk, true)
	pr := prober(t, p, n)
	if r := run(t, pr, "effective_rights", checks.Env{TemplateID: "pam"}); r.Status != checks.Fail {
		t.Errorf("read-only with Manage Safe Members: %s %s", r.Status, r.Message)
	}
	if r := run(t, pr, "write_scope", checks.Env{TemplateID: "pam", WriteScope: []string{"7"}}); r.Status != checks.Pass {
		t.Errorf("write scope covering the safe: %s %s", r.Status, r.Message)
	}
	if r := run(t, pr, "write_scope", checks.Env{TemplateID: "pam", WriteScope: []string{"8"}}); r.Status != checks.Fail {
		t.Errorf("write scope missing the safe: %s %s", r.Status, r.Message)
	}
	p, n, _ = pamRig(t, governed.CyberArk, false)
	if r := run(t, prober(t, p, n), "effective_rights", checks.Env{TemplateID: "pam"}); r.Status != checks.Pass {
		t.Errorf("read-only without it: %s %s", r.Status, r.Message)
	}
}

func TestPAMConnector(t *testing.T) {
	p, n, _ := pamRig(t, governed.CyberArk, false)
	cn, err := wire.Connector(p, n)
	if err != nil {
		t.Fatal(err)
	}
	if cn.System() != "cyberark" {
		t.Errorf("system = %s", cn.System())
	}
	res, err := cn.Discover(context.Background())
	if err != nil || len(res.Accounts) == 0 || len(res.Groups) == 0 {
		t.Fatalf("discover = %+v, %v", res, err)
	}
	// the dry run's data checks read class counts the connector itself does not report
	us := res.Stats.Classes["user"]
	if us == nil || us.Total != len(res.Accounts) || us.Attributes["id"].Present != us.Total || us.Attributes["id"].Distinct != us.Total {
		t.Errorf("stats = %+v", us)
	}
}

// ---------------------------------------------------------------- ERP

const erpID, erpSecret = "tessera-client", "s3cret-value"

func erpRig(t *testing.T, system string) (governed.Params, governed.Net) {
	t.Helper()
	fk := erpfake.New(system, erpID, erpSecret)
	fk.Set([]erpfake.Role{{ID: "Z_AP", Name: "Accounts payable", TCodes: []string{"FB60"}}},
		[]erpfake.User{{ID: "AP.CLERK", Name: "Ada Clerk", Email: "ada@corp.example", Roles: []erpfake.Assign{{Role: "Z_AP"}}}})
	srv, n := serve(t, fk)
	return governed.Params{Type: system, BaseURL: srv.URL, Settings: map[string]string{"client_id": erpID}, Secret: erpSecret}, n
}

func TestERPProber(t *testing.T) {
	for _, system := range []string{governed.SAP, governed.Oracle} {
		t.Run(system, func(t *testing.T) {
			p, n := erpRig(t, system)
			pr := prober(t, p, n)
			wantPass(t, pr, "erp", "endpoint_reachable", "auth_ok", "read_probe")
			// the integration's own rights cannot be read from an ERP: unsupported, so the
			// write-scope item needs an attestation rather than passing blind
			r := run(t, pr, "write_scope", checks.Env{TemplateID: "erp", WriteScope: []string{"Z_AP"}})
			if r.Status != checks.Skipped || r.Observed["unsupported"] != true {
				t.Errorf("write_scope: %s %s", r.Status, r.Message)
			}
			cn, err := wire.Connector(p, n)
			if err != nil {
				t.Fatal(err)
			}
			if res, err := cn.Discover(context.Background()); err != nil || cn.System() != system || len(res.Accounts) != 1 {
				t.Errorf("discover: %v %v", res, err)
			}
		})
	}
}

func TestERPProber_WrongSecret(t *testing.T) {
	p, n := erpRig(t, governed.SAP)
	p.Secret = "wrong"
	if r := run(t, prober(t, p, n), "auth_ok", checks.Env{TemplateID: "erp"}); r.Status != checks.Fail {
		t.Errorf("auth_ok with a wrong secret: %s %s", r.Status, r.Message)
	}
}

// ---------------------------------------------------------------- GitHub

func githubRig(t *testing.T) (governed.Params, governed.Net) {
	t.Helper()
	srv, n := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ghp-token" {
			http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/orgs/acme/repos" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `[{"name":"agents","default_branch":"main"},{"name":"old","default_branch":"main","archived":true},{"name":"fork","default_branch":"main","fork":true}]`)
	}))
	return governed.Params{Type: governed.GitHubScan, BaseURL: srv.URL, Settings: map[string]string{"org": "acme"}, Secret: "ghp-token"}, n
}

func TestGitHubProber(t *testing.T) {
	p, n := githubRig(t)
	pr := prober(t, p, n)
	wantPass(t, pr, "githubscan", "endpoint_reachable", "auth_ok", "read_probe")
	s, _ := pr.Sample(context.Background(), connectors.SampleQuery{})
	if s.PerClass["repository"] != 1 {
		t.Errorf("repositories = %v; archived and forked repositories are skipped", s.PerClass)
	}
	p.Secret = "wrong"
	if r := run(t, prober(t, p, n), "auth_ok", checks.Env{TemplateID: "githubscan"}); r.Status != checks.Fail {
		t.Errorf("auth_ok with a wrong token: %s %s", r.Status, r.Message)
	}
	p.Settings = map[string]string{"org": "other"}
	p.Secret = "ghp-token"
	if r := run(t, prober(t, p, n), "read_probe", checks.Env{TemplateID: "githubscan"}); r.Status == checks.Pass {
		t.Errorf("read_probe of an organization the token cannot list passed: %s", r.Message)
	}
}

func TestGitHubConnector(t *testing.T) {
	p, n := githubRig(t)
	cn, err := wire.Connector(p, n)
	if err != nil {
		t.Fatal(err)
	}
	if cn.System() != "github-scan" {
		t.Errorf("system = %s", cn.System())
	}
}

// ---------------------------------------------------------------- contractor feeds

func TestVMSProber(t *testing.T) {
	for _, vendor := range []string{governed.Fieldglass, governed.Beeline} {
		t.Run(vendor, func(t *testing.T) {
			fk := vmsfake.New(vendor, "client-1", "s3cret-value")
			fk.Set(vmsfake.Worker{ID: "W-1", First: "Casey", Last: "Contractor", Email: "casey@agency.example", Status: "Active",
				Start: "2026-09-01", End: "2026-12-31", Supplier: "Acme", Role: "Analyst", ManagerEmail: "dana@corp.example", Modified: t0})
			srv, n := serve(t, fk)
			p := governed.Params{Type: vendor, BaseURL: srv.URL, Secret: "client-1:s3cret-value"}
			wantPass(t, prober(t, p, n), "vms", "endpoint_reachable", "auth_ok", "read_probe")
			p.Secret = "client-1:wrong"
			if r := run(t, prober(t, p, n), "auth_ok", checks.Env{TemplateID: "vms"}); r.Status != checks.Fail {
				t.Errorf("auth_ok with a wrong secret: %s %s", r.Status, r.Message)
			}
		})
	}
}

func TestVMSProber_CSVFeed(t *testing.T) {
	srv, n := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-123" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/csv")
		fmt.Fprint(w, "worker_id,name,email,supplier,role,sponsor_email,status,start_date,end_date\n"+
			"W1,Casey Contractor,casey@agency.example,Acme,Analyst,dana@corp.example,active,2026-09-01,2026-12-31\n")
	}))
	p := governed.Params{Type: governed.CSVFeed, BaseURL: srv.URL, Settings: map[string]string{"csv_path": "/feeds/contractors.csv"}, Secret: "tok-123"}
	wantPass(t, prober(t, p, n), "vms", "auth_ok", "read_probe")
	p.Secret = "wrong"
	if r := run(t, prober(t, p, n), "auth_ok", checks.Env{TemplateID: "vms"}); r.Status != checks.Fail {
		t.Errorf("auth_ok with a wrong token: %s %s", r.Status, r.Message)
	}
}

// ---------------------------------------------------------------- AgentCore

const tenant = "00000000-0000-4000-8000-0000000000e1"

func agentcoreRig(t *testing.T) governed.Params {
	t.Helper()
	data := t.TempDir()
	dir := filepath.Join(data, tenant)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "agentcore", "testdata", "runtimes.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "snap.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return governed.Params{Type: governed.AgentCore, Settings: map[string]string{"snapshot": "snap.json"}, Tenant: tenant, DataDir: data}
}

func TestAgentCore(t *testing.T) {
	p := agentcoreRig(t)
	n := governed.Net{Now: func() time.Time { return t0 }}
	wantPass(t, prober(t, p, n), "agentcore", "read_probe", "cred_storage")
	cn, err := wire.Connector(p, n)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := cn.Discover(context.Background()); err != nil || cn.System() != "aws-agentcore" || len(res.Agents) != 3 {
		t.Errorf("discover = %+v, %v", res, err)
	}
}

// The snapshot is a file on the server: a tenant's connection reads only its
// own directory, only a plain file name, and never in production (no live client).
func TestAgentCore_Confinement(t *testing.T) {
	n := governed.Net{Now: func() time.Time { return t0 }}
	p := agentcoreRig(t)

	prod := p
	prod.Prod = true
	if _, err := wire.Prober(prod, n); err == nil || !strings.Contains(err.Error(), "prod") {
		t.Errorf("prod prober: %v", err)
	}
	if _, err := wire.Connector(prod, n); err == nil {
		t.Error("prod connector accepted")
	}

	for name, snap := range map[string]string{"parent": "../x.json", "absolute": "/etc/passwd", "nested": "a/b.json", "missing": "nope.json", "empty": ""} {
		q := p
		q.Settings = map[string]string{"snapshot": snap}
		if _, err := wire.Prober(q, n); err == nil {
			t.Errorf("%s: accepted %q", name, snap)
		}
	}
	other := p
	other.Tenant = "00000000-0000-4000-8000-0000000000e2" // a tenant with no directory
	if _, err := wire.Prober(other, n); err == nil {
		t.Error("another tenant read this tenant's file")
	}
	bad := p
	bad.Tenant = "../" + tenant
	if _, err := wire.Prober(bad, n); err == nil {
		t.Error("a tenant id with a path accepted")
	}
	noDir := p
	noDir.DataDir = ""
	if _, err := wire.Prober(noDir, n); err == nil {
		t.Error("no data directory accepted")
	}

	// a symbolic link out of the tenant's directory is refused
	secret := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(secret, []byte(`{"runtimes":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(p.DataDir, tenant, "link.json")); err != nil {
		t.Skip("no symlinks here")
	}
	q := p
	q.Settings = map[string]string{"snapshot": "link.json"}
	if _, err := wire.Prober(q, n); err == nil {
		t.Error("a symlink out of the tenant directory was followed")
	}
}

// ---------------------------------------------------------------- params

func TestParamsNeverPrintTheSecret(t *testing.T) {
	p := governed.Params{Type: governed.SAP, BaseURL: "https://s4.example.com", Settings: map[string]string{"client_id": "c"}, Secret: "TOP-SECRET-VALUE"}
	for _, f := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		if got := fmt.Sprintf(f, p); strings.Contains(got, "TOP-SECRET-VALUE") {
			t.Errorf("%s prints the secret: %s", f, got)
		}
	}
	// the connectors' own mapping reads the secret only through the closure
	env, err := p.Env()
	if err != nil {
		t.Fatal(err)
	}
	if v := env("TESSERA_SAP_CLIENT_SECRET"); strings.Contains(v, "TOP-SECRET") || !strings.HasPrefix(v, "env:") {
		t.Errorf("the secret reference = %q", v)
	}
	if v := os.Getenv("TESSERA_GOVERNED_SECRET"); v != "" {
		t.Error("the secret reached the process environment")
	}
}

func TestFeatureTypesHaveNoConnector(t *testing.T) {
	for _, typ := range []string{governed.AWSOrg, governed.Fieldglass, governed.Beeline, governed.CSVFeed} {
		if _, err := wire.Connector(governed.Params{Type: typ}, governed.Net{}); err == nil {
			t.Errorf("%s: a connector was built; its own feature reads it", typ)
		}
	}
	if _, err := wire.Prober(governed.Params{Type: "ldap"}, governed.Net{}); err == nil {
		t.Error("a prober for a type outside the registry")
	}
}
