package agent_test

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/agent"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

func TestConfig_PushTargets(t *testing.T) {
	base := `{"server_url":"https://t.example:8443","server_ca_file":"/ca.pem","state_dir":"/var/lib/a","allowed_targets":["ldap.corp.example:636"]`
	plain, err := agent.ParseConfig([]byte(base + `}`))
	if err != nil || len(plain.AllowPush()) != 0 {
		t.Fatalf("%v %v", plain, err)
	}
	withPush, err := agent.ParseConfig([]byte(base + `,"allowed_push_targets":["scim.corp.example:443","10.20.0.0/24:8443"],"push_ca_file":"/push-ca.pem"}`))
	if err != nil || len(withPush.AllowPush()) != 2 || withPush.PushCAFile != "/push-ca.pem" {
		t.Fatalf("%v %v", withPush, err)
	}
	// the hash of an agent that does not use pushes is what it always was; using them changes it; order and case do not
	if plain.AllowlistHash() == withPush.AllowlistHash() {
		t.Error("the allowlist hash ignores the push list")
	}
	reordered, _ := agent.ParseConfig([]byte(base + `,"allowed_push_targets":["10.20.0.0/24:8443","SCIM.corp.example:443"]}`))
	if reordered.AllowlistHash() != withPush.AllowlistHash() {
		t.Error("the allowlist hash depends on the order or case of the push list")
	}
	legacy := `{"server_url":"https://t.example:8443","server_ca_file":"/ca.pem","state_dir":"/var/lib/a","allowed_targets":["ldap.corp.example:636"]}`
	legacyCfg, _ := agent.ParseConfig([]byte(legacy))
	if legacyCfg.AllowlistHash() != plain.AllowlistHash() {
		t.Error("an empty push list changed the hash")
	}
	// the LDAP list and the push list take different ports: allowing a directory never allows a web service
	for name, raw := range map[string]string{
		"ldap port in the push list":  base + `,"allowed_push_targets":["scim.corp.example:636"]}`,
		"http port":                   base + `,"allowed_push_targets":["scim.corp.example:80"]}`,
		"https port in the ldap list": `{"server_url":"u","server_ca_file":"c","state_dir":"s","allowed_targets":["scim.corp.example:443"]}`,
		"wildcard":                    base + `,"allowed_push_targets":["*.corp.example:443"]}`,
		"broad cidr":                  base + `,"allowed_push_targets":["10.0.0.0/8:443"]}`,
		"joined":                      base + `,"allowed_push_targets":["a.corp:443,b.corp:443"]}`,
	} {
		if _, err := agent.ParseConfig([]byte(raw)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestLoadOrCreateSealKey(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "id")
	k1, err := agent.LoadOrCreateSealKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := agent.LoadOrCreateSealKey(dir)
	if err != nil || !k1.Equal(k2) {
		t.Fatalf("the sealing key changed between loads: %v", err)
	}
	other, _ := agent.LoadOrCreateSealKey(filepath.Join(t.TempDir(), "id"))
	if k1.Equal(other) {
		t.Error("two agents share a sealing key")
	}
	if os.PathSeparator != '\\' {
		if fi, err := os.Stat(filepath.Join(dir, "seal.key")); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("key file: %v %v", fi, err)
		}
	}
	// a damaged or foreign key file is refused, never replaced
	if err := os.WriteFile(filepath.Join(dir, "seal.key"), []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.LoadOrCreateSealKey(dir); err == nil {
		t.Error("a damaged key file was accepted")
	}
}

// failResolver fails the test if anything resolves a name.
type failResolver struct{ t *testing.T }

func (r failResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.t.Errorf("a host name was resolved before the agent's checks passed: %s", host)
	return nil, errors.New("no resolver")
}

func pushJob(t *testing.T, mut func(*agent.PulledJob)) agent.PulledJob {
	t.Helper()
	j := agent.PulledJob{ID: "job-1", Kind: agent.KindPush, ConnectionID: "conn-1", Push: &agent.PushJob{
		TenantID: "00000000-0000-4000-8000-0000000000a1", AgentID: "agent-1",
		Spec: target.PushSpec{OpID: "op-1", Target: "scim", BaseURL: "https://scim.corp.example/scim/v2", Op: target.DisableAccount,
			Key: "k1", Account: target.Account{Username: "alice"}}}}
	if mut != nil {
		mut(&j)
	}
	return j
}

// The agent refuses what it must refuse before it resolves or dials anything.
func TestExecutePush_Refusals(t *testing.T) {
	allow, _ := safedial.ParseAllowHTTPS("scim.corp.example:443")
	key, _ := seal.GenerateAgentKey()
	other, _ := seal.GenerateAgentKey()
	tenant := tenancy.MustParse("00000000-0000-4000-8000-0000000000a1")
	aad, _ := seal.AgentAAD(tenant, "agent-1", "conn-1", "job-1")
	good, _ := seal.SealToAgent(key.PublicKey(), []byte("tok"), aad)
	foreign, _ := seal.SealToAgent(other.PublicKey(), []byte("tok"), aad)

	ex := func() *agent.Executor {
		// a resolver that fails: nothing below may reach it
		return &agent.Executor{AllowPush: allow, SealKey: key, Resolver: failResolver{t}}
	}
	for name, tc := range map[string]struct {
		mut  func(*agent.PulledJob)
		exec *agent.Executor
		want string
	}{
		"another job kind":   {func(j *agent.PulledJob) { j.Kind = "sync" }, ex(), agent.CodeUnknownOp},
		"no push body":       {func(j *agent.PulledJob) { j.Push = nil }, ex(), agent.CodeUnknownOp},
		"no job id":          {func(j *agent.PulledJob) { j.ID = "" }, ex(), agent.CodeBadRequest},
		"an http target":     {func(j *agent.PulledJob) { j.Push.Spec.BaseURL = "http://scim.corp.example/v2" }, ex(), agent.CodeBadRequest},
		"an unknown target":  {func(j *agent.PulledJob) { j.Push.Spec.Target = "ldap" }, ex(), agent.CodeBadRequest},
		"a host not listed":  {func(j *agent.PulledJob) { j.Push.Spec.BaseURL = "https://evil.example/v2" }, ex(), agent.CodeTargetNotAllowed},
		"a port not listed":  {func(j *agent.PulledJob) { j.Push.Spec.BaseURL = "https://scim.corp.example:8443/v2" }, ex(), agent.CodeTargetNotAllowed},
		"an empty allowlist": {nil, &agent.Executor{SealKey: key, Resolver: failResolver{t}}, agent.CodeTargetNotAllowed},
		"a sealed credential but no key": {func(j *agent.PulledJob) { j.Push.SealedCredential = good },
			&agent.Executor{AllowPush: allow, Resolver: failResolver{t}}, agent.CodeNoCredential},
		"a credential sealed to another agent": {func(j *agent.PulledJob) { j.Push.SealedCredential = foreign }, ex(), agent.CodeNoCredential},
		"a credential for another job":         {func(j *agent.PulledJob) { j.Push.SealedCredential = good; j.ID = "job-2" }, ex(), agent.CodeNoCredential},
		"a credential for another connection":  {func(j *agent.PulledJob) { j.Push.SealedCredential = good; j.ConnectionID = "conn-2" }, ex(), agent.CodeNoCredential},
		"a credential for another tenant": {func(j *agent.PulledJob) {
			j.Push.SealedCredential = good
			j.Push.TenantID = "00000000-0000-4000-8000-0000000000b1"
		}, ex(), agent.CodeNoCredential},
		"a tenant that is not an id": {func(j *agent.PulledJob) { j.Push.SealedCredential = good; j.Push.TenantID = "acme" }, ex(), agent.CodeBadRequest},
		"a credential name nobody has": {func(j *agent.PulledJob) { j.Push.Spec.CredName = "svc" },
			&agent.Executor{AllowPush: allow, Creds: &memCreds{m: map[string]string{}}, Resolver: failResolver{t}}, agent.CodeNoCredential},
	} {
		res := tc.exec.ExecutePush(context.Background(), pushJob(t, tc.mut))
		if res.Error == nil || res.Error.Code != tc.want || res.Push != nil {
			t.Errorf("%s: %+v (want %s)", name, res.Error, tc.want)
		} else if strings.Contains(res.Error.Message, "tok") && tc.want != agent.CodeUnknownOp {
			t.Errorf("%s: the message mentions the credential: %q", name, res.Error.Message)
		}
	}
}
