package bedrockagents_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/bedrockagents"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/bedrockagents/bedrockfake"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

var t0 = time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)

const (
	akid   = "AKIAIOSFODNN7EXAMPLE"
	secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	region = "us-east-1"
	acct   = "123456789012"
)

func arn(id string) string { return "arn:aws:bedrock:" + region + ":" + acct + ":agent/" + id }

func agents() []bedrockfake.Agent {
	return []bedrockfake.Agent{
		{ID: "AGENT00001", Name: "support-bot", ARN: arn("AGENT00001"), Status: "PREPARED", Description: "Answers tickets", Created: 1760000000,
			Role: "arn:aws:iam::" + acct + ":role/service-role/AmazonBedrockExecutionRoleForAgents_support", Model: "anthropic.claude-3-5-sonnet-20241022-v2:0",
			Tags: map[string]string{"Sponsor": "Pat@Acme.example", "creator": "arn:aws:iam::" + acct + ":user/deploy", "pii": "true"},
			Groups: []bedrockfake.Group{
				{ID: "GRP0000001", Name: "tickets", State: "ENABLED", Lambda: "arn:aws:lambda:" + region + ":" + acct + ":function:tickets", Functions: []string{"create", "close"}},
				{ID: "GRP0000002", Name: "code", State: "ENABLED", Signature: "AMAZON.CodeInterpreter"},
				{ID: "GRP0000003", Name: "off", State: "DISABLED", Lambda: "arn:aws:lambda:" + region + ":" + acct + ":function:off"},
				{ID: "GRP0000004", Name: "user-input", State: "ENABLED", Signature: "AMAZON.UserInput"}},
			KBs: []bedrockfake.KB{{ID: "KB00000001", State: "ENABLED"}, {ID: "KB00000002", State: "DISABLED"}}},
		{ID: "AGENT00002", Name: "ops-bot", ARN: arn("AGENT00002"), Status: "FAILED", Role: "arn:aws:iam::" + acct + ":role/ops", Model: "amazon.titan-text-premier-v1:0",
			Tags: map[string]string{"owner": "a-team"}},
	}
}

type rig struct {
	fake *bedrockfake.Fake
	cfg  bedrockagents.Config
	open func(bedrockagents.Config) (*bedrockagents.Client, error)
}

func credJSON(token string) string {
	b, _ := json.Marshal(map[string]string{"access_key_id": akid, "secret_access_key": secret, "session_token": token})
	return string(b)
}

func newRig(t *testing.T, token string, mut func(*bedrockfake.Fake)) *rig {
	t.Helper()
	fk := bedrockfake.New(akid, secret, token, region, agents()...)
	if mut != nil {
		mut(fk)
	}
	return newRigWith(t, fk, token)
}

func newRigWith(t *testing.T, fk *bedrockfake.Fake, token string) *rig {
	t.Helper()
	srv := connsynctest.New(t, fk)
	hc, err := safehttp.NewForTest(t, srv.Options(0))
	if err != nil {
		t.Fatal(err)
	}
	cfg := bedrockagents.Config{Region: region, Secret: connsync.NewSecret(credJSON(token)), AgentURL: srv.URL, Sleep: func(context.Context, time.Duration) error { return nil }}
	return &rig{fk, cfg, func(c bedrockagents.Config) (*bedrockagents.Client, error) {
		cl, err := bedrockagents.Open(c, connsynctest.Runtime, hc, func() time.Time { return t0 })
		return cl, err
	}}
}

func (r *rig) discover(t *testing.T) *connectors.DiscoveryResult {
	t.Helper()
	c, err := r.open(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	res, err := bedrockagents.NewConnector(c, func() time.Time { return t0 }).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestDiscoverMapsAgentsToolsAndOwners(t *testing.T) {
	for _, tc := range []struct {
		name  string
		token string
		page  int
	}{{"long-term keys", "", 0}, {"session token, paged", "FwoGZXIvYXdzEXAMPLETOKEN", 1}} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, tc.token, func(f *bedrockfake.Fake) { f.PageSize = tc.page })
			res := r.discover(t)
			if r.fake.BadSignatures() != 0 || r.fake.Writes() != 0 {
				t.Fatalf("bad signatures %d, writes %d", r.fake.BadSignatures(), r.fake.Writes())
			}
			if len(res.Identities) != 2 || len(res.Agents) != 2 || len(res.Accounts) != 2 {
				t.Fatalf("identities %d agents %d accounts %d", len(res.Identities), len(res.Agents), len(res.Accounts))
			}
			bot, ops := res.Identities[0], res.Identities[1]
			if bot.ExternalID != "bedrock:AGENT00001" || bot.Type != "ai_agent" || bot.Owner == nil || bot.Owner.Email != "pat@acme.example" || bot.Status != "active" {
				t.Errorf("support-bot = %+v", bot)
			}
			if ops.Status != "disabled" || ops.Owner != nil {
				t.Errorf("ops-bot = %+v", ops)
			}
			if a := res.Agents[0]; a.Kind != "bedrock_agent" || a.SponsorRef != "Pat@Acme.example" || !strings.HasPrefix(a.CreatorRef, "arn:aws:iam::") || a.Creator != nil {
				t.Errorf("agent record = %+v", a)
			}
			if a := res.Agents[1]; a.SponsorRef != "a-team" || a.Sponsor != nil {
				t.Errorf("unresolvable owner = %+v", a)
			}
			acts := map[string]connectors.PermissionRecord{}
			for _, p := range res.Permissions {
				acts[p.ExternalID] = p
			}
			wantPriv := map[string]bool{
				"arn:aws:lambda:us-east-1:123456789012:function:tickets#lambda:InvokeFunction": false,
				"bedrock-action-group:AGENT00001/GRP0000002#return_control":                    true, // the code interpreter
				"bedrock-action-group:AGENT00001/GRP0000004#return_control":                    false,
				"bedrock-knowledge-base:KB00000001#bedrock:Retrieve":                           false,
				"bedrock-model:anthropic.claude-3-5-sonnet-20241022-v2:0#bedrock:InvokeModel":  false,
			}
			for k, v := range wantPriv {
				p, ok := acts[k]
				if !ok || p.Privileged != v {
					t.Errorf("%s = %+v (present %v), want privileged %v", k, p, ok, v)
				}
			}
			for k := range acts {
				if strings.Contains(k, ":off#") || strings.Contains(k, "KB00000002") || strings.Contains(k, "GRP0000003") {
					t.Errorf("a disabled tool is granted: %s", k)
				}
			}
			for _, rs := range res.Resources {
				if !slices.Contains(rs.Tags, "pii") && (strings.Contains(rs.ExternalID, "AGENT00001") || strings.Contains(rs.ExternalID, "KB00000001")) {
					t.Errorf("%s lacks the pii tag", rs.ExternalID)
				}
			}
			if !slices.Equal(res.AgentSnapshotOf, []string{"aws-bedrock"}) {
				t.Errorf("snapshot of = %v", res.AgentSnapshotOf)
			}
			if got := fmt.Sprintf("%+v", res); strings.Contains(got, "free text the connector must not keep") || strings.Contains(got, "Answers tickets") || strings.Contains(got, secret) {
				t.Error("a description or the secret was kept")
			}
			if len(res.Identities) != len(res.Accounts) || res.Accounts[0].CreatedAt == nil || !res.Accounts[0].CreatedAt.Equal(time.Unix(1760000000, 0).UTC()) {
				t.Errorf("account = %+v", res.Accounts[0])
			}
			edges := 0
			for _, e := range res.Edges {
				if e.Src.ExternalID == "AGENT00001" && e.Relation == "direct_grant" {
					edges++
				}
			}
			if edges != 5+1 { // role, model, tickets, code, user-input, knowledge base
				t.Errorf("support-bot edges = %d", edges)
			}
		})
	}
}

func TestFaults(t *testing.T) {
	for _, tc := range []struct {
		name   string
		faults bedrockfake.Faults
		cfg    func(*bedrockagents.Config)
		is     error
		text   string
		ok     bool
	}{
		{name: "throttled then served", faults: bedrockfake.Faults{Throttle: 2}, ok: true},
		{name: "server error then served", faults: bedrockfake.Faults{ServerErr: 1}, ok: true},
		{name: "agent deleted mid-read", faults: bedrockfake.Faults{Gone: "AGENT00002"}, ok: true},
		{name: "access denied", faults: bedrockfake.Faults{Deny: true}, text: "HTTP 403 (AccessDeniedException)"},
		{name: "wrong secret", cfg: func(c *bedrockagents.Config) {
			b, _ := json.Marshal(map[string]string{"access_key_id": akid, "secret_access_key": "x" + secret})
			c.Secret = connsync.NewSecret(string(b))
		}, is: bedrockagents.ErrCredential},
		{name: "not json", faults: bedrockfake.Faults{NotJSON: true}, is: connsync.ErrMalformed},
		{name: "never recovers", faults: bedrockfake.Faults{Throttle: 100}, text: "gave up"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, "", func(f *bedrockfake.Fake) { f.SetFaults(tc.faults) })
			if tc.cfg != nil {
				tc.cfg(&r.cfg)
			}
			c, err := r.open(r.cfg)
			if err != nil {
				t.Fatal(err)
			}
			res, err := bedrockagents.NewConnector(c, nil).Discover(context.Background())
			if tc.ok {
				if err != nil {
					t.Fatal(err)
				}
				if tc.faults.Gone != "" && len(res.Identities) != 1 {
					t.Errorf("identities = %d", len(res.Identities))
				}
				return
			}
			if err == nil {
				t.Fatal("no error")
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Errorf("err = %v, want %v", err, tc.is)
			}
			if tc.text != "" && !strings.Contains(err.Error(), tc.text) {
				t.Errorf("err = %v, want text %q", err, tc.text)
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("the error carries the secret: %v", err)
			}
		})
	}
}

func TestProbe(t *testing.T) {
	r := newRig(t, "", nil)
	c, err := r.open(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.Probe(context.Background())
	if err != nil || p.Agents != 2 || c.Identity() != akid || c.Mode() != "sigv4_access_key" {
		t.Errorf("probe = %+v, %v (%s, %s)", p, err, c.Identity(), c.Mode())
	}
	if ops := r.fake.Ops(); len(ops) != 1 || ops["ListAgents"] != 1 {
		t.Errorf("ops = %v", ops)
	}
}

func TestOpenValidates(t *testing.T) {
	r := newRig(t, "", nil)
	good := r.cfg
	for _, tc := range []struct {
		name string
		mut  func(*bedrockagents.Config)
	}{
		{"region", func(c *bedrockagents.Config) { c.Region = "us-east-1.evil.example" }},
		{"empty region", func(c *bedrockagents.Config) { c.Region = "" }},
		{"not json", func(c *bedrockagents.Config) { c.Secret = connsync.NewSecret("AKIA...") }},
		{"unknown field", func(c *bedrockagents.Config) {
			c.Secret = connsync.NewSecret(`{"access_key_id":"` + akid + `","secret_access_key":"` + secret + `","x":1}`)
		}},
		{"short key id", func(c *bedrockagents.Config) {
			c.Secret = connsync.NewSecret(`{"access_key_id":"AKIA","secret_access_key":"` + secret + `"}`)
		}},
		{"space in secret", func(c *bedrockagents.Config) {
			c.Secret = connsync.NewSecret(`{"access_key_id":"` + akid + `","secret_access_key":"abc def ghi jkl mno pqr"}`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := good
			tc.mut(&cfg)
			if _, err := r.open(cfg); err == nil {
				t.Error("accepted")
			}
		})
	}
	// an endpoint override is a dev setting
	hc, err := safehttp.NewForTest(t, connsynctest.New(t, r.fake).Options(0))
	if err != nil {
		t.Fatal(err)
	}
	for _, env := range []string{config.Prod, config.Test} {
		if _, err := bedrockagents.Open(good, connsync.Runtime{Env: env}, hc, nil); err == nil || !strings.Contains(err.Error(), "refused outside dev") {
			t.Errorf("%s accepted an override: %v", env, err)
		}
	}
	// without an override, only the region's own endpoint
	prod := connsync.Runtime{Env: config.Prod}
	ok := bedrockagents.Config{Region: region, Secret: good.Secret}
	if _, err := bedrockagents.Open(ok, prod, hc, nil); err != nil {
		t.Errorf("prod default endpoint: %v", err)
	}
	if got := bedrockagents.DefaultURL("cn-north-1"); got != "https://bedrock-agent.cn-north-1.amazonaws.com.cn" {
		t.Errorf("cn url = %s", got)
	}
	if _, err := bedrockagents.Open(bedrockagents.Config{Region: region, Secret: good.Secret, AgentURL: "https://evil.example"}, prod, hc, nil); err == nil {
		t.Error("prod accepted another host")
	}
	if _, err := bedrockagents.Open(good, connsynctest.Runtime, nil, nil); err == nil {
		t.Error("no client accepted")
	}
}

func TestReaderPolicyIsReadOnly(t *testing.T) {
	var doc struct {
		Statement []struct {
			Effect string
			Action []string
		}
	}
	if err := json.Unmarshal([]byte(bedrockagents.ReaderPolicy), &doc); err != nil {
		t.Fatal(err)
	}
	for _, st := range doc.Statement {
		for _, a := range st.Action {
			op := strings.TrimPrefix(a, "bedrock:")
			if !strings.HasPrefix(op, "List") && !strings.HasPrefix(op, "Get") {
				t.Errorf("%s is not a read", a)
			}
		}
	}
}

func TestSecretNeverPrinted(t *testing.T) {
	r := newRig(t, "TOKEN-VALUE-1234", nil)
	for _, v := range []any{r.cfg} {
		if got := fmt.Sprintf("%v %+v %#v", v, v, v); strings.Contains(got, secret) || strings.Contains(got, "TOKEN-VALUE") {
			t.Errorf("prints the credential: %s", got)
		}
	}
	c, err := r.open(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%v %+v", c, c); strings.Contains(got, secret) {
		t.Errorf("client prints the credential: %.300s", got)
	}
	if c.Mode() != "sigv4_session" {
		t.Errorf("mode = %s", c.Mode())
	}
}

func TestFromEnv(t *testing.T) {
	r := newRig(t, "", nil)
	env := map[string]string{"TESSERA_BEDROCK_REGION": region, "TESSERA_BEDROCK_CREDENTIAL": "env:K", "K": credJSON(""), "TESSERA_BEDROCK_AGENT_URL": r.cfg.AgentURL}
	get := func(k string) string { return env[k] }
	hc, _ := safehttp.NewForTest(t, connsynctest.New(t, r.fake).Options(0))
	cn, err := bedrockagents.FromEnv(get, connsynctest.Runtime, hc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cn.System() != "aws-bedrock" {
		t.Errorf("system = %s", cn.System())
	}
	env["TESSERA_BEDROCK_CREDENTIAL"] = credJSON("") // a literal credential is refused
	if _, err := bedrockagents.FromEnv(get, connsynctest.Runtime, hc, nil); err == nil {
		t.Error("literal credential accepted")
	}
}

// The ARN of ListTagsForResource goes on the wire as one strictly encoded segment (written out by hand here);
// the sigv4 package's TestCanonicalPath_EncodedSlashSegment pins how that path signs.
func TestTagsPathIsOneEncodedSegment(t *testing.T) {
	r := newRig(t, "", nil)
	r.discover(t)
	const want = "/tags/arn%3Aaws%3Abedrock%3Aus-east-1%3A123456789012%3Aagent%2FAGENT00001"
	if !slices.Contains(r.fake.Paths(), want) {
		t.Errorf("no request to %s in %v", want, r.fake.Paths())
	}
	if r.fake.BadSignatures() != 0 {
		t.Errorf("%d bad signatures", r.fake.BadSignatures())
	}
}

// A status that is not an AWS enum value is not kept, and an agent with too many enabled action groups fails
// the read rather than costing one call each.
func TestUntrustedShapesAreBounded(t *testing.T) {
	r := newRigWith(t, bedrockfake.New(akid, secret, "", region, bedrockfake.Agent{ID: "AGENT00009", Name: "x", ARN: arn("AGENT00009"), Status: "PREPARED\nINJECTED"}), "")
	res := r.discover(t)
	if got := res.Accounts[0].Attributes["agent_status"]; got != "" {
		t.Errorf("agent_status = %q", got)
	}
	var groups []bedrockfake.Group
	for i := 0; i < 201; i++ {
		groups = append(groups, bedrockfake.Group{ID: fmt.Sprintf("GRP%07d", i), Name: "g", State: "ENABLED"})
	}
	r3 := newRigWith(t, bedrockfake.New(akid, secret, "", region, bedrockfake.Agent{ID: "AGENT00010", Name: "y", ARN: arn("AGENT00010"), Status: "PREPARED", Groups: groups}), "")
	c, err := r3.open(r3.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bedrockagents.NewConnector(c, nil).Discover(context.Background()); err == nil || !strings.Contains(err.Error(), "more action groups") {
		t.Errorf("201 action groups: %v", err)
	}
	if n := r3.fake.Ops()["GetAgentActionGroup"]; n != 0 {
		t.Errorf("%d GetAgentActionGroup calls before the bound", n)
	}
}
