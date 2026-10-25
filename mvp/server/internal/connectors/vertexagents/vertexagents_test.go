package vertexagents_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/vertexagents"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/vertexagents/vertexfake"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

var t0 = time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)

const (
	sa      = "tessera-reader@acme-agents-prod.iam.gserviceaccount.com"
	project = "acme-agents-prod"
	loc     = "us-central1"
	runAs   = "support-agent@acme-agents-prod.iam.gserviceaccount.com"
)

func engines() []vertexfake.Engine {
	return []vertexfake.Engine{
		{ID: "1001", DisplayName: "support-agent", CreateTime: "2026-09-01T10:00:00Z", ServiceAccount: runAs,
			Labels: map[string]string{"sponsor": "pat_acme", "creator": "olu", "pii": "true"}, Secrets: []string{"crm-api-key", "projects/acme-agents-prod/secrets/db-password"},
			Description: "free text the connector must not keep", Env: map[string]string{"API_BASE": "https://internal.example/very-secret-env-value"}},
		{ID: "1002", DisplayName: "identity-agent", IdentityType: "AGENT_IDENTITY", Effective: "principal://agents.global.org-123.system.id.goog/resources/aiplatform/projects/123456/locations/us-central1/reasoningEngines/1002"},
		{ID: "1003", DisplayName: "plain"},
	}
}

type rig struct {
	fake *vertexfake.Fake
	srv  *connsynctest.Server
	cfg  vertexagents.Config
	open func(vertexagents.Config) (*vertexagents.Client, error)
}

func newRig(t *testing.T, mut func(*vertexfake.Fake)) *rig {
	t.Helper()
	fk := vertexfake.New(sa, project, loc, engines()...)
	if mut != nil {
		mut(fk)
	}
	srv := connsynctest.New(t, fk)
	hc, err := safehttp.NewForTest(t, srv.Options(0))
	if err != nil {
		t.Fatal(err)
	}
	cfg := vertexagents.Config{Key: connsync.NewSecret(vertexfake.Key(sa)), ProjectID: project, Location: loc, Owner: "olu@acme.example",
		APIURL: srv.URL, TokenURL: srv.URL + "/token"}
	return &rig{fake: fk, srv: srv, cfg: cfg, open: func(c vertexagents.Config) (*vertexagents.Client, error) {
		return vertexagents.Open(c, connsynctest.Runtime, hc, func() time.Time { return t0 })
	}}
}

func (r *rig) discover(t *testing.T) (*connectors.DiscoveryResult, error) {
	t.Helper()
	c, err := r.open(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return vertexagents.NewConnector(c).Discover(context.Background())
}

func TestDiscoverMapsAgentsAndGrants(t *testing.T) {
	for _, page := range []int{0, 1} {
		t.Run(fmt.Sprintf("page %d", page), func(t *testing.T) {
			r := newRig(t, func(f *vertexfake.Fake) { f.PageSize = page })
			res, err := r.discover(t)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Identities) != 3 || len(res.Agents) != 3 || len(res.Accounts) != 3 {
				t.Fatalf("identities %d agents %d accounts %d", len(res.Identities), len(res.Agents), len(res.Accounts))
			}
			id := res.Identities[0]
			if id.ExternalID != "vertex:1001" || id.Type != "ai_agent" || id.Name != "support-agent" || id.Owner == nil || id.Owner.Email != "olu@acme.example" || id.Status != "active" {
				t.Errorf("identity = %+v", id)
			}
			if a := res.Agents[0]; a.Kind != "vertex_agent_engine" || a.CreatorRef != "olu" || a.Creator != nil || a.Sponsor == nil {
				t.Errorf("agent record = %+v", a)
			}
			perms := map[string]connectors.PermissionRecord{}
			for _, p := range res.Permissions {
				perms[p.ExternalID] = p
			}
			for _, want := range []string{
				"gcp-sa:" + runAs + "#run_as",
				"gcp-secret:projects/acme-agents-prod/secrets/crm-api-key#secretmanager.versions.access",
				"gcp-secret:projects/acme-agents-prod/secrets/db-password#secretmanager.versions.access",
				"gcp-agent-identity:principal://agents.global.org-123.system.id.goog/resources/aiplatform/projects/123456/locations/us-central1/reasoningEngines/1002#run_as",
			} {
				if _, ok := perms[want]; !ok {
					t.Errorf("missing grant %s", want)
				}
			}
			for _, rs := range res.Resources {
				if strings.Contains(rs.ExternalID, runAs) && !slices.Contains(rs.Tags, "pii") {
					t.Errorf("%s lacks the pii tag", rs.ExternalID)
				}
			}
			if !slices.Equal(res.AgentSnapshotOf, []string{"gcp-vertex"}) {
				t.Errorf("snapshot of = %v", res.AgentSnapshotOf)
			}
			got := fmt.Sprintf("%+v", res)
			for _, bad := range []string{"free text the connector must not keep", "very-secret-env-value", "API_BASE"} {
				if strings.Contains(got, bad) {
					t.Errorf("the result keeps %q", bad)
				}
			}
			if r.fake.Writes() != 0 {
				t.Errorf("%d writes", r.fake.Writes())
			}
			for _, q := range r.srv.Requests() {
				if q.Method != "GET" && q.Path != "/token" {
					t.Errorf("sent %s %s", q.Method, q.Path)
				}
			}
			if r.fake.Tokens() != 1 {
				t.Errorf("%d token exchanges, want one (cached)", r.fake.Tokens())
			}
		})
	}
}

func TestOwnerFromLabelWhenNoSetting(t *testing.T) {
	r := newRig(t, nil)
	r.cfg.Owner = ""
	res, err := r.discover(t)
	if err != nil {
		t.Fatal(err)
	}
	if res.Identities[0].Owner != nil || res.Agents[0].SponsorRef != "pat_acme" {
		t.Errorf("owner = %+v, record = %+v", res.Identities[0].Owner, res.Agents[0])
	}
}

func TestFaults(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*vertexfake.Fake)
		is   error
		text string
	}{
		{name: "api denied", mut: func(f *vertexfake.Fake) { f.Deny = true }, text: "403"},
		{name: "token refused", mut: func(f *vertexfake.Fake) { f.RefuseToken = true }, is: vertexagents.ErrCredential},
		{name: "not json", mut: func(f *vertexfake.Fake) { f.NotJSON = true }, is: connsync.ErrMalformed},
		{name: "pages never end", mut: func(f *vertexfake.Fake) { f.Endless, f.PageSize = true, 1 }, text: "more pages"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := newRig(t, tc.mut).discover(t)
			if err == nil || res != nil {
				t.Fatalf("res %v, err %v", res, err)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Errorf("err = %v, want %v", err, tc.is)
			}
			if tc.text != "" && !strings.Contains(err.Error(), tc.text) {
				t.Errorf("err = %v, want text %q", err, tc.text)
			}
			if strings.Contains(err.Error(), "BEGIN PRIVATE KEY") || strings.Contains(err.Error(), vertexfake.Token) {
				t.Errorf("error leaks a secret: %v", err)
			}
		})
	}
}

func TestProbe(t *testing.T) {
	r := newRig(t, nil)
	c, err := r.open(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.Probe(context.Background())
	if err != nil || p.Agents != 3 || c.Identity() != sa || c.Mode() != "json_key" {
		t.Errorf("probe = %+v, %v, %s, %s", p, err, c.Identity(), c.Mode())
	}
}

func TestOpenValidates(t *testing.T) {
	r := newRig(t, nil)
	for name, mut := range map[string]func(*vertexagents.Config){
		"bad project":  func(c *vertexagents.Config) { c.ProjectID = "A/B" },
		"bad location": func(c *vertexagents.Config) { c.Location = "../x" },
		"bad owner":    func(c *vertexagents.Config) { c.Owner = "not an email" },
		"no key":       func(c *vertexagents.Config) { c.Key = connsync.NewSecret("") },
		"not a key":    func(c *vertexagents.Config) { c.Key = connsync.NewSecret(`{"type":"authorized_user"}`) },
	} {
		c := r.cfg
		mut(&c)
		if _, err := r.open(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := vertexagents.Open(r.cfg, connsync.Runtime{Env: config.Prod}, nil, nil); err == nil {
		t.Error("a nil client was accepted")
	}
}

// The endpoint is the location's public one outside dev: an override is a dev setting, and a different host is
// refused even when it is not an override.
func TestEndpointOverrideIsRefusedOutsideDev(t *testing.T) {
	r := newRig(t, nil)
	hc, _ := safehttp.NewForTest(t, r.srv.Options(0))
	for _, env := range []string{config.Prod, config.Test} {
		if _, err := vertexagents.Open(r.cfg, connsync.Runtime{Env: env}, hc, nil); err == nil || !strings.Contains(err.Error(), "refused outside dev") {
			t.Errorf("%s: %v", env, err)
		}
	}
	c := r.cfg
	c.APIURL, c.TokenURL = "", ""
	if _, err := vertexagents.Open(c, connsync.Runtime{Env: config.Prod}, hc, nil); err != nil {
		t.Errorf("prod with the public endpoints: %v", err)
	}
}

func TestSecretNeverPrinted(t *testing.T) {
	r := newRig(t, nil)
	c, err := r.open(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
		for _, x := range []any{c, vertexagents.NewConnector(c), r.cfg} {
			if got := fmt.Sprintf(f, x); strings.Contains(got, "PRIVATE KEY") || strings.Contains(got, "private_key") {
				t.Errorf("%s prints the key: %.80s", f, got)
			}
		}
	}
}

func TestFromEnv(t *testing.T) {
	r := newRig(t, nil)
	env := map[string]string{"TESSERA_VERTEX_KEY": "env:K", "K": vertexfake.Key(sa), "TESSERA_VERTEX_PROJECT": project, "TESSERA_VERTEX_LOCATION": loc,
		"TESSERA_VERTEX_API_URL": r.srv.URL, "TESSERA_VERTEX_TOKEN_URL": r.srv.URL + "/token"}
	hc, _ := safehttp.NewForTest(t, r.srv.Options(0))
	cn, err := vertexagents.FromEnv(func(k string) string { return env[k] }, connsynctest.Runtime, hc, func() time.Time { return t0 })
	if err != nil || cn.System() != "gcp-vertex" {
		t.Fatalf("%v %v", cn, err)
	}
	if res, err := cn.Discover(context.Background()); err != nil || len(res.Agents) != 3 {
		t.Errorf("discover = %v, %v", res, err)
	}
	delete(env, "TESSERA_VERTEX_KEY")
	if _, err := vertexagents.FromEnv(func(k string) string { return env[k] }, connsynctest.Runtime, hc, nil); err == nil {
		t.Error("no key accepted")
	}
}
